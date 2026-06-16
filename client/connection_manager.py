"""Connection manager.

Owns the transport layer: socket lifecycle, the receive-thread loop, rate
limiting, size caps, keepalive responses, and server-info frames. Routing of
parsed frames to feature managers lives on ``SecureChatClient.route``.
"""

from __future__ import annotations

import base64
import contextlib
import enum
import json
import os
import socket
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from config import ClientConfigHandler
from protocol.constants import PROTOCOL_VERSION, MessageType
from protocol.errors import (
    ChatError,
    ConnectionClosedError,
    ErrorCode,
    MessageError,
    RatchetError,
    TransportError,
)
from utils import network_utils

if TYPE_CHECKING:
    from new_client import SecureChatClient
    from SecureChatABCs.protocol_base import ProtocolBase
    from SecureChatABCs.ui_base import UIBase

config = ClientConfigHandler()


class _QueueKind(enum.Enum):
    """Discriminant for items stored in the outgoing send queue."""
    ENCRYPT_TEXT = "encrypt_text"
    ENCRYPT_JSON = "encrypt_json"
    ENCRYPT_JSON_THEN_SWITCH = "encrypt_json_then_switch"


class ConnectionManager:
    """Handles transport: receive loop, rate limiting, keepalive, and server-info frames."""
    
    def __init__(self, client: SecureChatClient, protocol: ProtocolBase) -> None:
        self._client = client
        self._socket: socket.socket | None = None
        self._receive_thread: threading.Thread | None = None
        self._connected: bool = False
        self._rl_window_start: float | int = 0.0
        self._rl_count: int = 0
        self.server_protocol_version: str = "0.0.0"
        self.server_identifier: str = ""
        self.protocol: ProtocolBase = protocol

        # Outgoing send queue + sender thread (250 ms tick, dummy-traffic padding)
        self._message_queue: deque[tuple[_QueueKind, str | dict[str, Any]]] = deque()
        self._sender_thread: threading.Thread | None = None
        self._sender_running: bool = False
        self._sender_lock: threading.Lock = threading.Lock()
        self._send_dummy_messages: bool = config["send_dummy_packets"]

    @property
    def _ui(self) -> UIBase:
        return self._client.ui
    
    @property
    def connected(self) -> bool:
        """True while the TCP connection to the server is open."""
        return self._connected
    
    # transport lifecycle
    
    def connect(self, host: str, port: int) -> bool:
        """Open a TCP connection and start the background receive thread.

        Returns True on success, False if the connection could not be established.
        """
        try:
            self._close_socket()
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(30)
            self._socket.connect((host, port))
        except TimeoutError as e:
            self._client.raise_to_ui(TransportError(context={"reason": "timeout"}, cause=e))
            self._close_socket()
            return False
        except ConnectionRefusedError as e:
            self._client.raise_to_ui(TransportError(context={"reason": "refused", "host": host, "port": port}, cause=e))
            self._close_socket()
            return False
        except Exception as e:
            self._client.raise_to_ui(TransportError(context={"reason": str(e)}, cause=e))
            self._close_socket()
            return False
        
        self._connected = True
        self._receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
        self._receive_thread.start()
        return True
    
    def disconnect(self) -> None:
        """Notify the server, stop sending, close the socket, and join the receive thread."""
        if self._connected:
            self.send_encoded({"type": MessageType.CLIENT_DISCONNECT})
        self.reset_send_state()
        self._connected = False
        self._close_socket()
        if self._receive_thread is not None and self._receive_thread.is_alive():
            with contextlib.suppress(Exception):
                self._receive_thread.join(timeout=1.0)
                
        self._receive_thread = None
    
    def _close_socket(self) -> None:
        """Close the socket if open, ignoring errors, and drop the reference."""
        if self._socket is not None:
            with contextlib.suppress(Exception):
                self._socket.close()
            self._socket = None
    
    def send_raw(self, data: bytes) -> str | None:
        """Send a raw frame over the socket. Returns None on success, an error string otherwise."""
        if self._socket is None:
            return "No active connection"
        return network_utils.send_message(self._socket, data)
    
    def send_encoded(self, obj: Any) -> str | None:
        """JSON-encode and send a frame over the socket. Returns None on success, an error string otherwise."""
        if self._socket is None:
            return "No active connection"
        return network_utils.send_dict_as_json(self._socket, obj)

    # send queue + sender thread

    @property
    def send_dummy_messages(self) -> bool:
        """Whether dummy traffic-shaping packets should currently be sent."""
        return (self._send_dummy_messages
                and not self.protocol.rekey_in_progress
                and not self.protocol.has_active_file_transfers)

    @send_dummy_messages.setter
    def send_dummy_messages(self, value: bool) -> None:
        self._send_dummy_messages = value

    def start_sender_thread(self) -> None:
        """Start the background sender thread that drains the send queue every 250 ms."""
        if self._sender_thread is not None and self._sender_thread.is_alive():
            return  # Thread already running

        self._sender_running = True
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()

    def stop_sender_thread(self) -> None:
        """Stop the background sender thread."""
        self._sender_running = False
        if self._sender_thread is not None and self._sender_thread.is_alive():
            self._sender_thread.join(timeout=1.0)
        self._sender_thread = None

    def reset_send_state(self) -> None:
        """Stop the sender thread and drop any queued outgoing messages.

        Callers MUST invoke this before clearing the protocol's chain keys so the
        sender thread cannot encrypt against half-reset crypto state.
        """
        self.stop_sender_thread()
        with self._sender_lock:
            self._message_queue.clear()

    def queue_json(self, obj: dict[str, Any]) -> None:
        """Encrypt a JSON-serialisable dict and add it to the send queue."""
        with self._sender_lock:
            self._message_queue.append((_QueueKind.ENCRYPT_JSON, obj))

    def queue_text(self, text: str) -> None:
        """Encrypt a plain-text chat message and add it to the send queue."""
        with self._sender_lock:
            self._message_queue.append((_QueueKind.ENCRYPT_TEXT, text))

    def queue_json_then_switch(self, obj: dict[str, Any]) -> None:
        """Encrypt a JSON dict, send it under the current keys, then activate pending keys."""
        with self._sender_lock:
            self._message_queue.append((_QueueKind.ENCRYPT_JSON_THEN_SWITCH, obj))

    def _sender_loop(self) -> None:
        """Background loop: dequeue one item per 250 ms tick, encrypt, and send it.

        When the queue is empty and dummy-message sending is enabled, a random
        dummy packet is sent instead to obscure traffic patterns.
        """
        while self._sender_running:
            item = self._get_next_item()
            to_send, switch_keys_after = self._prepare_item_for_sending(item)

            if to_send is not None:
                self._send_prepared_item(to_send, switch_keys_after)

            time.sleep(0.25)

    def _get_next_item(self) -> tuple[_QueueKind, Any] | bytes | None:
        """Get the next item from the queue or generate a dummy message."""
        with self._sender_lock:
            if self._message_queue:
                return self._message_queue.popleft()

        if self.send_dummy_messages and self.protocol.encryption_ready and config["send_dummy_packets"]:
            return self._generate_dummy_message()

        return None

    def _generate_dummy_message(self) -> bytes:
        """Generate an encrypted dummy message with random data."""
        dummy_data = os.urandom(config["max_dummy_packet_size"])
        dummy_message = {
            "type": MessageType.DUMMY_MESSAGE,
            "data": base64.b64encode(dummy_data).decode("utf-8"),
        }
        return self.protocol.encrypt_message(json.dumps(dummy_message))

    def _prepare_item_for_sending(
            self, item: tuple[_QueueKind, Any] | bytes | bytearray | None,
    ) -> tuple[bytes | None, bool]:
        """Convert a queue item into bytes ready for transmission.

        Returns (data_to_send, switch_keys_after) where switch_keys_after signals
        that pending keys should be activated after the message is sent.
        """
        if item is None:
            return None, False

        try:
            # Raw bytes from _generate_dummy_message
            if isinstance(item, (bytes, bytearray)):
                return bytes(item), False

            kind, payload = item

            if kind is _QueueKind.ENCRYPT_TEXT:
                return self._encrypt_text_message(payload), False

            if kind is _QueueKind.ENCRYPT_JSON:
                return self._encrypt_json_message(payload), False

            if kind is _QueueKind.ENCRYPT_JSON_THEN_SWITCH:
                return self._encrypt_json_message(payload), True

            raise MessageError(code=ErrorCode.MESSAGE_TYPE, context={"queue_kind": str(kind)})

        except ChatError as e:
            self._client.raise_to_ui(e)
            return None, False
        except (ValueError, TypeError) as e:
            self._client.raise_to_ui(ChatError(f"Message preparation error (dropped): {e}", cause=e))
            return None, False
        except Exception as e:
            self._client.raise_to_ui(ChatError(f"Unexpected error preparing message (dropped): {e}", cause=e))
            return None, False

    def _encrypt_text_message(self, text: str) -> bytes:
        """Wrap a chat message in a TEXT_MESSAGE frame and encrypt it."""
        if not isinstance(text, str) or not self.protocol.encryption_ready:
            raise RatchetError(code=ErrorCode.CHAIN_KEY_MISSING, context={"kind": "encrypt_text"})

        inner_obj = {"type": MessageType.TEXT_MESSAGE, "text": text}
        return self.protocol.encrypt_message(json.dumps(inner_obj))

    def _encrypt_json_message(self, obj: dict[str, Any]) -> bytes:
        """Encrypt an already-typed JSON frame."""
        if not isinstance(obj, dict) or not self.protocol.encryption_ready:
            raise RatchetError(code=ErrorCode.CHAIN_KEY_MISSING, context={"kind": "encrypt_json"})

        return self.protocol.encrypt_message(json.dumps(obj))

    def _send_prepared_item(self, to_send: bytes, switch_keys_after: bool) -> None:
        """Send prepared bytes and activate pending keys afterwards if requested."""
        result = self.send_raw(to_send)
        if result is not None:
            self._client.raise_to_ui(ChatError(f"Failed to send message: {result}", context={"reason": str(result)}))

        if switch_keys_after:
            self.protocol.activate_pending_keys()

    # receive loop
    
    def receive_loop(self) -> None:
        """Background thread loop: read raw frames from socket, dispatch to handle_message."""
        if self._socket is None:
            return
        while self._connected:
            try:
                message_data = network_utils.receive_message(self._socket, max_size=config["max_message_size"])
                self.handle_message(message_data)
            except ConnectionClosedError:
                self._ui.display_system_message("Connection to server lost.")
                break
            except Exception as e:
                if not self._connected:
                    break
                self._client.raise_to_ui(TransportError(code=ErrorCode.SOCKET_RECV, context={"error": str(e)}, cause=e))
                break
    
    # transport gate
    
    def _try_log_decrypted(self, message_data: bytes, context: str) -> None:
        """Attempt to decrypt dropped message and log raw bytes + decrypted text if successful."""
        proto = getattr(self._client, "_protocol", None)
        if proto is None or not self._client.key_exchange_complete:
            self._ui.log_raw_bytes("RECV", context, message_data)
            return
        try:
            decrypted = proto.decrypt_message(message_data)
            self._ui.log_raw_bytes("RECV", context + ":decrypted", message_data, decrypted_text=decrypted)
        except (ValueError, Exception):
            self._ui.log_raw_bytes("RECV", context, message_data)
    
    def _rate_limited(self, message_data: bytes) -> bool:
        """Return True if the per-peer rate limit is exceeded; the frame is dropped and logged."""
        if self._client.bypass_rate_limits:
            return False
        now = time.time()
        if now - self._rl_window_start >= 1.0:
            self._rl_window_start = now
            self._rl_count = 0
        if self._rl_count >= 6:
            self._client.raise_to_ui(TransportError(code=ErrorCode.RATE_LIMITED, context={"window": "1s"}))
            self._try_log_decrypted(message_data, "dropped:rate_limit")
            return True
        self._rl_count += 1
        return False
    
    def _oversized(self, message_data: bytes) -> bool:
        """Return True if a pre-verification frame exceeds the size cap; the frame is dropped and logged."""
        if self._client.bypass_rate_limits or len(message_data) <= 33260:
            return False
        self._client.raise_to_ui(TransportError(code=ErrorCode.FRAME_TOO_LARGE, 
            context={"size": len(message_data), "max_preverify": 33260}
        ))
        self._try_log_decrypted(message_data, "dropped:oversized")
        return True
    
    def handle_message(self, message_data: bytes) -> None:
        """Transport gate for inbound frames: rate limit, size cap, then hand off to routing.

        Drops rate-limited or oversized pre-verification frames; everything that
        passes is handed to ``SecureChatClient.route`` for type dispatch.
        """
        if self._rate_limited(message_data):
            return
        if self._oversized(message_data):
            return
        self._client.route(message_data)
    
    # keepalive
    
    def handle_keepalive(self) -> None:
        """Respond to a server keepalive ping to prevent the connection from being dropped."""
        response_message = {"type": MessageType.KEEP_ALIVE_RESPONSE}
        result = self.send_encoded(response_message)
        if result is not None:
            self._client.raise_to_ui(TransportError(
                code=ErrorCode.SOCKET_SEND,
                context={"reason": str(result), "kind": "keepalive"}
            ))
            self._ui.display_system_message("Server may disconnect after 3 keepalive failures.")
    
    # server info
    
    def handle_server_full(self) -> None:
        self._client.raise_to_ui(TransportError(context={"reason": "server_full"}))
        self._client.disconnect()
    
    def handle_server_version_info(self, message_data: bytes) -> None:
        """Parse server's version/identifier frame, store values, warn if protocol major version differs."""
        message = json.loads(message_data)
        self.server_protocol_version = message.get("protocol_version", "0.0.0")
        if self.server_protocol_version == "0.0.0":
            self._client.raise_to_ui(TransportError(
                context={"reason": "invalid_server_version"},
            ))
        
        self._ui.display_system_message(f"Server Protocol Version: v{self._client.server_protocol_version}")
        identifier = message.get("identifier", "")
        if isinstance(identifier, str) and identifier.strip():
            self._client.set_server_identifier(identifier.strip())
            self._ui.display_system_message(f"Server Identifier: {self.server_identifier}")
        
        if self.server_protocol_version != PROTOCOL_VERSION:
            self._ui.display_system_message(
                    f"Protocol version mismatch: Client v{PROTOCOL_VERSION}, "
                    f"Server v{self.server_protocol_version}",
            )
            major_server = self.server_protocol_version.split(".")[0]
            major_client = PROTOCOL_VERSION.split(".")[0]
            if major_server != major_client:
                self._client.raise_to_ui(TransportError(
                    context={"reason": "version_major_mismatch",
                             "client": PROTOCOL_VERSION, "server": self.server_protocol_version},
                ))
    
    def on_server_disconnect(self, reason: str) -> None:
        self._ui.display_system_message(f"Server disconnected: {reason}")
        self._client.disconnect()
