"""Connection manager.

Owns the inbound dispatch loop: receive-thread loop, rate limiting,
keepalive responses, server-info frames, and top-level message routing.
"""
from __future__ import annotations

import json
import time
from socket import socket
from typing import TYPE_CHECKING, Any

from config import ClientConfigHandler
from protocol import constants
from protocol.constants import (
    FILE_CHUNK_CIPHERTEXT_OFFSET,
    MAGIC_SIZE,
    MessageType,
    PROTOCOL_VERSION,
)
from utils import network_utils
from utils.checks import allowed_outer_fields, first_unexpected_field

if TYPE_CHECKING:
    from new_client import SecureChatClient
    from SecureChatABCs.protocol_base import ProtocolBase
    from SecureChatABCs.ui_base import UIBase

config = ClientConfigHandler()


class ConnectionManager:
    """Handles receive loop, dispatch, rate limiting, keepalive, and server-info frames."""

    def __init__(self, client: "SecureChatClient") -> None:
        self._client = client
        self._rl_window_start: float = 0.0
        self._rl_count: int = 0

    @property
    def _ui(self) -> UIBase:
        return self._client.ui

    @property
    def _protocol(self) -> ProtocolBase:
        return self._client._protocol

    @property
    def _socket(self) -> socket:
        return self._client._socket

    # receive loop

    def receive_loop(self) -> None:
        """Background thread loop: read raw frames from socket, dispatch to handle_message."""
        while self._client.connected:
            try:
                message_data = network_utils.receive_message(self._socket, max_size=config["max_message_size"])
                self.handle_message(message_data)
            except ConnectionError:
                self._ui.display_system_message("Connection to server lost.")
                break
            except Exception as e:
                if not self._client.connected:
                    break
                self._ui.display_error_message(f"Error receiving message: {e}")
                break

    # dispatch

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

    def handle_message(self, message_data: bytes) -> None:
        """Top-level dispatcher for all incoming frames.

        Enforces rate limiting and size checks before attempting to parse the message type
        and routing to the appropriate handler. Binary frames (file chunks, deaddrop chunks)
        are handled via handle_maybe_binary_chunk on the facade.
        """
        client = self._client
        if not client.bypass_rate_limits:
            now = time.time()
            if now - self._rl_window_start >= 1.0:
                self._rl_window_start = now
                self._rl_count = 0
            if self._rl_count >= 6:
                self._ui.display_error_message("Rate-limited peer: dropped message")
                self._try_log_decrypted(message_data, "dropped:rate_limit")
                return
            self._rl_count += 1

        if len(message_data) > 33260 and not client.bypass_rate_limits:
            self._ui.display_error_message(
                    "Received overly large message without key verification. Dropping."
                    f" ({len(message_data)} bytes)",
            )
            self._try_log_decrypted(message_data, "dropped:oversized")
            return

        try:
            message_json: dict[str, Any] = json.loads(message_data)
            message_type = MessageType(int(message_json.get("type")))  # type: ignore
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            success = self.handle_maybe_binary_chunk(message_data)
            if not success:
                self._ui.display_error_message("Received message that could not be decoded.")
                self._ui.log_raw_bytes("RECV", "dropped:decode_error", message_data)
            return

        if message_type == MessageType.NONE:
            self._ui.display_error_message("Received message with invalid type.")
            return

        allowed = allowed_outer_fields(message_type)
        unexpected = first_unexpected_field(message_json, allowed)
        if unexpected:
            self._ui.display_error_message(
                    f"Dropped message from unverified peer due to unexpected field '{unexpected}'.")
            return

        match message_type:
            case MessageType.KE_DSA_RANDOM:
                client._key_exchange.handle_dsa_random(message_data)
            case MessageType.KE_MLKEM_PUBKEY:
                client._key_exchange.handle_mlkem_pubkey(message_data)
            case MessageType.KE_MLKEM_CT_KEYS:
                client._key_exchange.handle_mlkem_ct_keys(message_data)
            case MessageType.KE_X25519_HQC_CT:
                client._key_exchange.handle_x25519_hqc_ct(message_data)
            case MessageType.KE_VERIFICATION:
                client._key_exchange.handle_verification(message_data)
            case MessageType.ENCRYPTED_MESSAGE:
                if client.key_exchange_complete:
                    client.handle_encrypted_message(message_data)
                else:
                    self._ui.display_error_message("\nReceived encrypted message before key exchange complete")
            case MessageType.ERROR:
                self._ui.display_error_message(f"{message_json.get('error', 'Unknown error')}")
            case MessageType.KEY_VERIFICATION:
                client._key_exchange.handle_verification_message(message_data)
            case MessageType.KEY_EXCHANGE_RESET:
                client._key_exchange.handle_reset(message_data)
            case MessageType.KEEP_ALIVE:
                self.handle_keepalive()
            case MessageType.INITIATE_KEY_EXCHANGE:
                client._key_exchange.initiate()
            case MessageType.SERVER_FULL:
                self.handle_server_full()
            case MessageType.SERVER_VERSION_INFO:
                self.handle_server_version_info(message_data)
            case MessageType.SERVER_DISCONNECT:
                reason = message_json.get('reason', 'Server initiated disconnect')
                self.on_server_disconnect(reason)
            case MessageType.DEADDROP_START:
                client._deaddrop.handle_start_response(message_json)
            case MessageType.DEADDROP_MESSAGE:
                client._deaddrop.handle_encrypted_message(message_json)
            case _:
                self._ui.display_error_message(f"Unknown message type: {message_type}")

    def handle_maybe_binary_chunk(self, message_data: bytes) -> bool:
        """Try to interpret a non-JSON frame as encrypted binary chunk (file transfer or deaddrop)."""
        if not len(message_data) >= FILE_CHUNK_CIPHERTEXT_OFFSET:
            return False
        magic: bytes = message_data[:MAGIC_SIZE]
        if magic == constants.MAGIC_NUMBER_FILE_TRANSFER:
            try:
                result = self._protocol.decrypt_file_chunk(message_data)
                self._client._file_transfer.handle_chunk_binary(result)
                return True
            except ValueError:
                return False
        elif magic == constants.MAGIC_NUMBER_DEADDROPS:
            try:
                self._client._deaddrop.handle_binary_chunk(message_data)
                return True
            except ValueError:
                return False
        return False

    # keepalive

    def handle_keepalive(self) -> None:
        """Respond to a server keepalive ping to prevent the connection from being dropped."""
        response_message = {"type": MessageType.KEEP_ALIVE_RESPONSE}
        result = self._client._send_raw(json.dumps(response_message).encode("utf-8"))
        if result is not None:
            self._ui.display_error_message(f"Failed to send keepalive response: {result}")
            self._ui.display_system_message("Server may disconnect after 3 keepalive failures.")

    # server info

    def handle_server_full(self) -> None:
        self._ui.display_error_message("Server is full. Cannot connect at this time.")
        self._ui.display_error_message("Please try again later.")
        self._client.disconnect()

    def handle_server_version_info(self, message_data: bytes) -> None:
        """Parse server's version/identifier frame, store values, warn if protocol major version differs."""
        message = json.loads(message_data)
        self._client.server_protocol_version = message.get("protocol_version", "0.0.0")
        if self._client.server_protocol_version == "0.0.0":
            self._ui.display_error_message(
                    "Server returned invalid protocol version information, communication may "
                    "still work but may be unreliable or have missing features.",
            )

        self._ui.display_system_message(f"Server Protocol Version: v{self._client.server_protocol_version}")
        identifier = message.get("identifier", "")
        if isinstance(identifier, str) and identifier.strip():
            self._client.server_identifier = identifier.strip()
            self._protocol.set_server_identifier(self._client.server_identifier)
            self._ui.display_system_message(f"Server Identifier: {self._client.server_identifier}")

        if self._client.server_protocol_version != PROTOCOL_VERSION:
            self._ui.display_system_message(
                    f"Protocol version mismatch: Client v{PROTOCOL_VERSION}, "
                    f"Server v{self._client.server_protocol_version}",
            )
            major_server = self._client.server_protocol_version.split('.')[0]
            major_client = PROTOCOL_VERSION.split('.')[0]
            if major_server != major_client:
                self._ui.display_error_message("Versions may not be compatible - communication issues possible")

    def on_server_disconnect(self, reason: str) -> None:
        self._ui.display_system_message(f"Server disconnected: {reason}")
        self._client.disconnect()
