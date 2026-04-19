"""
Secure Chat Client with End-to-End Encryption — core / background logic.

This module contains the client class that handles all networking, crypto,
protocol, and background operations.  It delegates every user-facing
interaction to a pluggable UI object that implements ``UIBase``.
"""
import binascii
import json
import socket
import string
import threading
from pathlib import Path
from typing import Any

from SecureChatABCs.client_base import ClientBase
from SecureChatABCs.protocol_base import ProtocolBase
from SecureChatABCs.ui_base import UIBase
from client.connection_manager import ConnectionManager
from client.deaddrop_manager import DeaddropManager
from client.file_transfer_manager import FileTransferManager
from client.key_exchange_manager import KeyExchangeManager
from client.voice_call_manager import VoiceCallManager
from config import ClientConfigHandler
from protocol.constants import MessageType
from protocol.file_handler import ProtocolFileHandler
from protocol.shared import SecureChatProtocol
from protocol.types import FileMetadata, FileTransfer
from utils import network_utils
from utils.checks import allowed_unverified_inner_fields, first_unexpected_field
from utils.network_utils import send_message
from utils.threading_utils import ThreadSafeDict

config = ClientConfigHandler()


class SecureChatClient(ClientBase):
    """Core secure-chat client: networking, cryptography, and protocol logic.

    Manages the full lifecycle of a peer-to-peer encrypted session:

    * TCP connection to the relay server (``connect`` / ``disconnect``).
    * Post-quantum key exchange (ML-KEM-1024 + X25519) via :class:`SecureChatProtocol`.
    * Interactive key-fingerprint verification to detect man-in-the-middle attacks.
    * Encrypted messaging, file transfer (chunked, optionally compressed), and
      voice-call signalling.
    * Periodic and on-demand rekeying to provide forward secrecy.
    * Anonymous file drop via the server's deaddrop facility.
    * Rate limiting and keepalive handling.

    All user-facing output and prompts are delegated to ``self.ui``, which must
    implement :class:`UIBase`.  This keeps the client fully UI-agnostic and
    testable without a real interface.
    """
    
    def __init__(self, ui: UIBase) -> None:
        """Initialise the client with a UI implementation.

        Sets up all session state to its default (disconnected, no keys) values.
        No network activity takes place here; call :meth:`connect` to establish
        a connection.

        Args:
            ui: An object implementing :class:`UIBase` that will receive all
                display callbacks and user-prompt requests.
        """
        # UI layer
        self.ui: UIBase = ui
        
        # Connection configuration
        self.host: str = "0.0.0.0"
        self.port: int = 16384
        self._socket: socket.socket = socket.socket()
        
        self.file_handler: ProtocolFileHandler = ProtocolFileHandler()
        self._protocol: ProtocolBase = SecureChatProtocol(self, self.file_handler)
        
        # Threads
        self._receive_thread: threading.Thread | None = None
        
        # Session state flags
        self._connected: bool = False
        self._key_exchange_complete: bool = False
        self._verification_complete: bool = False
        self._verification_started: bool = False
        
        # Peer identity and permissions
        self.peer_nickname: str = "Other user"
        self.nickname_change_allowed: bool = config["peer_nickname_change"]
        self._own_nickname: str = "You"
        self._peer_verified_own_key: bool = False
        self._peer_key_verified: bool = False
        
        # Feature toggles/preferences
        self.allow_file_transfers: bool = True
        self.send_delivery_receipts: bool = True
        
        # Voice call state — delegated to VoiceCallManager
        self._voice_call: VoiceCallManager = VoiceCallManager(self)

        # Key exchange state — delegated to KeyExchangeManager
        self._key_exchange: KeyExchangeManager = KeyExchangeManager(self)
        
        # File transfer state — delegated to FileTransferManager
        self._file_transfer: FileTransferManager = FileTransferManager(self)
        self.file_transfer_update_interval: int = 10
        
        # Server version information
        self.server_protocol_version: str = "0.0.0"
        self.server_identifier: str = ""
        
        # Deaddrop session — delegated to DeaddropManager
        self._deaddrop: DeaddropManager = DeaddropManager(self)

        # Networking + dispatch — delegated to ConnectionManager
        self._connection: ConnectionManager = ConnectionManager(self)
    
    @property
    def connected(self) -> bool:
        return self._connected
    
    @property
    def key_exchange_complete(self) -> bool:
        return self._key_exchange_complete
    
    @property
    def verification_complete(self) -> bool:
        return self._verification_complete
    
    @property
    def verification_started(self) -> bool:
        return self._verification_started
    
    @property
    def voice_call_active(self) -> bool:
        return self._voice_call.active

    @property
    def voice_muted(self) -> bool:
        return self._voice_call.muted

    @voice_muted.setter
    def voice_muted(self, value: bool) -> None:
        self._voice_call.muted = value
    
    @property
    def file_transfer_active(self) -> bool:
        """True if any file transfer (regular or deaddrop download) is currently in progress."""
        return bool(self._file_transfer.active or self._deaddrop.download_in_progress)

    @property
    def deaddrop_supported(self) -> bool:
        return self._deaddrop.supported

    @property
    def pending_file_transfers(self) -> ThreadSafeDict[str, FileTransfer]:
        return self._file_transfer.pending_file_transfers

    @property
    def active_file_metadata(self) -> ThreadSafeDict[str, FileMetadata]:
        return self._file_transfer.active_file_metadata

    @property
    def pending_file_requests(self) -> ThreadSafeDict[str, FileMetadata]:
        return self._file_transfer.active_file_metadata
    
    @property
    def bypass_rate_limits(self) -> bool:
        """True when rate limiting should be suspended — during file transfers, voice calls, rekeying, or while key verification is still pending after key exchange."""
        return bool(self.file_transfer_active or self._voice_call.active or self._protocol.rekey_in_progress
                    or (self._key_exchange_complete and not self._verification_complete))
    
    @property
    def own_nickname(self) -> str:
        return self._own_nickname
    
    @own_nickname.setter
    def own_nickname(self, value: str) -> None:
        """Set the local user's nickname and notify the peer via an encrypted NICKNAME_CHANGE message."""
        self._protocol.queue_json({
            "type":     MessageType.NICKNAME_CHANGE,
            "nickname": value,
        })
        self._own_nickname = value
    
    @property
    def peer_verified_key(self) -> bool:
        return self._peer_verified_own_key
    
    @property
    def peer_key_verified(self) -> bool:
        return self._peer_key_verified
    
    @property
    def own_key_fingerprint(self) -> str:
        return self._protocol.get_own_key_fingerprint()
    
    def connect(self, host: str, port: int) -> bool:
        """Open a TCP connection to the server and start the background receive thread.
        
        Returns True on success, False if the connection could not be established.
        """
        try:
            self._socket.close()
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(30)
            self._socket.connect((host, port))
            self._connected = True
            self.host, self.port = host, port
            
            self.ui.display_system_message(f"Connected to secure chat server at {self.host}:{self.port}")
            self.ui.display_system_message("Waiting for another user to connect...")
            
            self._receive_thread = threading.Thread(target=self._connection.receive_loop, daemon=True)
            self._receive_thread.start()
            
            self.ui.on_connected()
            return True
        
        except socket.timeout:
            self.ui.display_error_message("Connection timed out. Please try again.")
            self._socket.close()
            return False
        
        except ConnectionRefusedError:
            self.ui.display_error_message("Connection refused. Please check the server address and port.")
            self._socket.close()
            return False
        
        except Exception as e:
            self.ui.display_error_message(f"Failed to connect to server: {e}")
            self._socket.close()
            return False
    
    def disconnect(self) -> None:
        self.end_call(notify_peer=self.key_exchange_complete and self.connected)
        self._protocol.stop_sender_thread()
        
        if self.connected:
            network_utils.encode_send_message(self._socket, {"type": MessageType.CLIENT_DISCONNECT})
        
        self._connected = False
        try:
            self._socket.close()
        except Exception:
            pass
        
        self._deaddrop.reset()
        
        if self._receive_thread and self._receive_thread.is_alive():
            try:
                self._receive_thread.join(timeout=1.0)
            except Exception:
                pass
        
        self.ui.on_graceful_disconnect("Disconnected from server.")
    
    def end_call(self, notify_peer: bool = True) -> None:
        self._voice_call.end(notify_peer=notify_peer)
    
    # messaging
    
    @property
    def next_message_counter(self) -> int:
        return self._protocol.message_counter + 1
    
    def send_message(self, text: str) -> bool:
        """Encrypt and queue a text message for delivery to the peer.

        Returns False (and shows an error) if the key exchange or encryption is not yet ready.
        Also triggers an auto-rekey check after queuing.
        """
        if not self.key_exchange_complete:
            self.ui.display_error_message("Cannot send messages - key exchange not complete")
            return False
        
        if not self._protocol.encryption_ready:
            self.ui.display_error_message("Cannot send message, encryption isn't ready")
            return False
        
        if not self.peer_key_verified:
            self.ui.display_system_message("Sending message to unverified peer")
        
        self._protocol.queue_text(text)
        self.check_and_initiate_auto_rekey()
        return True
    
    # file transfer — thin proxies to FileTransferManager

    def send_file(self, file_path: Path | str, compress: bool = True) -> None:
        self._file_transfer.send(file_path, compress=compress)

    def reject_file_transfer(self, transfer_id: str) -> None:
        self._file_transfer.reject(transfer_id)

    # key exchange & verification — thin proxies to KeyExchangeManager

    def initiate_key_exchange(self) -> None:
        self._key_exchange.initiate()

    def handle_ke_dsa_random(self, message_data: bytes) -> None:
        self._key_exchange.handle_dsa_random(message_data)

    def confirm_key_verification(self, verified: bool) -> None:
        self._key_exchange.confirm_verification(verified)

    def handle_key_verification_message(self, message_data: bytes) -> None:
        self._key_exchange.handle_verification_message(message_data)

    def handle_key_exchange_reset(self, message_data: bytes) -> None:
        self._key_exchange.handle_reset(message_data)

    def handle_rekey(self, inner: dict[str, Any]) -> None:
        self._key_exchange.handle_rekey(inner)

    def initiate_rekey(self) -> None:
        self._key_exchange.initiate_rekey()

    def check_and_initiate_auto_rekey(self) -> None:
        self._key_exchange.check_auto_rekey()
    
    # voice calls — thin proxies to VoiceCallManager

    def request_voice_call(self, rate: int, chunk_size: int, audio_format: int) -> None:
        self._voice_call.request(rate, chunk_size, audio_format)

    def on_user_response(self, accepted: bool, rate: int, chunk_size: int, audio_format: int) -> None:
        self._voice_call.on_user_response(accepted, rate, chunk_size, audio_format)

    def send_voice_data(self, audio_data: bytes) -> None:
        self._voice_call.send_audio(audio_data)
    
    def send_ephemeral_mode_change(self, mode: str) -> None:
        """Send an encrypted EPHEMERAL_MODE_CHANGE message to the peer."""
        if not self._protocol:
            return
        payload = {
            "type": MessageType.EPHEMERAL_MODE_CHANGE,
            "mode": mode,
        }
        self._protocol.queue_json(payload)
    
    # deaddrop — thin proxies to DeaddropManager

    def start_deaddrop(self) -> None:
        self._deaddrop.start_handshake()

    def deaddrop_session_active(self) -> bool:
        return self._deaddrop.session_active

    def wait_for_deaddrop_handshake(self, timeout: float = 3.0) -> bool:
        return self._deaddrop.wait_for_handshake(timeout)

    def deaddrop_upload(self, name: str, password: str, file_path: Path) -> None:
        self._deaddrop.upload(name, password, file_path)

    def deaddrop_check(self, name: str) -> None:
        self._deaddrop.check(name)

    def deaddrop_download(self, name: str, password: str) -> None:
        self._deaddrop.download(name, password)
    
    def _send_raw(self, data: bytes) -> Any:
        """Send a raw frame over the socket. Exists so tests can patch `new_client.send_message`."""
        return send_message(self._socket, data)

    def on_error(self, message: str) -> None:
        """Handle an error reported by the protocol layer."""
        self.ui.display_error_message(message)
    
    def emergency_close(self) -> None:
        """Immediately disconnect and wipe all session state, including keys and file transfers."""
        self.ui.display_system_message("EMERGENCY CLOSE ACTIVATED")
        self.disconnect()
        self._key_exchange_complete = False
        self._verification_complete = False
        self._protocol.reset_key_exchange()
        self.file_handler.clear()
        self._file_transfer.clear()

    # connection dispatch — thin proxies to ConnectionManager

    def handle_message(self, message_data: bytes) -> None:
        self._connection.handle_message(message_data)

    def handle_maybe_binary_chunk(self, message_data: bytes) -> bool:
        return self._connection.handle_maybe_binary_chunk(message_data)

    def handle_keepalive(self) -> None:
        self._connection.handle_keepalive()
    
    def handle_delivery_confirmation(self, message: dict[str, Any]) -> None:
        """Forward a delivery confirmation (read receipt) from the peer to the UI."""
        confirmed = message.get("confirmed_counter")
        if confirmed is not None:
            self.ui.on_delivery_confirmation(int(confirmed))  # type: ignore
    
    def handle_encrypted_message(self, message_data: bytes) -> None:
        """Decrypt an ENCRYPTED_MESSAGE frame and dispatch its inner payload to handle_message_types.

        Applies additional field-allowlist checks when the peer's key has not yet been verified.
        """
        try:
            decrypted_text = self._protocol.decrypt_message(message_data)
        except ValueError as e:
            self.ui.display_error_message(str(e))
            self.ui.log_raw_bytes("RECV", "dropped:decrypt_fail", message_data)
            return
        
        received_message_counter = self._protocol.peer_counter
        
        try:
            message_json: dict[str, Any] = json.loads(decrypted_text)
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
            self.ui.display_error_message("Received message that could not be decoded.")
            return
        
        if not self.peer_key_verified:
            allowed_inner = allowed_unverified_inner_fields()
            unexpected_inner = first_unexpected_field(message_json, allowed_inner)
            if unexpected_inner:
                self.ui.display_error_message(
                        f"Dropped decrypted message from unverified peer due to unexpected field '{unexpected_inner}'.",
                )
                return
        
        message_type = MessageType(message_json.get("type", -1))
        if message_type == MessageType.NONE:
            self.ui.display_error_message("Received message with invalid type.")
            return
        
        try:
            self.handle_message_types(message_type, message_json, received_message_counter)
        except Exception as e:
            self.ui.display_error_message(f"Error handling a message: {e}")
            return
        
        self.check_and_initiate_auto_rekey()
    
    def handle_message_types(self, message_type: MessageType, message_json: dict[str, Any],
                             received_message_counter: int,
                             ) -> bool:
        """Route a decrypted inner message to the correct handler based on its type.

        Returns True if the message type was recognised and handled, False otherwise.
        """
        match message_type:
            
            case MessageType.DUMMY_MESSAGE:
                pass
            
            case MessageType.TEXT_MESSAGE:
                text = str(message_json.get("text", ""))
                if not self.peer_key_verified:
                    text = "".join(ch for ch in text if ch in string.printable)
                self.ui.display_regular_message(text, self.peer_nickname)
                self._send_delivery_confirmation(received_message_counter)
            
            case MessageType.EMERGENCY_CLOSE:
                self.handle_emergency_close()
            
            case MessageType.FILE_METADATA:
                self._file_transfer.handle_metadata(message_json)

            case MessageType.FILE_ACCEPT:
                self._file_transfer.handle_accept(message_json)

            case MessageType.FILE_REJECT:
                self._file_transfer.handle_reject(message_json)

            case MessageType.FILE_COMPLETE:
                self._file_transfer.handle_complete(message_json)
            
            case MessageType.DELIVERY_CONFIRMATION:
                if self.key_exchange_complete:
                    self.handle_delivery_confirmation(message_json)
            
            case MessageType.EPHEMERAL_MODE_CHANGE:
                self.handle_ephemeral_mode_change(message_json)
            
            case MessageType.REKEY:
                self._key_exchange.handle_rekey(message_json)
            
            case MessageType.VOICE_CALL_INIT:
                self._voice_call.handle_init(message_json)

            case MessageType.VOICE_CALL_ACCEPT:
                self._voice_call.handle_accept(message_json)

            case MessageType.VOICE_CALL_REJECT:
                self._voice_call.handle_reject()

            case MessageType.VOICE_CALL_DATA:
                self._voice_call.handle_data(message_json)

            case MessageType.VOICE_CALL_END:
                self._voice_call.handle_end()
            
            case MessageType.NICKNAME_CHANGE:
                self.handle_nickname_change(message_json)
            
            case _:
                self.ui.display_error_message(f"Dropped message with unknown inside type: {message_type}")
                return False
        
        return True
    
    def _send_delivery_confirmation(self, confirmed_counter: int) -> None:
        """Queue a delivery confirmation for the message with the given counter value, if receipts are enabled."""
        if not self.send_delivery_receipts:
            return
        message = {
            "type":              MessageType.DELIVERY_CONFIRMATION,
            "confirmed_counter": confirmed_counter,
        }
        self._protocol.queue_json(message)
    
    def handle_emergency_close(self) -> None:
        """Handle an EMERGENCY_CLOSE message from the peer: notify the UI and immediately disconnect."""
        self._protocol.reset_key_exchange()
        self.ui.on_emergency_close()
        self.ui.display_system_message("EMERGENCY CLOSE RECEIVED")
        self.ui.display_system_message("The other client has activated emergency close.")
        self.ui.display_system_message("Connection will be terminated immediately.")
        
        self.disconnect()
        self._key_exchange_complete = False
        self._verification_complete = False
        self.file_handler.clear()
    
    def handle_ephemeral_mode_change(self, message: dict[str, Any]) -> None:
        """Apply an ephemeral-mode change from the server, but only if the owner ID matches the known server identifier."""
        mode = str(message.get("mode", "OFF")).upper()
        owner_id = message.get("owner_id")
        
        if owner_id == self.server_identifier:
            self.ui.on_ephemeral_mode_change(mode, owner_id)
        else:
            self.ui.display_error_message(f"Ignored ephemeral mode change: invalid owner '{owner_id}'")
    
    def handle_nickname_change(self, message: dict[str, Any]) -> None:
        """Apply a peer nickname change, subject to verification and configuration checks."""
        if not self.peer_key_verified:
            self.ui.display_system_message("Ignored nickname change from peer: connection is unverified")
            return
        if not self.nickname_change_allowed:
            self.ui.display_system_message("Peer attempted to change nickname")
            return
        self.peer_nickname = str(message.get("nickname", "Other User"))[:config["max_nickname_length"]]
        self.ui.on_nickname_change(self.peer_nickname)
        self.ui.display_system_message(f"Peer changed nickname to: {self.peer_nickname}")
    