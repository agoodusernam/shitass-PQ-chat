"""
Secure Chat Client with End-to-End Encryption — core / background logic.

This module contains the client class that handles all networking, crypto,
protocol, and background operations.  It delegates every user-facing
interaction to a pluggable UI object that implements ``UIBase``.
"""
import base64
import binascii
import hashlib
import json
import os
import socket
import string
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pqcrypto.kem import ml_kem_1024  # type: ignore

from SecureChatABCs.client_base import ClientBase
from SecureChatABCs.protocol_base import ProtocolBase
from SecureChatABCs.ui_base import UIBase, UICapability
from config import ClientConfigHandler
from protocol import constants, types, utils
from protocol.constants import (
    MessageType, PROTOCOL_VERSION,
    NONCE_SIZE, CTR_NONCE_SIZE, DOUBLE_KEY_SIZE,
    DEADDROP_KDF_KEY_LENGTH, DEADDROP_PBKDF2_ITERATIONS,
    DEADDROP_FILE_EXT_HEADER_SIZE, DEADDROP_HKDF_SALT_SIZE,
    MAGIC_SIZE, FILE_CHUNK_CIPHERTEXT_OFFSET,
    DEADDROP_NONCE_OFFSET, DEADDROP_CIPHERTEXT_OFFSET,
    DEADDROP_LENGTH_PREFIX_SIZE,
)
from protocol.create_messages import create_file_metadata_message
from protocol.crypto_classes import ChunkIndependentDoubleEncryptor
from protocol.file_handler import ProtocolFileHandler
from protocol.parse_messages import process_file_metadata
from protocol.shared import SecureChatProtocol
from protocol.types import FileMetadata, FileTransfer
from protocol.utils import chunk_file
from utils import network_utils
from utils.checks import allowed_outer_fields, allowed_unverified_inner_fields, first_unexpected_field
from utils.network_utils import encode_send_message, send_message

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
        
        # Voice call state
        self._voice_call_active: bool = False
        self.voice_muted: bool = False
        
        # File transfer state
        self.pending_file_transfers: dict[str, FileTransfer] = {}
        self.active_file_metadata: dict[str, FileMetadata] = {}
        self._last_progress_shown: dict[str, float | int] = {}
        self.file_transfer_update_interval: int = 10
        
        # Server version information
        self.server_protocol_version: str = "0.0.0"
        self.server_identifier: str = ""
        
        # Deaddrop session state
        self._deaddrop_shared_secret: bytes | None = None
        self.deaddrop_supported: bool = False
        self.deaddrop_max_size: int = 0
        self._deaddrop_in_progress: bool = False
        self._deaddrop_chunks: dict[int, bytes] = {}
        self._deaddrop_file_size: int = 0
        self._deaddrop_name: str = ""
        self._deaddrop_password_hash: str = ""
        # Download-specific state
        self._deaddrop_download_in_progress: bool = False
        self._deaddrop_download_name: str = ""
        self._deaddrop_download_expected_hash: str | None = None
        self._deaddrop_download_chunks: dict[int, bytes] = {}
        self._deaddrop_download_max_index: int = -1
        self._deaddrop_download_key: bytes | None = None
        # Streaming download state (for deaddrop)
        self._deaddrop_dl_encryptor: ChunkIndependentDoubleEncryptor | None = None
        self._deaddrop_dl_password: str = ""
        self._deaddrop_dl_next_nonce: bytes | None = None
        self._deaddrop_dl_expected_index: int = 0
        self._deaddrop_dl_part_path: str | None = None
        self._deaddrop_dl_file: BinaryIO | None = None
        self._deaddrop_dl_bytes_downloaded: int = 0
        # Event to signal completion of the deaddrop handshake
        self._deaddrop_handshake_event: threading.Event | None = None
        
        # Rate limiting
        self._rl_window_start: float = 0.0
        self._rl_count: int = 0
    
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
        return self._voice_call_active
    
    @property
    def voice_muted(self) -> bool:
        return self._voice_muted
    
    @voice_muted.setter
    def voice_muted(self, value: bool) -> None:
        self._voice_muted = value
    
    @property
    def file_transfer_active(self) -> bool:
        """True if any file transfer (regular or deaddrop download) is currently in progress."""
        return bool(self.pending_file_transfers or self.active_file_metadata or self._deaddrop_download_in_progress)
    
    @property
    def pending_file_requests(self) -> dict[str, FileMetadata]:
        return self.active_file_metadata
    
    @property
    def bypass_rate_limits(self) -> bool:
        """True when rate limiting should be suspended — during file transfers, voice calls, rekeying, or while key verification is still pending after key exchange."""
        return bool(self.file_transfer_active or self._voice_call_active or self._protocol.rekey_in_progress
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
            
            self._receive_thread = threading.Thread(target=self._receive_messages, daemon=True)
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
        
        # Reset deaddrop state
        self._deaddrop_shared_secret = None
        self.deaddrop_supported = False
        self.deaddrop_max_size = 0
        self._deaddrop_in_progress = False
        self._deaddrop_chunks = {}
        self._deaddrop_file_size = 0
        self._deaddrop_name = ""
        self._deaddrop_password_hash = ""
        self._deaddrop_download_in_progress = False
        self._deaddrop_download_name = ""
        self._deaddrop_download_expected_hash = None
        self._deaddrop_download_chunks = {}
        self._deaddrop_download_max_index = -1
        self._deaddrop_download_key = None
        self._deaddrop_dl_encryptor = None
        self._deaddrop_dl_password = ""
        self._deaddrop_dl_next_nonce = None
        self._deaddrop_dl_expected_index = 0
        self._deaddrop_dl_part_path = None
        self._deaddrop_dl_file = None
        self._deaddrop_dl_bytes_downloaded = 0
        if self._deaddrop_handshake_event is not None:
            self._deaddrop_handshake_event.set()
        self._deaddrop_handshake_event = None
        
        if self._receive_thread and self._receive_thread.is_alive():
            try:
                self._receive_thread.join(timeout=1.0)
            except Exception:
                pass
        
        self.ui.on_graceful_disconnect("Disconnected from server.")
    
    def end_call(self, notify_peer: bool = True) -> None:
        """End the current voice call and optionally notify the peer."""
        if not self._voice_call_active:
            return
        self._voice_call_active = False
        self._protocol.send_dummy_messages = True
        # Notify peer
        if notify_peer:
            self._protocol.queue_json({"type": MessageType.VOICE_CALL_END})
            self.ui.display_system_message("Voice call ended")
        
        self.ui.on_voice_call_end()
    
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
    
    # file transfer
    
    def send_file(self, file_path: Path | str, compress: bool = True) -> None:
        """Send a file to the peer by first transmitting its metadata and waiting for acceptance.

        The actual chunk transfer starts in a background thread once the peer accepts.
        Requires key verification to be complete.
        """
        try:
            if isinstance(file_path, str):
                file_path_obj = Path(file_path)
            else:
                file_path_obj = file_path
            if not self.verification_complete:
                self.ui.display_error_message("Cannot send file: Key verification not complete")
                return
            
            if not self.peer_key_verified:
                self.ui.display_system_message(
                        "Warning: Sending file over an unverified connection. This is vulnerable to MitM attacks.",
                )
            
            metadata = create_file_metadata_message(file_path_obj, compress=compress, chunk_size=config["send_chunk_size"])
            compress = metadata["compressed"]
            
            transfer_id = metadata["transfer_id"]
            self.pending_file_transfers[transfer_id] = FileTransfer(
                    file_path=file_path_obj,
                    metadata=metadata,
                    compress=compress,
            )
            metadata_message = deepcopy(dict(metadata))
            metadata_message["type"] = MessageType.FILE_METADATA
            self._protocol.queue_json(metadata_message)
            compression_text = "compressed" if compress else "uncompressed"
            self.ui.display_system_message(
                    f"File transfer request sent: {metadata['filename']} ({metadata['file_size']} bytes, {compression_text})",
            )
        
        except Exception as e:
            self.ui.display_error_message(f"Failed to send file: {e}")
    
    def reject_file_transfer(self, transfer_id: str) -> None:
        """Reject an incoming file transfer request identified by *transfer_id*."""
        self._protocol.queue_json({
            "type":        MessageType.FILE_REJECT,
            "transfer_id": transfer_id,
            "reason":      "User declined",
        })
        if transfer_id in self.active_file_metadata:
            del self.active_file_metadata[transfer_id]
    
    # key exchange & verification
    
    def initiate_key_exchange(self) -> None:
        """Step 3: Client A sends KE_DSA_RANDOM (DSA pubkey + random)."""
        msg = self._protocol.create_ke_dsa_random()
        self._protocol.ke_step = 1  # We are the initiator (Client A)
        send_message(self._socket, msg)
    
    def handle_ke_dsa_random(self, message_data: bytes) -> None:
        """Handle receiving KE_DSA_RANDOM from peer."""
        version_warning = self._protocol.process_ke_dsa_random(message_data)
        if version_warning:
            self.ui.display_system_message(f"{version_warning}")
        
        if self._protocol.ke_step == 0:
            # We are Client B, receiving Client A's DSA random (step 3)
            # Respond with our own DSA random (step 6)
            self._protocol.ke_step = 2
            msg = self._protocol.create_ke_dsa_random()
            send_message(self._socket, msg)
        elif self._protocol.ke_step == 1:
            # We are Client A, receiving Client B's DSA random (step 6)
            # Send ML-KEM pubkey (step 8)
            msg = self._protocol.create_ke_mlkem_pubkey()
            send_message(self._socket, msg)
    
    def handle_ke_mlkem_pubkey(self, message_data: bytes) -> None:
        """Handle receiving KE_MLKEM_PUBKEY (step 8) - only Client B receives this."""
        self._protocol.process_ke_mlkem_pubkey(message_data)
        # Client B responds with KE_MLKEM_CT_KEYS (step 10)
        msg = self._protocol.create_ke_mlkem_ct_keys()
        send_message(self._socket, msg)
    
    def handle_ke_mlkem_ct_keys(self, message_data: bytes) -> None:
        """Handle receiving KE_MLKEM_CT_KEYS (step 10) - only Client A receives this."""
        self._protocol.process_ke_mlkem_ct_keys(message_data)
        # Client A responds with KE_X25519_HQC_CT (step 13)
        msg = self._protocol.create_ke_x25519_hqc_ct()
        send_message(self._socket, msg)
    
    def handle_ke_x25519_hqc_ct(self, message_data: bytes) -> None:
        """Handle receiving KE_X25519_HQC_CT (step 13) - only Client B receives this.
        Client B derives final keys and sends verification."""
        self._protocol.process_ke_x25519_hqc_ct(message_data)
        # Client B now has final keys, send verification (step 15)
        msg = self._protocol.create_ke_verification()
        send_message(self._socket, msg)
    
    def handle_ke_verification(self, message_data: bytes) -> None:
        """Handle receiving KE_VERIFICATION from peer."""
        if self._protocol.ke_step == 1:
            # We are Client A, receiving Client B's verification (step 15)
            # Keys already finalized in create_ke_x25519_hqc_ct (step 12)
            if not self._protocol.process_ke_verification(message_data):
                self.ui.display_error_message("Key exchange verification failed!")
                return
            # Send our own verification back (step 16)
            msg = self._protocol.create_ke_verification()
            send_message(self._socket, msg)
            self.ui.display_system_message("Key exchange completed successfully.")
            self.handle_key_exchange_complete()
        elif self._protocol.ke_step == 2:
            # We are Client B, receiving Client A's verification (step 16)
            if not self._protocol.process_ke_verification(message_data):
                self.ui.display_error_message("Key exchange verification failed!")
                return
            self.ui.display_system_message("Key exchange completed successfully.")
            self.handle_key_exchange_complete()
    
    def handle_key_exchange_complete(self) -> None:
        """Mark the key exchange as complete and immediately start key verification."""
        self._key_exchange_complete = True
        self.ui.on_key_exchange_complete()
        self.start_key_verification()
    
    def start_key_verification(self) -> None:
        """Initiate key verification — delegates the prompt to the UI."""
        self._verification_started = True
        fingerprint = self._protocol.get_own_key_fingerprint()
        verified = self.ui.prompt_key_verification(fingerprint)
        self.confirm_key_verification(verified)
    
    def confirm_key_verification(self, verified: bool) -> None:
        """Record the local user's verification decision, send it to the peer, and start the sender thread."""
        self._peer_key_verified = verified
        verification_message = self._protocol.create_key_verification_message(verified)
        send_message(self._socket, verification_message)
        
        self._verification_complete = True
        self._protocol.start_sender_thread(self._socket)
    
    def get_own_key_fingerprint(self) -> str:
        return self._protocol.get_own_key_fingerprint()
    
    def handle_key_verification_message(self, message_data: bytes) -> None:
        """Process the peer's key verification result and notify the UI."""
        try:
            peer_verified = self._protocol.process_key_verification_message(message_data)
        except types.DecodeError as e:
            self.ui.display_error_message(str(e))
            return
        
        self._peer_verified_own_key = peer_verified
        self.ui.on_peer_verified_our_key(peer_verified)
    
    def initiate_rekey(self) -> None:
        if not self.key_exchange_complete:
            self.ui.display_error_message("Cannot rekey - key exchange not complete")
            return
        if self._protocol.rekey_in_progress:
            self.ui.display_system_message("Rekey already in progress.")
            return
        msg = self._protocol.create_rekey_dsa_random(is_initiator=True)
        self._protocol.queue_json(msg)
        self.ui.display_system_message("Rekey initiated.")
    
    def check_and_initiate_auto_rekey(self) -> None:
        """
        Trigger a rekey if the protocol's message counter threshold has been reached.

        Skipped when rate-limit bypass is active (file transfer, voice call, etc.) or
        when a file transfer is in progress, to avoid disrupting those flows.
        """
        if not self._protocol.should_auto_rekey:
            return
        if self.bypass_rate_limits:
            self._protocol.reset_auto_rekey_counter()
            return
        if self.file_handler.has_active_file_transfers:
            return
        if not self.key_exchange_complete:
            return
        msg = self._protocol.create_rekey_dsa_random(is_initiator=True)
        self._protocol.queue_json(msg)
    
    # voice calls
    
    def request_voice_call(self, rate: int, chunk_size: int, audio_format: int) -> None:
        """Send a voice call initiation request to the peer."""
        if not self.peer_key_verified:
            self.ui.display_system_message(
                    "Warning: Requesting a voice call over an unverified connection. "
                    "This is vulnerable to MitM attacks.",
            )
        to_send = {
            "type":         MessageType.VOICE_CALL_INIT,
            "rate":         rate,
            "chunk_size":   chunk_size,
            "audio_format": audio_format,
        }
        self._protocol.queue_json(to_send)
    
    def on_user_response(self, accepted: bool, rate: int, chunk_size: int, audio_format: int) -> None:
        """Handle the local user's response to an incoming voice call."""
        if accepted:
            self._voice_call_active = True
            self._protocol.queue_json({
                "type":         MessageType.VOICE_CALL_ACCEPT,
                "rate":         rate,
                "chunk_size":   chunk_size,
                "audio_format": audio_format,
            })
        
        else:
            self._protocol.queue_json({
                "type": MessageType.VOICE_CALL_REJECT,
            })
            
            self.ui.display_system_message("Rejected voice call")
    
    def send_voice_data(self, audio_data: bytes) -> None:
        """Send voice data to the peer during an active voice call."""
        print('Sending voice data')
        if not (self._voice_call_active and self._protocol):
            return
        
        message = json.dumps({
            "type":       MessageType.VOICE_CALL_DATA,
            "audio_data": base64.b64encode(audio_data).decode('utf-8'),
        },
        )
        network_utils.send_message(self._socket, self._protocol.encrypt_message(message))
    
    def send_ephemeral_mode_change(self, mode: str) -> None:
        """Send an encrypted EPHEMERAL_MODE_CHANGE message to the peer."""
        if not self._protocol:
            return
        payload = {
            "type": MessageType.EPHEMERAL_MODE_CHANGE,
            "mode": mode,
        }
        self._protocol.queue_json(payload)
    
    # deaddrop
    
    def start_deaddrop(self) -> None:
        self.start_deaddrop_handshake()
    
    def deaddrop_session_active(self) -> bool:
        return self._deaddrop_shared_secret is not None
    
    def start_deaddrop_handshake(self) -> None:
        """Send a DEADDROP_START frame to the server to begin the deaddrop key-exchange handshake."""
        if not self.connected:
            self.ui.display_error_message("Cannot start deaddrop - not connected")
            return
        if self._deaddrop_in_progress:
            self.ui.display_error_message("Deaddrop already in progress")
            return
        
        self._deaddrop_shared_secret = None
        self.deaddrop_supported = False
        if self._deaddrop_handshake_event is None:
            self._deaddrop_handshake_event = threading.Event()
        else:
            self._deaddrop_handshake_event.clear()
        
        self.ui.display_system_message("Starting deaddrop handshake")
        msg = {"type": MessageType.DEADDROP_START}
        encode_send_message(self._socket, msg)
    
    def wait_for_deaddrop_handshake(self, timeout: float = 3.0) -> bool:
        """Block until the deaddrop handshake completes or *timeout* seconds elapse.

        Returns True if the handshake succeeded and a shared secret was established.
        """
        if not self.connected:
            self.ui.display_error_message("Cannot wait for deaddrop handshake - not connected")
            return False
        if self._deaddrop_handshake_event is None:
            self.ui.display_error_message("Deaddrop handshake has not been started")
            return False
        completed = self._deaddrop_handshake_event.wait(timeout)
        if not completed:
            self.ui.display_error_message("Deaddrop handshake timed out")
            return False
        return bool(self._deaddrop_shared_secret)
    
    def deaddrop_upload(self, name: str, password: str, file_path: Path) -> None:
        """Encrypt and upload a file to the server's deaddrop store.

        The file is encrypted chunk-by-chunk with a key derived from *password* and the
        server identifier. A password hash (Argon2id) is sent alongside the metadata so
        the server can authenticate future download requests.
        """
        if not self._deaddrop_shared_secret:
            self.ui.display_error_message("Deaddrop not initialised - handshake required")
            return
        
        if not file_path.is_file():
            self.ui.display_error_message(f"File not found: {file_path}")
            return
        
        file_size = file_path.resolve().stat().st_size
        if self.deaddrop_max_size and file_size > self.deaddrop_max_size:
            self.ui.display_error_message("File exceeds maximum deaddrop size allowed by server")
            return
        
        hkdf_salt = os.urandom(DEADDROP_HKDF_SALT_SIZE)
        key = self._derive_deaddrop_file_key(password, hkdf_salt)
        h = HMAC(key, hashes.SHA3_512())
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        file_hash = base64.b64encode(h.finalize()).decode("utf-8")
        
        password_hash = self._hash_deaddrop_password(password)
        self._deaddrop_file_size = file_size
        self._deaddrop_name = name
        self._deaddrop_password_hash = password_hash
        
        inner_meta = {
            "type":               MessageType.DEADDROP_UPLOAD,
            "name":               name,
            "file_size":          file_size,
            "file_hash":          file_hash,
            "file_password_hash": password_hash,
            "file_key_salt":      base64.b64encode(hkdf_salt).decode("utf-8"),
        }
        outer_meta = self._encrypt_deaddrop_inner(json.dumps(inner_meta).encode("utf-8"))
        encode_send_message(self._socket, outer_meta)
        
        encryptor = ChunkIndependentDoubleEncryptor(key)
        self._deaddrop_chunks.clear()
        
        chunk_index = 0
        file_ext = os.path.splitext(file_path)[1][:DEADDROP_FILE_EXT_HEADER_SIZE]
        header = file_ext.encode("utf-8").ljust(DEADDROP_FILE_EXT_HEADER_SIZE, b"\x00")
        with open(file_path, "rb") as f:
            first = True
            while True:
                if first:
                    chunk_data = f.read(config["send_chunk_size"] - DEADDROP_FILE_EXT_HEADER_SIZE)
                    plaintext_chunk = header + chunk_data
                    first = False
                else:
                    chunk_data = f.read(config["send_chunk_size"])
                    plaintext_chunk = chunk_data
                nonce = hashlib.sha3_256(key + chunk_index.to_bytes(4, byteorder='little')).digest()[:CTR_NONCE_SIZE]
                if not chunk_data:
                    break
                
                ct = encryptor.encrypt(nonce, plaintext_chunk)
                payload = chunk_index.to_bytes(4, byteorder='little') + ct
                outer_nonce = os.urandom(NONCE_SIZE)
                frame = self._encrypt_deaddrop_chunk(payload, outer_nonce)
                
                result = send_message(self._socket, frame)
                if result is not None:
                    self.ui.display_error_message(f"Failed to send chunk: {result}")
                    chunk_index += 1
                    continue
                
                chunk_index += 1
                if chunk_index % 50 == 0:
                    self.ui.display_system_message(f"{utils.bytes_to_human_readable(chunk_index * 1024 * 1024)}/"
                                                   f"{utils.bytes_to_human_readable(file_size)} sent",
                                                   )
        
        complete_inner = {"type": MessageType.DEADDROP_COMPLETE}
        complete_outer = self._encrypt_deaddrop_inner(json.dumps(complete_inner).encode("utf-8"))
        encode_send_message(self._socket, complete_outer)
        self.ui.display_system_message("Deaddrop upload complete")
    
    def deaddrop_check(self, name: str) -> None:
        """Ask the server whether a deaddrop entry with the given *name* exists."""
        if not self._deaddrop_shared_secret:
            self.ui.display_error_message("Deaddrop not initialised - handshake required")
            return
        self._deaddrop_name = name
        inner = {
            "type": MessageType.DEADDROP_CHECK,
            "name": name,
        }
        outer = self._encrypt_deaddrop_inner(json.dumps(inner).encode("utf-8"))
        encode_send_message(self._socket, outer)
    
    def deaddrop_download(self, name: str, password: str) -> None:
        """Request a deaddrop file download from the server.

        Initialises streaming download state and derives the decryption key from *password*
        before sending the download request. Incoming chunks are processed by
        _process_deaddrop_data_streaming as they arrive.
        """
        if not self._deaddrop_shared_secret:
            self.ui.display_error_message("Deaddrop not initialised - handshake required")
            return
        
        self._deaddrop_name = name
        self._deaddrop_password_hash = self._hash_deaddrop_password(password)
        self._deaddrop_dl_password = password
        self._deaddrop_download_in_progress = True
        self._deaddrop_download_chunks.clear()
        self._deaddrop_download_max_index = -1
        self._deaddrop_download_expected_hash = None
        key = self._derive_deaddrop_file_key(password)
        self._deaddrop_download_key = key
        self._deaddrop_dl_encryptor = None
        self._deaddrop_dl_next_nonce = None
        self._deaddrop_dl_expected_index = 0
        self._deaddrop_dl_part_path = None
        if self._deaddrop_dl_file:
            try:
                self._deaddrop_dl_file.close()
            except Exception:
                pass
            self._deaddrop_dl_file = None
        
        inner_dl = {
            "type": MessageType.DEADDROP_DOWNLOAD,
            "name": name,
        }
        outer_dl = self._encrypt_deaddrop_inner(json.dumps(inner_dl).encode("utf-8"))
        encode_send_message(self._socket, outer_dl)
    
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
        self.pending_file_transfers.clear()
        self.active_file_metadata.clear()
    
    def _receive_messages(self) -> None:
        """Background thread loop: read raw frames from the socket and dispatch them to handle_message."""
        while self.connected:
            try:
                message_data = network_utils.receive_message(self._socket, max_size=config["max_message_size"])
                self.handle_message(message_data)
            except ConnectionError:
                self.ui.display_system_message("Connection to server lost.")
                break
            except Exception as e:
                if not self.connected:
                    break
                self.ui.display_error_message(f"Error receiving message: {e}")
                break
    
    def _try_log_decrypted(self, message_data: bytes, context: str) -> None:
        """Attempt to decrypt a dropped message and log raw bytes + decrypted text if successful."""
        proto = getattr(self, "_protocol", None)
        if proto is None or not self.key_exchange_complete:
            self.ui.log_raw_bytes("RECV", context, message_data)
            return
        try:
            decrypted = proto.decrypt_message(message_data)
            self.ui.log_raw_bytes("RECV", context + ":decrypted", message_data, decrypted_text=decrypted)
        except (ValueError, Exception):
            self.ui.log_raw_bytes("RECV", context, message_data)
    
    def handle_message(self, message_data: bytes) -> None:
        """Top-level dispatcher for all incoming frames.

        Enforces rate limiting and size checks before attempting to parse the message type
        and routing to the appropriate handler. Binary frames (file chunks, deaddrop chunks)
        are handled via handle_maybe_binary_chunk.
        """
        if not self.bypass_rate_limits:
            now = time.time()
            if now - self._rl_window_start >= 1.0:
                self._rl_window_start = now
                self._rl_count = 0
            if self._rl_count >= 6:
                self.ui.display_error_message("Rate-limited peer: dropped message")
                self._try_log_decrypted(message_data, "dropped:rate_limit")
                return
            self._rl_count += 1
        
        if len(message_data) > 33260 and not self.bypass_rate_limits:
            self.ui.display_error_message("Received overly large message without key verification. Dropping." +
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
                self.ui.display_error_message("Received message that could not be decoded.")
                self.ui.log_raw_bytes("RECV", "dropped:decode_error", message_data)
            return
        
        if message_type == MessageType.NONE:
            self.ui.display_error_message("Received message with invalid type.")
            return
        
        allowed = allowed_outer_fields(message_type)
        unexpected = first_unexpected_field(message_json, allowed)
        if unexpected:
            self.ui.display_error_message(f"Dropped message from unverified peer due to unexpected field '{unexpected}'.")
            return
        
        match message_type:
            case MessageType.KE_DSA_RANDOM:
                self.handle_ke_dsa_random(message_data)
            case MessageType.KE_MLKEM_PUBKEY:
                self.handle_ke_mlkem_pubkey(message_data)
            case MessageType.KE_MLKEM_CT_KEYS:
                self.handle_ke_mlkem_ct_keys(message_data)
            case MessageType.KE_X25519_HQC_CT:
                self.handle_ke_x25519_hqc_ct(message_data)
            case MessageType.KE_VERIFICATION:
                self.handle_ke_verification(message_data)
            case MessageType.ENCRYPTED_MESSAGE:
                if self.key_exchange_complete:
                    self.handle_encrypted_message(message_data)
                else:
                    self.ui.display_error_message("\nReceived encrypted message before key exchange complete")
            case MessageType.ERROR:
                self.ui.display_error_message(f"{message_json.get('error', 'Unknown error')}")
            case MessageType.KEY_VERIFICATION:
                self.handle_key_verification_message(message_data)
            case MessageType.KEY_EXCHANGE_RESET:
                self.handle_key_exchange_reset(message_data)
            case MessageType.KEEP_ALIVE:
                self.handle_keepalive()
            case MessageType.INITIATE_KEY_EXCHANGE:
                self.initiate_key_exchange()
            case MessageType.SERVER_FULL:
                self.handle_server_full()
            case MessageType.SERVER_VERSION_INFO:
                self.handle_server_version_info(message_data)
            case MessageType.SERVER_DISCONNECT:
                reason = message_json.get('reason', 'Server initiated disconnect')
                self.on_server_disconnect(reason)
            case MessageType.DEADDROP_START:
                self._handle_deaddrop_start_response(message_json)
            case MessageType.DEADDROP_MESSAGE:
                self._handle_deaddrop_encrypted_message(message_json)
            case _:
                self.ui.display_error_message(f"Unknown message type: {message_type}")
        return
    
    def handle_maybe_binary_chunk(self, message_data: bytes) -> bool:
        """Try to interpret a non-JSON frame as an encrypted binary chunk (file transfer or deaddrop).

        Returns True if the frame was recognised and handled, False otherwise.
        """
        if not len(message_data) >= FILE_CHUNK_CIPHERTEXT_OFFSET:
            return False
        magic: bytes = message_data[:MAGIC_SIZE]
        if magic == constants.MAGIC_NUMBER_FILE_TRANSFER:
            try:
                result = self._protocol.decrypt_file_chunk(message_data)
                self.handle_file_chunk_binary(result)
                return True
            except ValueError:
                return False
        elif magic == constants.MAGIC_NUMBER_DEADDROPS:
            try:
                self._handle_deaddrop_binary_chunk(message_data)
                return True
            except ValueError:
                return False
        return False
    
    def handle_keepalive(self) -> None:
        """Respond to a server keepalive ping to prevent the connection from being dropped."""
        response_message = {"type": MessageType.KEEP_ALIVE_RESPONSE}
        result = encode_send_message(self._socket, response_message)
        if result is not None:
            self.ui.display_error_message(f"Failed to send keepalive response: {result}")
            self.ui.display_system_message("Server may disconnect after 3 keepalive failures.")
    
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
                self.handle_file_metadata(message_json)
            
            case MessageType.FILE_ACCEPT:
                self.handle_file_accept(message_json)
            
            case MessageType.FILE_REJECT:
                self.handle_file_reject(message_json)
            
            case MessageType.FILE_COMPLETE:
                self.handle_file_complete(message_json)
            
            case MessageType.DELIVERY_CONFIRMATION:
                if self.key_exchange_complete:
                    self.handle_delivery_confirmation(message_json)
            
            case MessageType.EPHEMERAL_MODE_CHANGE:
                self.handle_ephemeral_mode_change(message_json)
            
            case MessageType.REKEY:
                self.handle_rekey(message_json)
            
            case MessageType.VOICE_CALL_INIT:
                self.handle_voice_call_init(message_json)
            
            case MessageType.VOICE_CALL_ACCEPT:
                self.handle_voice_call_accept(message_json)
            
            case MessageType.VOICE_CALL_REJECT:
                self.handle_voice_call_reject()
            
            case MessageType.VOICE_CALL_DATA:
                self.handle_voice_call_data(message_json)
            
            case MessageType.VOICE_CALL_END:
                self.handle_voice_call_end()
            
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
    
    def handle_key_exchange_reset(self, message_data: bytes) -> None:
        """Handle a KEY_EXCHANGE_RESET from the server: tear down the current session and prepare for a fresh key exchange."""
        message = json.loads(message_data.decode('utf-8'))
        reset_message = message.get("message", "Key exchange reset")
        
        self._key_exchange_complete = False
        self._verification_complete = False
        self._verification_started = False
        self._peer_key_verified = False
        self._peer_verified_own_key = False
        self._protocol.reset_key_exchange()
        self.file_handler.clear()
        
        self.peer_nickname = "Other user"
        
        self.pending_file_transfers.clear()
        self.active_file_metadata.clear()
        self._last_progress_shown.clear()
        
        self.end_call(notify_peer=False)
        
        self.ui.display_system_message("KEY EXCHANGE RESET")
        self.ui.display_system_message(f"Reason: {reset_message}")
        self.ui.display_system_message("The secure session has been terminated.")
        self.ui.display_system_message("Waiting for a new client to connect...")
        self.ui.display_system_message("A new key exchange will start automatically.")
    
    def handle_emergency_close(self) -> None:
        """Handle an EMERGENCY_CLOSE message from the peer: notify the UI and immediately disconnect."""
        self.ui.on_emergency_close()
        self.ui.display_system_message("EMERGENCY CLOSE RECEIVED")
        self.ui.display_system_message("The other client has activated emergency close.")
        self.ui.display_system_message("Connection will be terminated immediately.")
        
        self.disconnect()
        self._key_exchange_complete = False
        self._verification_complete = False
        self._protocol.reset_key_exchange()
        self.file_handler.clear()
        
        self.pending_file_transfers.clear()
        self.active_file_metadata.clear()
    
    def handle_ephemeral_mode_change(self, message: dict[str, Any]) -> None:
        """Apply an ephemeral-mode change from the server, but only if the owner ID matches the known server identifier."""
        mode = str(message.get("mode", "OFF")).upper()
        owner_id = message.get("owner_id")
        
        if owner_id == self.server_identifier:
            self.ui.on_ephemeral_mode_change(mode, owner_id)
        else:
            self.ui.display_error_message(f"Ignored ephemeral mode change: invalid owner '{owner_id}'")
    
    def handle_file_metadata(self, decrypted_message: dict[str, Any]) -> None:
        """Handle an incoming file transfer request: validate metadata, prompt the user, and send accept/reject."""
        try:
            metadata = process_file_metadata(decrypted_message)
        except KeyError as e:
            self.ui.display_error_message(str(e))
            return
        transfer_id = metadata["transfer_id"]
        if not self.allow_file_transfers:
            self.ui.display_system_message("File transfers are disabled. Ignoring incoming file.")
            self._protocol.queue_json({
                "type":        MessageType.FILE_REJECT,
                "transfer_id": transfer_id,
                "reason":      "User disabled file transfers",
            })
            return
        
        if not self.peer_key_verified:
            self.ui.display_system_message("Warning: Incoming file request over an unverified connection. "
                                           "This is vulnerable to MitM attacks.",
                                           )
        
        self.active_file_metadata[transfer_id] = metadata
        
        compressed_size: int | None = int(metadata["compressed_size"]) if metadata.get("compressed", False) and "compressed_size" in metadata else None
        result = self.ui.prompt_file_transfer(
                metadata["filename"],
                metadata["file_size"],
                metadata["total_chunks"],
                compressed_size,
        )
        
        if result is False or result is None:
            self._protocol.queue_json({
                "type":        MessageType.FILE_REJECT,
                "transfer_id": transfer_id,
                "reason":      "User declined",
            })
            del self.active_file_metadata[transfer_id]
        else:
            self._protocol.queue_json({
                "type":        MessageType.FILE_ACCEPT,
                "transfer_id": transfer_id,
            })
            self._protocol.send_dummy_messages = False
    
    def handle_file_accept(self, message: dict[str, Any]) -> None:
        """Handle the peer's acceptance of a pending file transfer and start sending chunks in a background thread."""
        self._protocol.send_dummy_messages = False
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self.ui.display_error_message("Received acceptance without transfer ID")
            self._protocol.send_dummy_messages = True
            return
        
        if transfer_id not in self.pending_file_transfers:
            self.ui.display_system_message("Received acceptance for unknown file transfer")
            self._protocol.send_dummy_messages = True
            return
        
        transfer_info = self.pending_file_transfers[transfer_id]
        file_path = transfer_info["file_path"]
        
        self.ui.display_system_message(f"File transfer accepted. Sending {transfer_info['metadata']['filename']}...")
        
        self.file_handler.sending_transfers[transfer_id] = transfer_info['metadata']
        
        chunk_thread = threading.Thread(
                target=self._send_file_chunks,
                args=(transfer_id, file_path),
                daemon=True,
        )
        chunk_thread.start()
    
    def handle_file_reject(self, message: dict[str, Any]) -> None:
        """Handle the peer's rejection of a pending file transfer and clean up local state."""
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self.ui.display_error_message("Received rejection without transfer ID")
            return
        reason = message.get("reason", "Unknown reason")
        
        if transfer_id in self.pending_file_transfers:
            filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
            self.ui.display_system_message(f"File transfer rejected: {filename} - {reason}")
            self.file_handler.stop_sending_transfer(transfer_id)
            del self.pending_file_transfers[transfer_id]
        else:
            self.ui.display_error_message("Received rejection for unknown file transfer")
    
    def handle_rekey(self, inner: dict[str, Any]) -> None:
        """Drive the four-step rekey handshake (init → response → commit → commit_ack).

        When the peer initiates a rekey over an unverified connection the user is prompted
        before proceeding; declining causes an immediate disconnect.
        """
        try:
            action = inner["action"]
        except KeyError:
            self.ui.display_error_message("Dropped rekey message without action. Invalid JSON.")
            return
        match action:
            case "dsa_random":
                # Peer initiated rekey (or race response). Prompt if peer is unverified and
                # we didn't initiate ourselves.
                if not self._protocol.rekey_in_progress:
                    self.ui.on_rekey_initiated_by_peer()
                    if not self.peer_key_verified:
                        proceed = self.ui.prompt_rekey()
                        if proceed is False:
                            self.ui.display_system_message(
                                    "Disconnecting as requested: rekey received from an unverified peer.")
                            self.disconnect()
                            return
                        elif proceed is None:
                            return
                    self.ui.display_system_message("Rekey initiated by peer.")
                try:
                    response = self._protocol.process_rekey_dsa_random(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                if response is not None:
                    self._protocol.queue_json(response)
            
            case "mlkem_pubkey":
                # B receives A's signed ML-KEM pubkey
                try:
                    response = self._protocol.process_rekey_mlkem_pubkey(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                self._protocol.queue_json(response)
            
            case "mlkem_ct_keys":
                # A receives B's ML-KEM ciphertext + encrypted pubkeys
                try:
                    response = self._protocol.process_rekey_mlkem_ct_keys(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                self._protocol.queue_json(response)  # x25519_hqc_ct
                self._protocol.queue_json(self._protocol.create_rekey_verification())  # A's verification
            
            case "x25519_hqc_ct":
                # B receives A's X25519 pubkey + encrypted HQC ciphertext; pending keys computed
                try:
                    self._protocol.process_rekey_x25519_hqc_ct(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                # Send verification under old keys, then activate — ensures A can decrypt B's proof.
                # on_rekey_complete deferred until B also verifies A's proof (in "verification" case).
                self._protocol.queue_json_then_switch(self._protocol.create_rekey_verification())
            
            case "verification":
                # Both A and B arrive here to verify peer's proof.
                # A still has pending keys; B has already activated via queue_json_then_switch.
                # process_rekey_verification falls back to active key material when pending is gone.
                try:
                    ok = self._protocol.process_rekey_verification(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                if not ok:
                    self._protocol.reset_rekey("Rekey verification failed — possible MitM.")
                    self.ui.display_error_message("Rekey verification failed — possible MitM. Rekey aborted.")
                    return
                # A activates pending keys here; B already activated, so skip.
                if self._protocol.rekey_pending_keys_exist:
                    self._protocol.activate_pending_keys()
                self.ui.on_rekey_complete()
            
            case _:
                self.ui.display_error_message("Received unknown rekey action")
    
    def handle_voice_call_init(self, init_msg: dict[str, Any]) -> None:
        """Handle incoming voice call request."""
        if not self.ui.has_capability(UICapability.VOICE_CALLS):
            self._protocol.queue_json({"type": MessageType.VOICE_CALL_REJECT})
            self.ui.display_system_message("Auto-rejected incoming voice call (unsupported by UI).")
            return
        
        if not self.peer_key_verified:
            self.ui.display_system_message(
                    "Warning: Incoming voice call over an unverified connection. "
                    "This is vulnerable to MitM attacks.",
            )
        
        self.ui.on_voice_call_init(init_msg)
    
    def handle_voice_call_accept(self, message: dict[str, Any]) -> None:
        self._voice_call_active = True
        self.ui.on_voice_call_accept(message)
    
    def handle_voice_call_reject(self) -> None:
        self._voice_call_active = False
        self.ui.on_voice_call_reject()
    
    def handle_voice_call_data(self, data: dict[str, Any]) -> None:
        print('Received voice data')
        if not self._voice_call_active:
            return
        self.ui.on_voice_call_data(data)
    
    def handle_voice_call_end(self) -> None:
        self._voice_call_active = False
        self.ui.on_voice_call_end()
    
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
    
    def handle_file_chunk_binary(self, chunk_info: dict[str, Any]) -> None:
        """Store a received file chunk and, once all chunks have arrived, reassemble and save the file."""
        transfer_id = chunk_info["transfer_id"]
        
        if transfer_id not in self.active_file_metadata:
            self.ui.display_error_message("Received chunk for unknown file transfer")
            return
        
        metadata = self.active_file_metadata[transfer_id]
        
        is_complete = self.file_handler.add_file_chunk(
                transfer_id,
                chunk_info["chunk_index"],
                chunk_info["chunk_data"],
                metadata["total_chunks"],
                chunk_size=config["send_chunk_size"],
        )
        
        received_chunks = len(self.file_handler.received_chunks.get(transfer_id, set()))
        progress = (received_chunks / metadata["total_chunks"]) * 100
        
        if transfer_id not in self._last_progress_shown:
            self._last_progress_shown[transfer_id] = -1
        
        if (progress - self._last_progress_shown[transfer_id] >= 10 or
                is_complete or
                received_chunks == 1):
            self.ui.file_download_progress(
                    transfer_id,
                    metadata["filename"],
                    received_chunks,
                    metadata["total_chunks"],
            )
            self._last_progress_shown[transfer_id] = progress
        
        if is_complete:
            output_path = os.path.join(os.getcwd(), metadata["filename"])
            
            counter = 1
            base_name, ext = os.path.splitext(metadata["filename"])
            while os.path.exists(output_path):
                output_path = os.path.join(os.getcwd(), f"{base_name}_{counter}{ext}")
                counter += 1
            
            try:
                compressed = metadata.get("compressed", True)
                self.file_handler.reassemble_file(transfer_id, output_path, metadata["file_hash"],
                                                  compressed=compressed,
                                                  )
                self.ui.on_file_transfer_complete(transfer_id, output_path)
                
                self._protocol.queue_json({
                    "type":        MessageType.FILE_COMPLETE,
                    "transfer_id": transfer_id,
                })
            
            except Exception as e:
                self.ui.display_error_message(f"File reassembly failed: {e}")
            
            del self.active_file_metadata[transfer_id]
            if transfer_id in self._last_progress_shown:
                del self._last_progress_shown[transfer_id]
    
    def handle_file_complete(self, message: dict[str, Any]) -> None:
        """Handle the peer's FILE_COMPLETE acknowledgement and clean up the outgoing transfer state."""
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self.ui.display_error_message("Dropped file complete message without transfer ID. Invalid JSON.")
            return
        
        if transfer_id in self.pending_file_transfers:
            filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
            self.ui.display_system_message(f"File transfer completed: {filename}")
            del self.pending_file_transfers[transfer_id]
            self._protocol.send_dummy_messages = True
        else:
            self.ui.display_error_message(f"Received file complete for unknown transfer ID: {transfer_id}")
    
    def handle_server_full(self) -> None:
        self.ui.display_error_message("Server is full. Cannot connect at this time.")
        self.ui.display_error_message("Please try again later.")
        self.disconnect()
    
    def handle_server_version_info(self, message_data: bytes) -> None:
        """Parse the server's version/identifier frame, store the values, and warn if the protocol major version differs."""
        message = json.loads(message_data)
        self.server_protocol_version = message.get("protocol_version", "0.0.0")
        if self.server_protocol_version == "0.0.0":
            self.ui.display_error_message("Server returned invalid protocol version information, communication may " +
                                          "still work but may be unreliable or have missing features.",
                                          )
        
        self.ui.display_system_message(f"Server Protocol Version: v{self.server_protocol_version}")
        identifier = message.get("identifier", "")
        if isinstance(identifier, str) and identifier.strip():
            self.server_identifier = identifier.strip()
            self._protocol.set_server_identifier(self.server_identifier)
            self.ui.display_system_message(f"Server Identifier: {self.server_identifier}")
        
        if self.server_protocol_version != PROTOCOL_VERSION:
            self.ui.display_system_message(f"Protocol version mismatch: Client v{PROTOCOL_VERSION}, "
                                           f"Server v{self.server_protocol_version}",
                                           )
            major_server = self.server_protocol_version.split('.')[0]
            major_client = PROTOCOL_VERSION.split('.')[0]
            if major_server != major_client:
                self.ui.display_error_message("Versions may not be compatible - communication issues possible")
    
    def on_server_disconnect(self, reason: str) -> None:
        self.ui.display_system_message(f"Server disconnected: {reason}")
        self.disconnect()
    
    def _send_file_chunks(self, transfer_id: str, file_path: str) -> None:
        """Background thread: read, encrypt, and send all chunks for an accepted file transfer."""
        try:
            transfer_info = self.pending_file_transfers[transfer_id]
            total_chunks = int(transfer_info["metadata"]["total_chunks"])
            compress = transfer_info.get("compress", True)
            filename = transfer_info["metadata"]["filename"]
            
            chunk_generator = chunk_file(file_path, compress=compress, chunk_size=config["send_chunk_size"])
            bytes_transferred = 0
            
            for i, chunk in enumerate(chunk_generator):
                if transfer_id not in self.pending_file_transfers:
                    break
                
                send_message(self._socket, self._protocol.encrypt_file_chunk(transfer_id, i, chunk))
                bytes_transferred += len(chunk)
                
                # Show progress in UI with frequency based on transfer size
                update_frequency = 1 if total_chunks <= 10 else (5 if total_chunks <= 50 else 10)
                if (i + 1) % update_frequency == 0 or (i + 1) == total_chunks:
                    self.ui.file_upload_progress(
                            transfer_id,
                            filename,
                            i + 1,
                            total_chunks,
                            bytes_transferred,
                    )
            
            self.ui.display_system_message(f"File chunks sent successfully: {filename}")
            self.file_handler.stop_sending_transfer(transfer_id)
        
        except Exception as e:
            self.ui.display_error_message(f"Error sending file chunks: {e}")
            self.file_handler.stop_sending_transfer(transfer_id)
    
    # deaddrop internal
    
    def _handle_deaddrop_start_response(self, message: dict[str, Any]) -> None:
        """Process the server's response to a DEADDROP_START request.

        If the server supports deaddrops, performs a ML-KEM key encapsulation to derive
        a shared secret used for all subsequent deaddrop messages, then signals the
        handshake event so that wait_for_deaddrop_handshake can return.
        """
        supported = bool(message.get("supported", False))
        if not supported:
            reason = message.get("reason", "Server does not support deaddrop")
            self.ui.display_error_message(reason)
            self._deaddrop_shared_secret = None
            self.deaddrop_supported = False
            self._deaddrop_in_progress = False
            if self._deaddrop_handshake_event is not None:
                self._deaddrop_handshake_event.set()
            return
        
        try:
            mlkem_public_b64 = str(message["mlkem_public"])
            mlkem_public = base64.b64decode(mlkem_public_b64, validate=True)
        except KeyError:
            self.ui.display_error_message("Invalid deaddrop start response: missing mlkem_public")
            if self._deaddrop_handshake_event is not None:
                self._deaddrop_handshake_event.set()
            return
        except binascii.Error:
            self.ui.display_error_message("Invalid deaddrop start response: bad mlkem_public encoding")
            if self._deaddrop_handshake_event is not None:
                self._deaddrop_handshake_event.set()
            return
        
        mlkem_ciphertext, kem_shared_secret = ml_kem_1024.encrypt(mlkem_public)
        
        self._deaddrop_shared_secret = ConcatKDFHash(
                algorithm=hashes.SHA3_512(),
                length=DEADDROP_KDF_KEY_LENGTH,
                otherinfo=b"deaddrop_key_exchange" + self.server_identifier.encode("utf-8"),
        ).derive(kem_shared_secret)
        
        self.deaddrop_supported = True
        self.deaddrop_max_size = int(message.get("max_file_size", 0))
        
        resp = {
            "type":     MessageType.DEADDROP_KE_RESPONSE,
            "mlkem_ct": base64.b64encode(mlkem_ciphertext).decode("utf-8"),
        }
        encode_send_message(self._socket, resp)
        self.ui.display_system_message("Deaddrop handshake complete")
        if self._deaddrop_handshake_event is not None:
            self._deaddrop_handshake_event.set()
    
    def _encrypt_deaddrop_inner(self, inner: bytes) -> dict[str, Any]:
        """Encrypt *inner* with ChaCha20-Poly1305 using the deaddrop shared secret.

        Returns a dict ready to be JSON-serialised and sent as a DEADDROP_MESSAGE frame.
        """
        if not self._deaddrop_shared_secret:
            raise ValueError("Deaddrop shared secret not established")
        nonce = os.urandom(NONCE_SIZE)
        aad = {
            "type":  MessageType.DEADDROP_MESSAGE,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
        }
        aad_raw = json.dumps(aad).encode("utf-8")
        aead = ChaCha20Poly1305(self._deaddrop_shared_secret)
        ciphertext = aead.encrypt(nonce, inner, aad_raw)
        return {
            "type":       MessageType.DEADDROP_MESSAGE,
            "nonce":      base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
    
    def _encrypt_deaddrop_chunk(self, chunk: bytes, nonce: bytes) -> bytes:
        """Encrypt a raw binary deaddrop chunk and prepend the magic number and nonce for framing."""
        if not self._deaddrop_shared_secret:
            raise ValueError("Deaddrop shared secret not established")
        aead = ChaCha20Poly1305(self._deaddrop_shared_secret)
        ciphertext = aead.encrypt(nonce, chunk, nonce)
        return constants.MAGIC_NUMBER_DEADDROPS + nonce + ciphertext
    
    def _handle_deaddrop_encrypted_message(self, outer: dict[str, Any]) -> None:
        """Decrypt and dispatch an incoming DEADDROP_MESSAGE frame from the server.

        Handles all inner message types: check responses, accept/deny, password-proof
        challenges, streaming data chunks, and completion signals.
        """
        if not self._deaddrop_shared_secret:
            self.ui.display_error_message("Received deaddrop message before handshake was complete")
            return
        
        try:
            nonce_b64 = str(outer["nonce"])
            ct_b64 = str(outer["ciphertext"])
            nonce = base64.b64decode(nonce_b64, validate=True)
            ciphertext = base64.b64decode(ct_b64, validate=True)
        except KeyError:
            self.ui.display_error_message("Malformed deaddrop message from server")
            return
        except binascii.Error:
            self.ui.display_error_message("Invalid base64 in deaddrop message from server")
            return
        
        aad_raw = json.dumps({
            "type":  MessageType.DEADDROP_MESSAGE,
            "nonce": nonce_b64,
        },
        ).encode("utf-8")
        
        try:
            aead = ChaCha20Poly1305(self._deaddrop_shared_secret)
            inner_bytes = aead.decrypt(nonce, ciphertext, aad_raw)
            inner = json.loads(inner_bytes.decode("utf-8"))
        except Exception:
            self.ui.display_error_message("Failed to decrypt deaddrop message from server")
            return
        
        inner_type = MessageType(int(inner.get("type", MessageType.NONE)))
        if inner_type == MessageType.DEADDROP_CHECK_RESPONSE:
            exists = bool(inner.get("exists", False))
            name = self._deaddrop_name or inner.get("name", "")
            self.ui.on_deaddrop_check_result(name, exists)
            if exists:
                self.ui.display_system_message(f"Deaddrop '{name}' exists on server.")
            else:
                self.ui.display_error_message(f"Deaddrop '{name}' does not exist on server.")
        elif inner_type == MessageType.DEADDROP_ACCEPT:
            self._deaddrop_in_progress = True
            if self._deaddrop_download_in_progress:
                self._deaddrop_download_expected_hash = str(inner.get("file_hash", ""))
                file_key_salt_b64 = inner.get("file_key_salt")
                if isinstance(file_key_salt_b64, str):
                    try:
                        hkdf_salt = base64.b64decode(file_key_salt_b64, validate=True)
                    except binascii.Error:
                        hkdf_salt = None
                else:
                    hkdf_salt = None
                if hkdf_salt and self._deaddrop_download_key is not None:
                    # Re-derive the key with the salt from the server metadata
                    self._deaddrop_download_key = self._derive_deaddrop_file_key(
                            self._deaddrop_dl_password, hkdf_salt)
                self.ui.display_system_message("Deaddrop download accepted by server; confirming and waiting for data...")
                confirm_inner = {"type": MessageType.DEADDROP_ACCEPT}
                confirm_outer = self._encrypt_deaddrop_inner(json.dumps(confirm_inner).encode("utf-8"))
                encode_send_message(self._socket, confirm_outer)
            else:
                self.ui.display_system_message("Deaddrop upload accepted by server")
        elif inner_type == MessageType.DEADDROP_DENY:
            reason = inner.get("reason", "Deaddrop request denied")
            self.ui.display_error_message(reason)
            self._deaddrop_in_progress = False
            self._deaddrop_download_in_progress = False
        elif inner_type == MessageType.DEADDROP_REDOWNLOAD:
            pass
        elif inner_type == MessageType.DEADDROP_PROVE:
            salt_b64 = inner.get("salt")
            if not isinstance(salt_b64, str):
                self.ui.display_error_message("Invalid deaddrop prove message from server")
                return
            try:
                download_salt = base64.b64decode(salt_b64, validate=True)
            except binascii.Error:
                self.ui.display_error_message("Invalid base64 salt in deaddrop prove message")
                return
            
            if not self._deaddrop_password_hash:
                self.ui.display_error_message("No stored deaddrop password hash for download")
                return
            
            pbk = PBKDF2HMAC(
                    algorithm=hashes.SHA3_512(),
                    length=DEADDROP_KDF_KEY_LENGTH,
                    salt=download_salt,
                    iterations=DEADDROP_PBKDF2_ITERATIONS,
            )
            og_hash_bytes = self._deaddrop_password_hash.encode("utf-8")
            client_hash = pbk.derive(og_hash_bytes)
            inner_msg = {
                "type": MessageType.DEADDROP_PROVE,
                "hash": base64.b64encode(client_hash).decode("utf-8"),
            }
            outer_msg = self._encrypt_deaddrop_inner(json.dumps(inner_msg).encode("utf-8"))
            encode_send_message(self._socket, outer_msg)
        elif inner_type == MessageType.DEADDROP_DATA:
            if not self._deaddrop_download_in_progress:
                return
            try:
                chunk_index = int(inner["chunk_index"])
                ct_b64_data = str(inner["ct"])
                chunk_data = base64.b64decode(ct_b64_data, validate=True)
            except (KeyError, ValueError, TypeError, binascii.Error):
                self.ui.display_error_message("Malformed deaddrop data from server")
                return
            self._process_deaddrop_data_streaming(chunk_index, chunk_data)
        elif inner_type == MessageType.DEADDROP_COMPLETE:
            if self._deaddrop_download_in_progress:
                self._finalise_deaddrop_download()
            else:
                self.ui.display_system_message("Deaddrop upload completed successfully")
            self._deaddrop_in_progress = False
            self._deaddrop_download_in_progress = False
    
    def _derive_deaddrop_file_key(self, password: str, hkdf_salt: bytes | None = None) -> bytes:
        salt = hashlib.sha3_512(
                b"deaddrop-file-key-v1:" + self.server_identifier.encode("utf-8"),
        ).digest()
        
        argon = Argon2id(
                salt=salt,
                memory_cost=1024 * 1024 * 4,
                iterations=4,
                lanes=4,
                length=DOUBLE_KEY_SIZE,
        )
        stretched = argon.derive(password.encode("utf-8"))
        
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=DOUBLE_KEY_SIZE,
                salt=hkdf_salt,
                info=b"deaddrop-file-encryption-key-v1",
        )
        return hkdf.derive(stretched)
    
    def _hash_deaddrop_password(self, password: str) -> str:
        """Derive a slow Argon2id hash of the deaddrop password for server-side authentication.

        Uses the server identifier as the salt. This is intentionally expensive and may
        briefly block the UI thread.
        """
        self.ui.display_system_message("Hashing deaddrop password, program may be unresponsive.")
        time.sleep(0.2)
        salt = self.server_identifier.encode("utf-8") if self.server_identifier else b"deaddrop_pass_default_salt_v1"
        hasher = Argon2id(
                salt=salt,
                memory_cost=1024 * 1024 * 2,  # memory_cost must be given in KiB, so 2 GiB
                iterations=6,
                lanes=4,
                length=DOUBLE_KEY_SIZE,
        )
        return base64.b64encode(hasher.derive(password.encode("utf-8"))).decode("utf-8")
    
    def _finalise_deaddrop_download(self) -> None:
        """Close the partial download file, rename it to its final name, and verify its HMAC."""
        self._deaddrop_dl_expected_index = 0
        self._deaddrop_dl_encryptor = None
        self._deaddrop_dl_next_nonce = None
        if self._deaddrop_dl_file:
            try:
                self._deaddrop_dl_file.close()
            except Exception:
                pass
            finally:
                self._deaddrop_dl_file = None
        
        if not self._deaddrop_dl_part_path:
            self.ui.display_error_message("No deaddrop partial file to finalise")
            return
        
        part_path = self._deaddrop_dl_part_path
        final_path = part_path[:-5] if part_path.lower().endswith(".part") else part_path
        try:
            os.replace(part_path, final_path)
        except Exception as exc:
            self.ui.display_error_message(f"Failed to finalise deaddrop file: {exc}")
            return
        
        expected_b64 = self._deaddrop_download_expected_hash or ""
        key = self._deaddrop_download_key
        if not expected_b64:
            self.ui.display_system_message("Deaddrop: no expected HMAC provided by server; skipped verification.")
            return
        elif key is None:
            self.ui.display_error_message("Deaddrop: missing key for HMAC verification; file kept as-is.")
            return
        
        if isinstance(expected_b64, str) and expected_b64.startswith("b'") and expected_b64.endswith("'"):
            expected_b64 = expected_b64[2:-1]
        try:
            expected_hmac = base64.b64decode(expected_b64, validate=True)
        except binascii.Error:
            self.ui.display_error_message("Deaddrop: invalid base64 expected HMAC provided by server; file kept as-is.")
            return
        
        h = HMAC(key, hashes.SHA3_512())
        with open(final_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        computed_hmac = h.finalize()
        
        if bytes_eq(computed_hmac, expected_hmac):
            self.ui.display_system_message("Deaddrop file integrity verified (HMAC OK).")
        else:
            self.ui.display_error_message("Deaddrop file HMAC verification failed, file will be kept as-is."
                                          f"Computed HMAC: {base64.b64encode(computed_hmac).decode('utf-8')},"
                                          f"Expected HMAC: {base64.b64encode(expected_hmac).decode('utf-8')}",
                                          )
        
        self.ui.on_deaddrop_download_complete(self._deaddrop_name, final_path)
        self.ui.display_system_message(f"Deaddrop download complete, saved to: {final_path}")
        self._deaddrop_dl_part_path = None
    
    def _handle_deaddrop_binary_chunk(self, message_data: bytes) -> None:
        """Decrypt a raw binary deaddrop chunk frame and forward it to the streaming processor."""
        if not self._deaddrop_download_in_progress or self._deaddrop_shared_secret is None:
            return
        aead = ChaCha20Poly1305(self._deaddrop_shared_secret)
        nonce = message_data[DEADDROP_NONCE_OFFSET:DEADDROP_CIPHERTEXT_OFFSET]
        ct = message_data[DEADDROP_CIPHERTEXT_OFFSET:]
        try:
            decrypted = aead.decrypt(nonce, ct, nonce)
        except InvalidTag:
            raise ValueError("Deaddrop chunk decryption failed")
        self._process_deaddrop_data_streaming(
                int.from_bytes(decrypted[:DEADDROP_LENGTH_PREFIX_SIZE], "big"),
                decrypted[DEADDROP_LENGTH_PREFIX_SIZE:],
        )
    
    def _process_deaddrop_data_streaming(self, chunk_index: int, chunk_data: bytes) -> None:
        """Decrypt and stream-write a single deaddrop download chunk to the partial output file.
        
        The first chunk carries a 12-byte header (file extension padded to 12 bytes).
        Each chunk's nonce is derived from the key and chunk index.
        Chunks must arrive in order; out-of-order chunks are dropped with an error.
        """
        if chunk_index != self._deaddrop_dl_expected_index:
            self.ui.display_error_message(
                    f"Unexpected deaddrop chunk index {chunk_index}, expected {self._deaddrop_dl_expected_index}",
            )
            return
        
        if (chunk_index + 1) % 100 == 0:
            size_so_far = utils.bytes_to_human_readable(self._deaddrop_dl_bytes_downloaded)
            self.ui.display_system_message(f"Received {size_so_far} so far")
        
        if self._deaddrop_download_key is None:
            self.ui.display_error_message("Deaddrop key not initialised")
            return
        
        if self._deaddrop_dl_encryptor is None:
            self._deaddrop_dl_encryptor = ChunkIndependentDoubleEncryptor(self._deaddrop_download_key)
        
        try:
            nonce = hashlib.sha3_256(self._deaddrop_download_key + chunk_index.to_bytes(4, byteorder='little')).digest()[:CTR_NONCE_SIZE]
            if chunk_index == 0:
                pt = self._deaddrop_dl_encryptor.decrypt(nonce, chunk_data)
                if len(pt) < DEADDROP_FILE_EXT_HEADER_SIZE:
                    self.ui.display_error_message("First deaddrop chunk too small to contain header")
                    return
                ext_header = pt[:DEADDROP_FILE_EXT_HEADER_SIZE]
                body = pt[DEADDROP_FILE_EXT_HEADER_SIZE:]
                self._deaddrop_dl_bytes_downloaded += len(body)
                
                file_ext = ext_header.rstrip(b"\x00").decode("utf-8", errors="ignore")
                file_ext = "".join(c for c in file_ext if c.isalnum() or c in ".-_") or ".bin"
                safe_name = "".join(c for c in self._deaddrop_name if c.isalnum() or c in ("-", "_")) or "deaddrop"
                if file_ext:
                    final_name = safe_name + (file_ext if file_ext.startswith(".") else ("." + file_ext))
                else:
                    final_name = safe_name
                part_path = final_name + ".part"
                
                try:
                    f = open(part_path, "wb")
                except Exception as exc:
                    self.ui.display_error_message(f"Failed to open deaddrop output file: {exc}")
                    return
                self._deaddrop_dl_file = f
                self._deaddrop_dl_part_path = part_path
                
                if body:
                    try:
                        f.write(body)
                    except Exception as exc:
                        self.ui.display_error_message(f"Failed to write to deaddrop file: {exc}")
                        try:
                            f.close()
                        except Exception:
                            pass
                        self._deaddrop_dl_file = None
                        try:
                            os.remove(part_path)
                        except Exception:
                            pass
                        return
            else:
                if not self._deaddrop_dl_file:
                    self.ui.display_error_message("Deaddrop output file not open")
                    return
                pt = self._deaddrop_dl_encryptor.decrypt(nonce, chunk_data)
                self._deaddrop_dl_bytes_downloaded += len(pt)
                try:
                    self._deaddrop_dl_file.write(pt)
                except Exception as exc:
                    self.ui.display_error_message(f"Failed to write to deaddrop file: {exc}")
                    return
        except Exception as exc:
            self.ui.display_error_message(f"Failed to process deaddrop chunk: {exc}")
            return
        finally:
            if chunk_index == self._deaddrop_dl_expected_index:
                self._deaddrop_dl_expected_index += 1
