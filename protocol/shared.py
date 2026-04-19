# shared.py - Shared cryptographic utilities and protocol definitions
# pylint: disable=trailing-whitespace, line-too-long
import base64
import binascii
import enum
import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time
from collections import deque
from typing import Any, TYPE_CHECKING

from SecureChatABCs.protocol_base import ProtocolBase
from protocol.file_handler import ProtocolFileHandler
from config import ClientConfigHandler
from utils.network_utils import send_message
from protocol.crypto_classes import DoubleEncryptor, KeyExchangeDoubleEncryptor
from protocol.constants import (
    DEFAULT_MAX_RATCHET_FORWARD, MessageType,
    MAGIC_NUMBER_FILE_TRANSFER,
    NONCE_SIZE,
    CLIENT_RANDOM_SIZE,
    HKDF_KEY_LENGTH,
    HEADER_LENGTH_SIZE,
    FILE_CHUNK_COUNTER_OFFSET,
    FILE_CHUNK_NONCE_OFFSET,
    FILE_CHUNK_EPH_PUB_OFFSET,
    FILE_CHUNK_CIPHERTEXT_OFFSET,
)
from protocol.utils import (
    LRUCache,
    generate_key_fingerprint,
)
from protocol.create_messages import (
    create_key_verification_message,
    create_ke_dsa_random,
    create_ke_mlkem_pubkey,
    create_ke_mlkem_ct_keys,
    create_ke_x25519_hqc_ct,
    create_ke_verification,
)
from protocol.parse_messages import (
    process_key_verification_message,
    parse_ke_dsa_random,
    parse_ke_mlkem_pubkey,
    parse_ke_mlkem_ct_keys,
    parse_ke_x25519_hqc_ct,
    parse_ke_verification,
)

try:
    import pqcrypto  # type: ignore[import-untyped]
    import cryptography
except ImportError as _exc:
    print("Required cryptographic libraries not found.")
    raise ImportError("Please install the required libraries with pip install -r requirements.txt")

from pqcrypto.kem import ml_kem_1024, hqc_256  # type: ignore # Still not production ready, but better than before
from pqcrypto.sign import ml_dsa_87  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC

from cryptography.hazmat.primitives.constant_time import bytes_eq

from cryptography.exceptions import InvalidTag

if TYPE_CHECKING:
    from SecureChatABCs.client_base import ClientBase


class _QueueKind(enum.Enum):
    """Discriminant for items stored in the protocol send queue."""
    ENCRYPT_TEXT = "encrypt_text"
    ENCRYPT_JSON = "encrypt_json"
    ENCRYPT_JSON_THEN_SWITCH = "encrypt_json_then_switch"


class SecureChatProtocol(ProtocolBase):
    """
    Concrete implementation of the secure chat protocol.

    Implements a post-quantum hybrid key exchange (ML-KEM-1024 + X25519 + HQC-256) combined
    with double-layer authenticated encryption (AES-GCM + ChaCha20Poly1305), a symmetric
    Double Ratchet for perfect forward secrecy, automatic rekeying, replay protection via
    message counters, and file-transfer support.

    Inherits from :class:`ProtocolBase` and satisfies its full abstract interface.
    """
    client: "ClientBase | None" = None
    
    def __init__(self, client: "ClientBase | None" = None, file_handler: ProtocolFileHandler | None = None) -> None:
        """
        Initialise the secure chat protocol with the default cryptographic state.

        Sets up all necessary state variables for the ML-KEM-1024 + X25519 + HQC-256 key
        exchange, double-encrypted AES-GCM + ChaCha20Poly1305 messaging, a symmetric Double
        Ratchet for perfect forward secrecy, replay protection, automatic rekeying, and file
        transfer functionality.

        Attributes are grouped below by their role.  "Guaranteed" attributes always hold a
        valid, usable value after ``__init__``.  "Unsafe" attributes default to a
        zero/empty/``None`` sentinel and are only valid after the corresponding protocol
        phase has completed.  Private attributes (prefixed ``_``) are listed for
        documentation completeness but should not be accessed directly by callers.

        Args:
            client (ClientBase | None): The client instance this protocol reports events and
                errors to.  May be ``None`` when the protocol is used standalone.
            file_handler (ProtocolFileHandler | None): Delegate for all file-transfer I/O.
                When ``None``, file-transfer operations are unavailable.

        Guaranteed Public Attributes:
            config (ClientConfigHandler): The configuration handler instance.
            message_counter (int): Outgoing message counter for the current session.
            peer_counter (int): Last confirmed incoming message counter.
            ke_step (int): Tracks which step of the multi-step key exchange is in progress.
            messages_since_last_rekey (int): Number of messages sent/received since the last rekey.
            rekey_interval (int): Randomised message threshold that triggers an automatic rekey.
            skipped_counters (LRUCache): Cache of out-of-order Double Ratchet chain states,
                keyed by counter value; capacity 1 000 entries.
            shared_key (bool): ``False`` until a session shared secret has been established.
            mlkem_public_key (bytes): Own ML-KEM-1024 public key; empty until key exchange.
            hqc_public_key (bytes): Own HQC-256 public key; empty until key exchange.
            peer_mlkem_public_key (bytes): Peer's ML-KEM-1024 public key; empty until key exchange.
            peer_hqc_public_key (bytes): Peer's HQC-256 public key; empty until key exchange.
            dh_public_key_bytes (bytes): Raw bytes of the own session-setup X25519 public key.
            peer_dh_public_key_bytes (bytes): Raw bytes of the peer's session-setup X25519 public key.
            msg_peer_base_public (bytes): Peer's last known Double Ratchet X25519 public key.
            pending_message_counter (int): Outgoing counter value staged for the next rekey activation.
            pending_peer_counter (int): Incoming counter value staged for the next rekey activation.
        Guaranteed Private Attributes:
            _file_handler (ProtocolFileHandler | None): File-transfer delegate; ``None`` when unused.
            _message_queue (deque): Queue of outgoing items pending encryption and dispatch.
            _socket (socket.socket | None): Active transport socket; ``None`` when not connected.
            _sender_thread (threading.Thread | None): Background sender thread; ``None`` when stopped.
            _sender_running (bool): Whether the background sender thread is active.
            _sender_lock (threading.Lock): Mutex protecting access to ``_message_queue``.
            _send_dummy_messages (bool): Whether traffic-analysis padding messages are enabled.

        Unsafe Private Attributes (valid only after the relevant protocol phase):
            _verification_key (bytes): HMAC key derived during key exchange; empty until then.
            _otp_material (bytes): One-time-pad material derived during key exchange.
            _hqc_secret (bytes): HQC-256 shared secret; empty until key exchange.
            _send_chain_key (bytes): Current symmetric ratchet key for outgoing messages.
            _receive_chain_key (bytes): Current symmetric ratchet key for incoming messages.
            _mlkem_private_key (bytes): Own ML-KEM-1024 private key; empty until key exchange.
            _hqc_private_key (bytes): Own HQC-256 private key; empty until key exchange.
            _mldsa_public_key (bytes): Ephemeral ML-DSA-87 public key; discarded after key exchange.
            _mldsa_private_key (bytes): Ephemeral ML-DSA-87 private key; discarded after key exchange.
            _ke_client_random (bytes): Own client random contributed to the key exchange.
            _peer_client_random (bytes): Peer's client random received during key exchange.
            _combined_random (bytes): XOR of both client randoms used in key derivation.
            _peer_mldsa_public_key (bytes): Peer's ML-DSA-87 public key; empty until key exchange.
            _ke_mlkem_shared_secret (bytes): Intermediate ML-KEM shared secret from key exchange.
            _ke_intermediary_key_1 (bytes): First intermediary key derived during key exchange.
            _server_identifier (str): Server identifier string used in key derivations.
            _dh_private_key (X25519PrivateKey | None): Ephemeral X25519 private key for session setup.
            _msg_recv_private (X25519PrivateKey | None): X25519 private key used in the Double Ratchet.
            _rekey_in_progress (bool): Whether a rekey exchange is currently in flight.
            _pending_send_chain_key (bytes): Send chain key staged for the next rekey activation.
            _pending_receive_chain_key (bytes): Receive chain key staged for the next rekey activation.
            _pending_otp_material (bytes): OTP material staged for the next rekey activation.
            _pending_verification_key (bytes): Verification key staged for the next rekey activation.
            _pending_key_verification_material (bytes): Fingerprint material staged for the next rekey activation.
            _pending_msg_recv_private (X25519PrivateKey | None): DH private key for post-rekey ratchet.
            _pending_msg_peer_base_public (bytes): Peer DH public key for post-rekey ratchet.
            _pending_peer_dh_public_key_bytes (bytes): Peer DH public key bytes staged for activation.
        """
        self.client: "ClientBase | None" = client
        self._file_handler: ProtocolFileHandler | None = file_handler
        
        # Configuration + protocol
        self.config: ClientConfigHandler = ClientConfigHandler()
        
        # Transport + queuing
        self._message_queue: deque[tuple[_QueueKind, str | dict[str, Any]]] = deque()
        self._socket: socket.socket | None = None
        self._sender_thread: threading.Thread | None = None
        self._sender_running: bool = False
        self._sender_lock: threading.Lock = threading.Lock()
        self._send_dummy_messages: bool = self.config["send_dummy_packets"]
        
        # Cryptographic identity + peer info
        self.mlkem_public_key: bytes = b""
        self._mlkem_private_key: bytes = b""
        self.hqc_public_key: bytes = b""
        self._hqc_private_key: bytes = b""
        
        self.peer_mlkem_public_key: bytes = b""
        self.peer_hqc_public_key: bytes = b""
        
        # ML-DSA signing keys (ephemeral, discarded after key exchange)
        self._mldsa_public_key: bytes = b""
        self._mldsa_private_key: bytes = b""
        
        # Key exchange intermediate state
        self._ke_client_random: bytes = b""
        self._peer_client_random: bytes = b""
        self._combined_random: bytes = b""
        self._peer_mldsa_public_key: bytes = b""
        self._ke_mlkem_shared_secret: bytes = b""
        self._ke_intermediary_key_1: bytes = b""
        self.ke_step: int = 0  # tracks which step of the multi-step KE we're on
        self._server_identifier: str = ""
        
        # Session keys
        self.shared_key: bool = False
        self._verification_key: bytes = b""
        self._otp_material: bytes = b""
        self._hqc_secret: bytes = b""
        
        # Ratchet state (symmetric)
        self.message_counter: int = 0
        self.peer_counter: int = 0
        self._send_chain_key: bytes = b""
        self._receive_chain_key: bytes = b""
        
        # X25519 ephemeral DH (session setup)
        self._dh_private_key: X25519PrivateKey | None = None
        self.dh_public_key_bytes: bytes = b""
        self.peer_dh_public_key_bytes: bytes = b""
        
        # Message-phase Double Ratchet
        self._msg_recv_private: X25519PrivateKey | None = None
        self.msg_peer_base_public: bytes = b""
        self.skipped_counters: LRUCache = LRUCache(1000)
        
        # Rekey state
        self._rekey_in_progress: bool = False
        self._pending_send_chain_key: bytes = b""
        self._pending_receive_chain_key: bytes = b""
        self._pending_otp_material: bytes = b""
        self._pending_verification_key: bytes = b""
        self._pending_key_verification_material: bytes = b""
        self._pending_msg_recv_private: X25519PrivateKey | None = None
        self._pending_msg_peer_base_public: bytes = b""
        self._pending_peer_dh_public_key_bytes: bytes = b""
        self.pending_message_counter: int = 0
        self.pending_peer_counter: int = 0
        # Rekey KE protocol state
        self._rke_step: int = 0  # 0=off, 1=I am A (initiator), 2=I am B (responder)
        self._rke_client_random: bytes = b""
        self._rke_peer_client_random: bytes = b""
        self._rke_combined_random: bytes = b""
        self._rke_mldsa_pub: bytes = b""
        self._rke_mldsa_priv: bytes = b""
        self._rke_peer_mldsa_pub: bytes = b""
        self._rke_mlkem_shared_secret: bytes = b""  # B stores mlkem secret between steps
        # A-side KE state
        self._rke_mlkem_priv: bytes = b""
        self._rke_dh_priv: X25519PrivateKey | None = None
        self._rke_dh_pub_bytes: bytes = b""
        self._rke_peer_hqc_pub: bytes = b""
        # B-side KE state
        self._rke_peer_mlkem_pub: bytes = b""
        self._rke_hqc_pub: bytes = b""
        self._rke_hqc_priv: bytes = b""
        self._rke_b_dh_priv: X25519PrivateKey | None = None
        self._rke_b_dh_pub_bytes: bytes = b""
        # Shared intermediary state
        self._rke_intermediary_key_1: bytes = b""
        
        # Automatic rekey tracking
        self.messages_since_last_rekey: int = 0
        # Randomise the rekey interval by ±10% of the base value
        base_interval = self.config["rekey_interval"]
        variation = round(base_interval * 0.1)
        self.rekey_interval: int = base_interval + (secrets.randbelow(variation + 1) - variation)
    
    @property
    def has_active_file_transfers(self) -> bool:
        # Set in __init__ of the file handler.
        if self._file_handler is None:
            return False
        return self._file_handler.has_active_file_transfers
    
    def reset_auto_rekey_counter(self) -> None:
        self.messages_since_last_rekey = 1
    
    @property
    def rekey_in_progress(self) -> bool:
        return self._rekey_in_progress
    
    @property
    def encryption_ready(self) -> bool:
        """Check if encryption is ready (shared key and chain keys established)."""
        return bool(self.shared_key and self._send_chain_key and self._receive_chain_key)
    
    @property
    def should_auto_rekey(self) -> bool:
        """Check if automatic rekey should be initiated based on message count."""
        return (self.messages_since_last_rekey >= self.rekey_interval and
                not self._rekey_in_progress and
                self.encryption_ready)
    
    @property
    def send_dummy_messages(self) -> bool:
        """Check if dummy messages should be sent."""
        return self._send_dummy_messages and not self._rekey_in_progress and not self.has_active_file_transfers
    
    @send_dummy_messages.setter
    def send_dummy_messages(self, value: bool) -> None:
        """Set whether the client wants dummy messages to be sent."""
        self._send_dummy_messages = value
    
    def reset_key_exchange(self) -> None:
        """
        Reset all cryptographic state to initial values for key exchange restart.
        
        These values will be rewritten quickly, so it's not necessary to zero them manually.
        Even that likely wouldn't actually clear the data from RAM
        """
        self.stop_sender_thread()
        
        self.shared_key = False
        self.message_counter = 0
        self.peer_counter = 0
        self.peer_mlkem_public_key = b""
        self.mlkem_public_key = b""
        self._hqc_secret = b""
        self._send_chain_key = b""
        self._receive_chain_key = b""
        # Reset DH ephemeral keys
        self._dh_private_key = None
        self.dh_public_key_bytes = b""
        self.peer_dh_public_key_bytes = b""
        # Reset message-phase Double Ratchet state
        self._msg_recv_private = None
        self.msg_peer_base_public = b""
        # Discard ML-DSA signing keys
        self._discard_mldsa_keys()
        # Clear KE intermediate state
        self._ke_client_random = b""
        self._peer_client_random = b""
        self._combined_random = b""
        self._peer_mldsa_public_key = b""
        self._ke_mlkem_shared_secret = b""
        self._ke_intermediary_key_1 = b""
        self.ke_step = 0
        
        # Clear message queue
        with self._sender_lock:
            self._message_queue.clear()
    
    def start_sender_thread(self, sock: socket.socket) -> None:
        """Start the background sender thread for message queuing."""
        if self._sender_thread is not None and self._sender_thread.is_alive():
            return  # Thread already running
        
        self._socket = sock
        self._sender_running = True
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()
    
    def stop_sender_thread(self) -> None:
        """Stop the background sender thread."""
        self._sender_running = False
        if self._sender_thread is not None and self._sender_thread.is_alive():
            self._sender_thread.join(timeout=1.0)
        self._sender_thread = None
        self._socket = None
    
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
    
    def send_emergency_close(self) -> bool:
        """
        Send an emergency close message immediately, bypassing the queue.
        
        Behavior:
            - If encryption is ready, encrypt immediately and send over the socket.
            - If encryption is not ready, send plaintext immediately.
        
        Returns:
            bool: True if the message was sent successfully, False otherwise.
        """
        if not self._socket:
            return False
        emergency_message = {"type": MessageType.EMERGENCY_CLOSE}
        if self.shared_key and self._send_chain_key:
            # Encrypt immediately using normal ratcheting
            encrypted = self.encrypt_message(json.dumps(emergency_message))
            send_message(self._socket, encrypted)
        
        else:
            # Fall back to plaintext immediate send
            send_message(self._socket, json.dumps(emergency_message).encode('utf-8'))
        
        return True
    
    def _generate_dummy_message(self) -> bytes:
        """Generate a dummy message with random data."""
        dummy_data = os.urandom(self.config["max_dummy_packet_size"])
        
        dummy_message = {
            "type": MessageType.DUMMY_MESSAGE,
            "data": base64.b64encode(dummy_data).decode('utf-8'),
        }
        return self.encrypt_message(json.dumps(dummy_message))
    
    def _sender_loop(self) -> None:
        """Background thread loop that sends messages every 250 ms.
        
        Dequeues one item per tick, encrypts it, and sends it over the socket.
        When the queue is empty and dummy-message sending is enabled, a random
        dummy packet is sent instead to obscure traffic patterns.
        """
        while self._sender_running:
            item = self._get_next_item()
            to_send, switch_keys_after = self._prepare_item_for_sending(item)
            
            if to_send is not None and self._socket is not None:
                self._send_prepared_item(to_send, switch_keys_after)
            
            time.sleep(0.25)
    
    def _get_next_item(self) -> tuple["_QueueKind", Any] | bytes | None:
        """Get the next item from the queue or generate a dummy message."""
        with self._sender_lock:
            if self._message_queue:
                return self._message_queue.popleft()
        
        # Generate dummy message if appropriate
        if self.send_dummy_messages and self.encryption_ready and self.config["send_dummy_packets"]:
            return self._generate_dummy_message()
        
        return None
    
    def _prepare_item_for_sending(self, item: tuple["_QueueKind", Any] | bytes | None) -> tuple[bytes | None, bool]:
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
            
            raise ValueError(f"Unsupported queue kind: {kind}")
        
        except (ValueError, TypeError) as e:
            self._report_error(f"Message preparation error (dropped): {e}")
            return None, False
        except Exception as e:
            self._report_error(f"Unexpected error preparing message (dropped): {e}")
            return None, False
    
    def _encrypt_text_message(self, text: str) -> bytes:
        """Encrypt a text message."""
        if not isinstance(text, str) or not (self.shared_key and self._send_chain_key):
            raise ValueError("Invalid text encryption request or keys not ready")
        
        inner_obj = {"type": MessageType.TEXT_MESSAGE, "text": text}
        return self.encrypt_message(json.dumps(inner_obj))
    
    def _encrypt_json_message(self, obj: dict) -> bytes:
        """Encrypt a JSON message."""
        if not isinstance(obj, dict) or not (self.shared_key and self._send_chain_key):
            raise ValueError("Invalid JSON encryption request or keys not ready")
        
        return self.encrypt_message(json.dumps(obj))
    
    def _send_prepared_item(self, to_send: bytes, switch_keys_after: bool) -> None:
        """Send prepared bytes and activate pending keys afterwards if requested."""
        assert self._socket is not None
        result = send_message(self._socket, to_send)
        if result is not None:
            self._report_error(f"Failed to send message: {result}")
        
        if switch_keys_after:
            self.activate_pending_keys()
    
    def _report_error(self, message: str) -> None:
        """Report an error to the client, or fall back to print if no client is set."""
        if self.client is not None:
            self.client.on_error(message)
        else:
            print(message)
    
    def _generate_dsa_keys(self) -> None:
        """Generate ML-DSA keypair for key exchange signing."""
        self._mldsa_public_key, self._mldsa_private_key = ml_dsa_87.generate_keypair()
    
    def set_server_identifier(self, identifier: str) -> None:
        """Set the server identifier for use in key derivations."""
        self._server_identifier = identifier
    
    def create_ke_dsa_random(self) -> bytes:
        """Create KE_DSA_RANDOM message: send our DSA public key and a client random."""
        self._generate_dsa_keys()
        self._ke_client_random = os.urandom(CLIENT_RANDOM_SIZE)
        # Derive combined random if we already have the peer's random (Client B path)
        if self._ke_client_random and self._peer_client_random:
            self._combined_random = self._derive_combined_random()
        return create_ke_dsa_random(self._mldsa_public_key, self._ke_client_random)
    
    def process_ke_dsa_random(self, data: bytes) -> str:
        """Process peer's KE_DSA_RANDOM message. Store peer DSA pubkey and random.
        Returns version warning string (empty if ok)."""
        parsed = parse_ke_dsa_random(data)
        self._peer_mldsa_public_key = parsed["mldsa_public_key"]
        self._peer_client_random = parsed["client_random"]
        # Derive combined random if we have both randoms (step 5 or 7)
        if self._ke_client_random and self._peer_client_random:
            self._combined_random = self._derive_combined_random()
        return parsed["version_warning"]
    
    def create_ke_mlkem_pubkey(self) -> bytes:
        """Create KE_MLKEM_PUBKEY message (step 8): generate ML-KEM and X25519 keypairs, send signed ML-KEM pubkey.
        X25519 keypair is generated here (step 2) for use in step 12."""
        self.mlkem_public_key, self._mlkem_private_key = ml_kem_1024.generate_keypair()
        self._dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key_bytes = self._dh_private_key.public_key().public_bytes_raw()
        return create_ke_mlkem_pubkey(self.mlkem_public_key, self._mldsa_private_key)
    
    def process_ke_mlkem_pubkey(self, data: bytes) -> None:
        """Process peer's KE_MLKEM_PUBKEY: verify signature and store peer ML-KEM pubkey."""
        parsed = parse_ke_mlkem_pubkey(data)
        mlkem_public_key = parsed["mlkem_public_key"]
        mldsa_signature = parsed["mldsa_signature"]
        
        if not ml_dsa_87.verify(self._peer_mldsa_public_key, mlkem_public_key, mldsa_signature):
            raise ValueError("ML-DSA signature verification failed on KE_MLKEM_PUBKEY")
        
        self.peer_mlkem_public_key = mlkem_public_key
    
    def create_ke_mlkem_ct_keys(self) -> bytes:
        """Create KE_MLKEM_CT_KEYS (step 10): encapsulate ML-KEM, derive intermediary key 1,
        encrypt our HQC and X25519 public keys with it."""
        # Generate HQC and X25519 keypairs
        self.hqc_public_key, self._hqc_private_key = hqc_256.generate_keypair()
        self._dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key_bytes = self._dh_private_key.public_key().public_bytes_raw()
        
        # Encapsulate ML-KEM to get ciphertext and shared secret
        mlkem_ciphertext, mlkem_shared_secret = ml_kem_1024.encrypt(self.peer_mlkem_public_key)
        self._ke_mlkem_shared_secret = mlkem_shared_secret
        
        # Derive intermediary key 1
        intermediary_key_1 = self._derive_intermediary_key_1(mlkem_shared_secret)
        self._ke_intermediary_key_1 = intermediary_key_1
        
        # Encrypt HQC and X25519 public keys with intermediary key 1
        encryptor = KeyExchangeDoubleEncryptor(intermediary_key_1)
        nonce1 = os.urandom(NONCE_SIZE)
        nonce2 = os.urandom(NONCE_SIZE)
        encrypted_hqc_pubkey = encryptor.encrypt(nonce1, self.hqc_public_key)
        encrypted_x25519_pubkey = encryptor.encrypt(nonce2, self.dh_public_key_bytes)
        
        return create_ke_mlkem_ct_keys(
                mlkem_ciphertext, encrypted_hqc_pubkey, encrypted_x25519_pubkey,
                nonce1, nonce2, self._mldsa_private_key,
        )
    
    def process_ke_mlkem_ct_keys(self, data: bytes) -> None:
        """Process peer's KE_MLKEM_CT_KEYS (step 11): decapsulate ML-KEM, derive intermediary key 1,
        decrypt peer's HQC and X25519 public keys. Then perform step 12: DH, HQC encapsulation,
        derive intermediary key 2, and finalize keys."""
        parsed = parse_ke_mlkem_ct_keys(data)
        
        # Verify signature
        if not ml_dsa_87.verify(self._peer_mldsa_public_key, parsed["signed_payload"], parsed["mldsa_signature"]):
            raise ValueError("ML-DSA signature verification failed on KE_MLKEM_CT_KEYS")
        
        # Decapsulate ML-KEM
        mlkem_shared_secret = ml_kem_1024.decrypt(self._mlkem_private_key, parsed["mlkem_ciphertext"])
        self._ke_mlkem_shared_secret = mlkem_shared_secret
        
        # Derive intermediary key 1
        intermediary_key_1 = self._derive_intermediary_key_1(mlkem_shared_secret)
        self._ke_intermediary_key_1 = intermediary_key_1
        
        # Decrypt peer's HQC and X25519 public keys
        decryptor = KeyExchangeDoubleEncryptor(intermediary_key_1)
        self.peer_hqc_public_key = decryptor.decrypt(parsed["nonce1"], parsed["encrypted_hqc_pubkey"])
        self.peer_dh_public_key_bytes = decryptor.decrypt(parsed["nonce2"], parsed["encrypted_x25519_pubkey"])
    
    def create_ke_x25519_hqc_ct(self) -> bytes:
        """Create KE_X25519_HQC_CT (step 12-13): Client A performs DH with peer's X25519 key,
        encapsulates HQC, derives intermediary key 2, encrypts X25519 pubkey with int_key_1
        and HQC ciphertext with int_key_2, then derives final keys."""
        # Perform X25519 DH with peer's public key (from step 10)
        peer_dh_pub = X25519PublicKey.from_public_bytes(self.peer_dh_public_key_bytes)
        dh_shared_secret = self._dh_private_key.exchange(peer_dh_pub)
        
        # Encapsulate HQC
        hqc_ciphertext, self._hqc_secret = hqc_256.encrypt(self.peer_hqc_public_key)
        
        # Derive intermediary key 2 from int_key_1 + X25519 secret
        intermediary_key_2 = self._derive_intermediary_key_2(self._ke_intermediary_key_1, dh_shared_secret)
        
        # Encrypt X25519 pubkey with intermediary key 1
        encryptor_1 = KeyExchangeDoubleEncryptor(self._ke_intermediary_key_1)
        nonce1 = os.urandom(NONCE_SIZE)
        encrypted_x25519_pubkey = encryptor_1.encrypt(nonce1, self.dh_public_key_bytes)
        
        # Encrypt HQC ciphertext with intermediary key 2
        encryptor_2 = KeyExchangeDoubleEncryptor(intermediary_key_2)
        nonce2 = os.urandom(NONCE_SIZE)
        encrypted_hqc_ciphertext = encryptor_2.encrypt(nonce2, hqc_ciphertext)
        
        # Sign before finalizing (finalize discards ML-DSA keys)
        message = create_ke_x25519_hqc_ct(
                encrypted_x25519_pubkey, encrypted_hqc_ciphertext,
                nonce1, nonce2, self._mldsa_private_key,
        )
        
        # Derive final keys (step 12)
        self._finalize_key_exchange(dh_shared_secret)
        
        return message
    
    def process_ke_x25519_hqc_ct(self, data: bytes) -> None:
        """Process peer's KE_X25519_HQC_CT (step 14): decrypt X25519 pubkey with int_key_1,
        perform DH, derive int_key_2, decrypt HQC ciphertext with int_key_2, decapsulate HQC,
        derive final keys."""
        parsed = parse_ke_x25519_hqc_ct(data)
        
        # Verify signature
        if not ml_dsa_87.verify(self._peer_mldsa_public_key, parsed["signed_payload"], parsed["mldsa_signature"]):
            raise ValueError("ML-DSA signature verification failed on KE_X25519_HQC_CT")
        
        # Decrypt peer's X25519 pubkey with intermediary key 1
        decryptor_1 = KeyExchangeDoubleEncryptor(self._ke_intermediary_key_1)
        peer_x25519_pubkey = decryptor_1.decrypt(parsed["nonce1"], parsed["encrypted_x25519_pubkey"])
        self.peer_dh_public_key_bytes = peer_x25519_pubkey
        
        # Perform X25519 DH
        peer_dh_pub = X25519PublicKey.from_public_bytes(peer_x25519_pubkey)
        dh_shared_secret = self._dh_private_key.exchange(peer_dh_pub)
        
        # Derive intermediary key 2
        intermediary_key_2 = self._derive_intermediary_key_2(self._ke_intermediary_key_1, dh_shared_secret)
        
        # Decrypt HQC ciphertext with intermediary key 2
        decryptor_2 = KeyExchangeDoubleEncryptor(intermediary_key_2)
        hqc_ciphertext = decryptor_2.decrypt(parsed["nonce2"], parsed["encrypted_hqc_ciphertext"])
        
        # Decapsulate HQC
        self._hqc_secret = hqc_256.decrypt(self._hqc_private_key, hqc_ciphertext)
        
        # Derive final keys
        self._finalize_key_exchange(dh_shared_secret)
    
    def _finalize_key_exchange(self, dh_shared_secret: bytes) -> None:
        """Derive final keys from all shared secrets per FINAL_KEY_DERIVATION and set up session."""
        server_id = self._server_identifier.encode('utf-8')
        
        # OTP material = SHA-3-512-HKDF(HQC secret, salt=combined_random, info=server_id + 'otp_material')
        otp_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._combined_random,
                info=server_id + b'otp_material',
        )
        self._otp_material = otp_hkdf.derive(self._hqc_secret)
        
        # Own chain key root = SHA-3-512-HKDF(ML-KEM secret + X25519 secret, salt=own_random, info=server_id + 'chain_key_root')
        own_chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._ke_client_random,
                info=server_id + b'chain_key_root',
        )
        own_chain_key_root = own_chain_hkdf.derive(self._ke_mlkem_shared_secret + dh_shared_secret)
        
        # Peer chain key root = same but with peer's random as salt
        peer_chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._peer_client_random,
                info=server_id + b'chain_key_root',
        )
        peer_chain_key_root = peer_chain_hkdf.derive(self._ke_mlkem_shared_secret + dh_shared_secret)
        
        # Set chain keys: own root for sending, peer root for receiving
        self._send_chain_key = own_chain_key_root
        self._receive_chain_key = peer_chain_key_root
        
        sorted_materials = sorted([self._otp_material, own_chain_key_root, peer_chain_key_root])
        verification_hash = hashlib.sha3_512(b''.join(sorted_materials)).digest()
        self._verification_key = verification_hash
        self._key_verification_material = hashlib.sha3_512(b''.join(sorted_materials) + self._combined_random).digest()[:32]
        
        self.shared_key = True
        
        # Initialize message-phase Double Ratchet baseline
        self._msg_recv_private = self._dh_private_key
        self.msg_peer_base_public = self.peer_dh_public_key_bytes
        
        # Discard ML-DSA keys
        self._discard_mldsa_keys()
        # Clean up KE state
        self._ke_mlkem_shared_secret = b""
        self._ke_client_random = b""
        self._peer_client_random = b""
        self._combined_random = b""
        self._peer_mldsa_public_key = b""
        self._ke_intermediary_key_1 = b""
    
    def _discard_mldsa_keys(self) -> None:
        """Discard ephemeral ML-DSA signing keys after key exchange."""
        self._mldsa_public_key = b""
        self._mldsa_private_key = b""
        self._peer_mldsa_public_key = b""
    
    def create_ke_verification(self) -> bytes:
        """Create KE_VERIFICATION message with verification key in signed plaintext."""
        return create_ke_verification(self._key_verification_material)
    
    def process_ke_verification(self, data: bytes) -> bool:
        """Process peer's KE_VERIFICATION and check it matches our derived key.
        Returns True if verification succeeds."""
        parsed = parse_ke_verification(data, local_verification_key=self._key_verification_material)
        return bool(parsed["verification_key"])
    
    def _derive_combined_random(self) -> bytes:
        """Derive combined random from both client randoms using SHA2-512-HKDF.
        combined_random = SHA2-512-HKDF(larger_random, salt=smaller_random, info=server_id + 'comb_rand')"""
        randoms = sorted([self._ke_client_random, self._peer_client_random])
        smaller_random = randoms[0]
        larger_random = randoms[1]
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=smaller_random,
                info=server_id + b'comb_rand',
        )
        return hkdf.derive(larger_random)
    
    def _derive_intermediary_key_1(self, mlkem_shared_secret: bytes) -> bytes:
        """Derive intermediary key 1 from ML-KEM shared secret.
        int_key_1 = SHA-3-512-HKDF(ML-KEM secret, salt=combined_random, info=server_id + 'int_key_1')"""
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._combined_random,
                info=server_id + b'int_key_1',
        )
        return hkdf.derive(mlkem_shared_secret)
    
    def _derive_intermediary_key_2(self, intermediary_key_1: bytes, dh_shared_secret: bytes) -> bytes:
        """Derive intermediary key 2 from intermediary key 1 and X25519 shared secret.
        int_key_2 = SHA-3-512-HKDF(int_key_1, salt=X25519_secret, info=server_id + 'int_key_2')"""
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=dh_shared_secret,
                info=server_id + b'int_key_2',
        )
        return hkdf.derive(intermediary_key_1)
    
    @staticmethod
    def _derive_message_key(chain_key: bytes, counter: int) -> bytes:
        """Derive a message key from the chain key and counter."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"message_key_{counter}".encode(),
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def _ratchet_chain_key(chain_key: bytes, counter: int) -> bytes:
        """Advance the chain key (ratchet forward)."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"chain_key_{counter}".encode("utf-8"),
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def _mix_dh_with_chain(chain_key: bytes, dh_shared: bytes, counter: int) -> bytes:
        """Mix DH shared secret into the chain key using HKDF with the chain key as salt."""
        info = b"dr_mix_" + str(counter).encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=chain_key,
                info=info,
        )
        return hkdf.derive(dh_shared)
    
    def get_own_key_fingerprint(self) -> str:
        """
        Generate a consistent fingerprint for the session that both users will see.
        Uses the verification key derived during key exchange, which is already
        order-independent (derived from sorted key materials).
        """
        if not self._key_verification_material:
            raise ValueError("Verification key not available - key exchange not completed")
        
        return generate_key_fingerprint(self._key_verification_material, self.config["wordlist_file"])
    
    @staticmethod
    def create_key_verification_message(verified: bool) -> bytes:
        """Create a key verification status message."""
        return create_key_verification_message(verified)
    
    @staticmethod
    def process_key_verification_message(data: bytes) -> bool:
        """Process a key verification message from peer."""
        return process_key_verification_message(data)
    
    def encrypt_message(self, plaintext: str | bytes) -> bytes:
        """
        Encrypt a message with authentication and replay protection using perfect forward secrecy.
        Integrates a Double Ratchet step using X25519 by including a fresh sender public key per message
        and mixing the DH shared secret into the chain key derivation.
        
        :param plaintext: The plaintext message to encrypt.
        :return: The encrypted message as bytes, ready to send.
        :raises: ValueError: If no shared key or send chain key is established.
        
        Additional MAC rationale:
            For authentication with AES or Poly1305, the message must be decrypted.
            To decrypt the message we need to derive the key.
            If there is no additional MAC, a bad actor could send a message with a very high counter,
            making the program essentially DoS itself.
            It also makes it possible to differentiate between forged messages and messages
            that have been corrupted or manipulated in flight
        """
        if not self.shared_key or not self._send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        self.message_counter += 1
        self.messages_since_last_rekey += 1
        
        # Generate ephemeral X25519 key for this message and compute DH with peer's static session public key
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
        peer_pub_bytes = self.peer_dh_public_key_bytes
        if not peer_pub_bytes:
            raise ValueError("Missing peer DH public key for encryption")
        dh_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
        
        # Mix DH into current send chain key to get a message-specific chain state
        mixed_chain_key = self._mix_dh_with_chain(self._send_chain_key, dh_shared, self.message_counter)
        
        # Derive unique message key for this message from the mixed chain
        message_key = self._derive_message_key(mixed_chain_key, self.message_counter)
        
        # Ratchet the send chain key forward for the next message (symmetric ratchet only)
        self._send_chain_key = self._ratchet_chain_key(self._send_chain_key, self.message_counter)
        
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        # Create AAD from message metadata for authentication
        nonce = os.urandom(NONCE_SIZE)
        aad_data: dict[str, MessageType | int | str] = {
            "type":          MessageType.ENCRYPTED_MESSAGE,
            "counter":       self.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8'),
        }
        aad: bytes = json.dumps(aad_data).encode('utf-8')
        encryptor = DoubleEncryptor(message_key, self._otp_material, message_counter=self.message_counter)
        # Encrypt with AES-GCM using the unique message key and AAD
        ciphertext = encryptor.encrypt(nonce, plaintext_bytes, aad)
        
        # Create authenticated message including our per-message DH public key
        encrypted_message: dict[str, MessageType | int | str] = {
            "type":          MessageType.ENCRYPTED_MESSAGE,
            "counter":       self.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "ciphertext":    base64.b64encode(ciphertext).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8'),
        }
        
        verif_hasher = HMAC(self._verification_key, hashes.SHA512())
        # Include dh_public_key in verification to authenticate the ratchet key
        verif_hasher.update(json.dumps({
            "counter":       encrypted_message["counter"],
            "nonce":         encrypted_message["nonce"],
            "dh_public_key": encrypted_message["dh_public_key"],
        }).encode('utf-8'))
        
        encrypted_message["verification"] = base64.b64encode(verif_hasher.finalize()).decode('utf-8')
        
        return json.dumps(encrypted_message).encode('utf-8')
    
    def decrypt_message(self, data: bytes) -> str:
        """Decrypt and authenticate a message using perfect forward secrecy with proper state management.
        Incorporates Double Ratchet: mixes DH shared secret (from peer's included X25519 public key and our
        message-phase private key) into the chain before deriving the message key.
        
        Raises value error if message is invalid or verification fails.
        """
        if not self.shared_key or not self._receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        try:
            message: dict[str, Any] = json.loads(data)
            nonce: bytes = base64.b64decode(message["nonce"])
            ciphertext: bytes = base64.b64decode(message["ciphertext"])
            counter: int = message["counter"]
            peer_dh_pub_b64: str = message["dh_public_key"]
            peer_dh_pub_bytes = base64.b64decode(peer_dh_pub_b64, validate=True)
            expected_verification: bytes = base64.b64decode(message["verification"], validate=True)
        except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as e:
            raise ValueError("Message decoding failed, message dropped") from e
        except KeyError as e:
            raise ValueError("Message missing field, message dropped") from e
        
        verif_hasher = HMAC(self._verification_key, hashes.SHA512())
        # Include dh_public_key in verification to authenticate the ratchet key
        verif_hasher.update(json.dumps({
            "counter":       counter,
            "nonce":         message["nonce"],
            "dh_public_key": peer_dh_pub_b64,
        }).encode('utf-8'))
        actual_verification = verif_hasher.finalize()
        if not bytes_eq(expected_verification, actual_verification):
            raise ValueError("Message verification failed, message dropped")
        
        # Determine if we have to use a previously saved ratchet step (out-of-order message)
        use_saved = False
        temp_chain_key: bytes
        new_chain_key: bytes = b""
        if counter <= self.peer_counter:
            # Try to use a saved pre-ratchet chain state for this counter
            saved = self.skipped_counters[counter]
            if saved is None:
                # As per current implementation, raise the same ValueError when not saved
                raise ValueError("Message is probably legitimate but counter has unexpected value: " +
                                 f"higher than {self.peer_counter} got {counter}")
            temp_chain_key = saved
            use_saved = True
        else:
            if counter - (self.peer_counter + 1) > DEFAULT_MAX_RATCHET_FORWARD:
                raise ValueError("Message is probably legitimate but we would have to ratchet " +
                                 "further than the configured maximum to attempt decryption.")
            # We are moving forward; ratchet across gaps and save intermediate steps
            temp_chain_key = self._receive_chain_key
            for i in range(self.peer_counter + 1, counter):
                # Save the pre-ratchet chain state for counter i so we can later decrypt out-of-order
                if self.skipped_counters[i] is None:
                    self.skipped_counters[i] = temp_chain_key
                # Advance to the next chain state
                temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
        
        # Mix DH from peer's message into the temp chain key
        if not self._msg_recv_private:
            raise ValueError("Local DH private key not initialized for message ratchet")
        
        dh_shared = self._msg_recv_private.exchange(X25519PublicKey.from_public_bytes(peer_dh_pub_bytes))
        
        mixed_chain_key = self._mix_dh_with_chain(temp_chain_key, dh_shared, counter)
        
        # Derive the message key for the current message from the mixed chain
        message_key = self._derive_message_key(mixed_chain_key, counter)
        
        # Calculate what the new chain key state WOULD be (symmetric ratchet only)
        if not use_saved:
            new_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
        
        # Create AAD from message metadata for authentication verification
        aad_data = {
            "type":          MessageType.ENCRYPTED_MESSAGE,
            "counter":       counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(peer_dh_pub_bytes).decode('utf-8'),
        }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Decrypt with the derived message key and verify AAD
        decryptor = DoubleEncryptor(message_key, self._otp_material, counter)
        try:
            decrypted_data = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise ValueError("Message is probably legitimate but failed to decrypt, InvalidTag")
        
        try:
            decrypted_data_str = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Message is probably legitimate but failed to decode, UnicodeDecodeError")
        
        # Update ratchet state: only when moving forward. For out-of-order (saved) do not change state.
        if use_saved:
            # Remove saved step after successful decryption
            try:
                self.skipped_counters.pop(counter)
            except KeyError:
                pass
        if not use_saved and new_chain_key:
            self._receive_chain_key = new_chain_key
            self.peer_counter = counter
            # Store peer's latest public key for our next send
            self.msg_peer_base_public = peer_dh_pub_bytes
            # Track message for automatic rekey
            self.messages_since_last_rekey += 1
        
        return decrypted_data_str
    
    def encrypt_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes) -> bytes:
        """
        Encrypt a file chunk using the Double Ratchet, identical in structure to encrypt_message
        but operating on raw binary data rather than JSON text.

        Frame layout: [1-byte magic][COUNTER_SIZE-byte counter][NONCE_SIZE-byte nonce][HALF_KEY_SIZE-byte eph_pub][ciphertext]

        :return: The encrypted frame as bytes, ready to send.
        :raises ValueError: If encryption state is not ready.
        """
        if not self.shared_key or not self._send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        # Bump global message counter (shared with text messages) for unified ratchet state
        self.message_counter += 1
        
        # Generate ephemeral X25519 key for this chunk
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
        peer_pub_bytes = self.peer_dh_public_key_bytes
        if not peer_pub_bytes:
            raise ValueError("Missing peer DH public key for file chunk encryption")
        
        # Compute DH shared secret for this chunk and mix into send chain
        dh_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
        mixed_chain_key = self._mix_dh_with_chain(self._send_chain_key, dh_shared, self.message_counter)
        
        # Derive unique message key for this chunk
        message_key = self._derive_message_key(mixed_chain_key, self.message_counter)
        
        # Ratchet the send chain key forward for the next message
        self._send_chain_key = self._ratchet_chain_key(self._send_chain_key, self.message_counter)
        
        # Create compact header
        header = {
            "type":        MessageType.FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index,
        }
        header_json = json.dumps(header).encode('utf-8')
        
        # Encrypt header and chunk data in one operation
        nonce = os.urandom(NONCE_SIZE)
        
        # Create AAD including eph pub to authenticate ratchet key
        aad_data = {
            "type":          MessageType.FILE_CHUNK,
            "counter":       self.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8'),
        }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Combine header length + header + chunk data for encryption
        header_len = struct.pack('!H', len(header_json))  # 2 bytes for header length
        plaintext = header_len + header_json + chunk_data
        encryptor = DoubleEncryptor(message_key, self._otp_material, self.message_counter)
        ciphertext = encryptor.encrypt(nonce, plaintext, aad)
        
        # Pack: magic (1) + counter (8) + nonce (NONCE_SIZE) + eph_pub (HALF_KEY_SIZE) + ciphertext
        counter_bytes = struct.pack('!Q', self.message_counter)
        return MAGIC_NUMBER_FILE_TRANSFER + counter_bytes + nonce + eph_pub_bytes + ciphertext
    
    def decrypt_file_chunk(self, encrypted_data: bytes) -> dict:
        """
        Decrypt a file chunk frame produced by encrypt_file_chunk.
        Expects frame: [1-byte magic][COUNTER_SIZE-byte counter][NONCE_SIZE-byte nonce][HALF_KEY_SIZE-byte eph_pub][ciphertext].

        :return: dict with keys ``transfer_id``, ``chunk_index``, ``chunk_data``.
        :raises ValueError: If decryption fails or the frame is malformed.
        """
        if not self.shared_key or not self._receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        if len(encrypted_data) < FILE_CHUNK_CIPHERTEXT_OFFSET:
            raise ValueError("Invalid chunk message format")
        
        try:
            counter = int(struct.unpack('!Q', encrypted_data[FILE_CHUNK_COUNTER_OFFSET:FILE_CHUNK_NONCE_OFFSET])[0])
        except struct.error:
            raise ValueError("Invalid chunk message format")
        except ValueError:
            raise ValueError("Invalid counter in chunk message")
        
        nonce = encrypted_data[FILE_CHUNK_NONCE_OFFSET:FILE_CHUNK_EPH_PUB_OFFSET]
        peer_eph_pub = encrypted_data[FILE_CHUNK_EPH_PUB_OFFSET:FILE_CHUNK_CIPHERTEXT_OFFSET]
        ciphertext = encrypted_data[FILE_CHUNK_CIPHERTEXT_OFFSET:]
        
        # Check for replay attacks or very old messages
        if counter <= self.peer_counter:
            raise ValueError("Replay attack or out-of-order message detected. Expected > " +
                             f"{self.peer_counter}, got {counter}")
        
        # Advance the chain key to the correct state for this message (symmetric ratchet)
        temp_chain_key = self._receive_chain_key
        for i in range(self.peer_counter + 1, counter):
            temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
        
        # DH mix: use our receive private key for message-phase ratchet
        if not self._msg_recv_private:
            raise ValueError("Local DH private key not initialized for file chunk ratchet")
        dh_shared = self._msg_recv_private.exchange(X25519PublicKey.from_public_bytes(peer_eph_pub))
        mixed_chain_key = self._mix_dh_with_chain(temp_chain_key, dh_shared, counter)
        
        # Derive the message key for the current message
        message_key = self._derive_message_key(mixed_chain_key, counter)
        
        # Calculate what the new chain key state WOULD be (symmetric ratchet only)
        new_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
        
        # Create AAD including eph pub to authenticate ratchet key
        aad_data = {
            "type":          MessageType.FILE_CHUNK,
            "counter":       counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(peer_eph_pub).decode('utf-8'),
        }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Decrypt the chunk payload with AAD verification
        decryptor = DoubleEncryptor(message_key, self._otp_material, counter)
        try:
            plaintext = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise ValueError("File chunk decryption failed: InvalidTag")
        
        # Parse the decrypted header and extract chunk data
        if len(plaintext) < HEADER_LENGTH_SIZE:
            raise ValueError("Invalid decrypted data: too short")
        
        try:
            header_len = struct.unpack('!H', plaintext[:HEADER_LENGTH_SIZE])[0]
        except struct.error:
            raise ValueError("Invalid decrypted data: header length")
        
        if len(plaintext) < HEADER_LENGTH_SIZE + header_len:
            raise ValueError("Invalid decrypted data: header length mismatch")
        
        header_json = plaintext[HEADER_LENGTH_SIZE:HEADER_LENGTH_SIZE + header_len]
        chunk_data = plaintext[HEADER_LENGTH_SIZE + header_len:]
        try:
            header = json.loads(header_json)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid decrypted data: header JSON decode failed")
        
        if header["type"] != MessageType.FILE_CHUNK:
            raise ValueError("Invalid message type in decrypted chunk")
        
        # Decryption successful, update the state
        self._receive_chain_key = new_chain_key
        self.peer_counter = counter
        # Store peer's latest eph public key for completeness
        self.msg_peer_base_public = peer_eph_pub
        
        return {
            "transfer_id": header["transfer_id"],
            "chunk_index": header["chunk_index"],
            "chunk_data":  chunk_data,
        }
    
    # Rekey methods
    def activate_pending_keys(self) -> None:
        """Atomically switch active session to the pending keys (if available)."""
        if not self._pending_send_chain_key:
            return
        # Activate session keys
        self.shared_key = True
        self._verification_key = self._pending_verification_key
        self._key_verification_material = self._pending_key_verification_material
        self._send_chain_key = self._pending_send_chain_key
        self._receive_chain_key = self._pending_receive_chain_key
        self._otp_material = self._pending_otp_material
        # Reset message counters
        self.message_counter = 0
        self.peer_counter = 0
        self.messages_since_last_rekey = 0
        # Reset DH ratchet baseline
        self._msg_recv_private = self._pending_msg_recv_private
        self.msg_peer_base_public = self._pending_msg_peer_base_public
        self.peer_dh_public_key_bytes = self._pending_peer_dh_public_key_bytes
        self.skipped_counters = LRUCache(1000)
        # Clear pending state
        self._pending_send_chain_key = b""
        self._pending_receive_chain_key = b""
        self._pending_otp_material = b""
        self._pending_verification_key = b""
        self._pending_key_verification_material = b""
        self._pending_msg_recv_private = None
        self._pending_msg_peer_base_public = b""
        self._pending_peer_dh_public_key_bytes = b""
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        # Clear rekey state
        self._rke_reset()
        self._rekey_in_progress = False
    
    def _rke_reset(self) -> None:
        """Clear all rekey KE protocol state (does not clear pending keys or _rekey_in_progress)."""
        self._rke_step = 0
        self._rke_client_random = b""
        self._rke_peer_client_random = b""
        self._rke_combined_random = b""
        self._rke_mldsa_pub = b""
        self._rke_mldsa_priv = b""
        self._rke_peer_mldsa_pub = b""
        self._rke_mlkem_shared_secret = b""
        self._rke_mlkem_priv = b""
        self._rke_dh_priv = None
        self._rke_dh_pub_bytes = b""
        self._rke_peer_hqc_pub = b""
        self._rke_peer_mlkem_pub = b""
        self._rke_hqc_pub = b""
        self._rke_hqc_priv = b""
        self._rke_b_dh_priv = None
        self._rke_b_dh_pub_bytes = b""
        self._rke_intermediary_key_1 = b""
    
    def reset_rekey(self, error_msg: str = "") -> None:
        """Abort an in-progress rekey and clear all associated state."""
        self._rke_reset()
        self._pending_send_chain_key = b""
        self._pending_receive_chain_key = b""
        self._pending_otp_material = b""
        self._pending_verification_key = b""
        self._pending_key_verification_material = b""
        self._pending_msg_recv_private = None
        self._pending_msg_peer_base_public = b""
        self._pending_peer_dh_public_key_bytes = b""
        self._rekey_in_progress = False
        if error_msg:
            self._report_error(f"Rekey aborted: {error_msg}")
    
    def _rke_derive_combined_random(self) -> bytes:
        """Derive combined random from both rekey client randoms (domain-separated from initial KE)."""
        randoms = sorted([self._rke_client_random, self._rke_peer_client_random])
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=randoms[0],
                info=server_id + b'rekey_comb_rand',
        )
        return hkdf.derive(randoms[1])
    
    def _rke_derive_intermediary_key_1(self, mlkem_shared_secret: bytes) -> bytes:
        """Derive rekey int_key_1 from ML-KEM secret."""
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._rke_combined_random,
                info=server_id + b'rekey_int_key_1',
        )
        return hkdf.derive(mlkem_shared_secret)
    
    def _rke_derive_intermediary_key_2(self, intermediary_key_1: bytes, dh_shared_secret: bytes) -> bytes:
        """Derive rekey int_key_2 from int_key_1 and X25519 secret."""
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=dh_shared_secret,
                info=server_id + b'rekey_int_key_2',
        )
        return hkdf.derive(intermediary_key_1)
    
    def _rke_finalize(self, dh_shared_secret: bytes, hqc_secret: bytes,
                      mlkem_shared_secret: bytes,
                      own_dh_priv: X25519PrivateKey, peer_dh_pub_bytes: bytes,
                      ) -> None:
        """Derive and store pending session keys (mirrors _finalize_key_exchange but into _pending_*)."""
        server_id = self._server_identifier.encode('utf-8')
        
        otp_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._rke_combined_random,
                info=server_id + b'rekey_otp_material',
        )
        pending_otp = otp_hkdf.derive(hqc_secret)
        
        own_chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._rke_client_random,
                info=server_id + b'rekey_chain_key_root',
        )
        own_chain_key = own_chain_hkdf.derive(mlkem_shared_secret + dh_shared_secret)
        
        peer_chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=self._rke_peer_client_random,
                info=server_id + b'rekey_chain_key_root',
        )
        peer_chain_key = peer_chain_hkdf.derive(mlkem_shared_secret + dh_shared_secret)
        
        sorted_materials = sorted([pending_otp, own_chain_key, peer_chain_key])
        verification_hash = hashlib.sha3_512(b''.join(sorted_materials)).digest()
        key_verification_material = hashlib.sha3_512(
                b''.join(sorted_materials) + self._rke_combined_random).digest()[:32]
        
        self._pending_otp_material = pending_otp
        self._pending_send_chain_key = own_chain_key
        self._pending_receive_chain_key = peer_chain_key
        self._pending_verification_key = verification_hash
        self._pending_key_verification_material = key_verification_material
        self._pending_msg_recv_private = own_dh_priv
        self._pending_msg_peer_base_public = peer_dh_pub_bytes
        self._pending_peer_dh_public_key_bytes = peer_dh_pub_bytes
    
    def create_rekey_dsa_random(self, is_initiator: bool) -> dict:
        """Start a rekey: generate ephemeral ML-DSA keys + client random; return dsa_random payload."""
        self._rke_mldsa_pub, self._rke_mldsa_priv = ml_dsa_87.generate_keypair()
        self._rke_client_random = os.urandom(CLIENT_RANDOM_SIZE)
        self._rke_step = 1 if is_initiator else 2
        self._rekey_in_progress = True
        return {
            "type":             MessageType.REKEY,
            "action":           "dsa_random",
            "is_response":      False,  # False = initiating, True = responding to peer's dsa_random
            "mldsa_public_key": base64.b64encode(self._rke_mldsa_pub).decode('utf-8'),
            "client_random":    base64.b64encode(self._rke_client_random).decode('utf-8'),
        }
    
    def _make_dsa_random_response(self) -> dict:
        """Return B's dsa_random payload (marked as a response, not an initiation)."""
        return {
            "type":             MessageType.REKEY,
            "action":           "dsa_random",
            "is_response":      True,
            "mldsa_public_key": base64.b64encode(self._rke_mldsa_pub).decode('utf-8'),
            "client_random":    base64.b64encode(self._rke_client_random).decode('utf-8'),
        }
    
    def process_rekey_dsa_random(self, inner: dict) -> dict | None:
        """Process peer's dsa_random. Returns next outbound rekey message dict or None.

        The `is_response` field distinguishes a peer-initiated message (race condition possible)
        from a peer response to our own initiation (normal flow — always stay A).
        """
        try:
            peer_mldsa_pub = base64.b64decode(inner["mldsa_public_key"], validate=True)
            peer_random = base64.b64decode(inner["client_random"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise ValueError(f"Invalid rekey dsa_random: {e}") from e
        
        peer_is_initiating = not inner.get("is_response", False)
        
        if self._rke_step == 0:
            # Peer initiated and we haven't started. Generate our keys and become B.
            self._rke_mldsa_pub, self._rke_mldsa_priv = ml_dsa_87.generate_keypair()
            self._rke_client_random = os.urandom(CLIENT_RANDOM_SIZE)
            self._rke_step = 2
            self._rekey_in_progress = True
        
        if self._rke_step == 1:
            # I am A (initiator).
            if peer_is_initiating and peer_random > self._rke_client_random:
                # Race AND peer has larger random → peer stays A, I become B
                self._rke_step = 2
                # Fall through to B processing below
            else:
                # Normal A processing (or race where I win/have equal random)
                if self._rke_combined_random:
                    # Already processed a dsa_random (duplicate from race); ignore
                    return None
                self._rke_peer_mldsa_pub = peer_mldsa_pub
                self._rke_peer_client_random = peer_random
                self._rke_combined_random = self._rke_derive_combined_random()
                return self._create_rekey_mlkem_pubkey()
        
        # I am B (responder). Store peer data and respond with own dsa_random.
        if self._rke_combined_random:
            # Already processed a dsa_random; ignore duplicate
            return None
        self._rke_peer_mldsa_pub = peer_mldsa_pub
        self._rke_peer_client_random = peer_random
        self._rke_combined_random = self._rke_derive_combined_random()
        return self._make_dsa_random_response()
    
    def _create_rekey_mlkem_pubkey(self) -> dict:
        """(A) Generate ML-KEM-1024 and X25519 keypairs; return signed mlkem_pubkey payload."""
        mlkem_pub, mlkem_priv = ml_kem_1024.generate_keypair()
        self._rke_mlkem_priv = mlkem_priv
        dh_priv = X25519PrivateKey.generate()
        self._rke_dh_priv = dh_priv
        self._rke_dh_pub_bytes = dh_priv.public_key().public_bytes_raw()
        signature = ml_dsa_87.sign(self._rke_mldsa_priv, mlkem_pub)
        return {
            "type":             MessageType.REKEY,
            "action":           "mlkem_pubkey",
            "mlkem_public_key": base64.b64encode(mlkem_pub).decode('utf-8'),
            "mldsa_signature":  base64.b64encode(signature).decode('utf-8'),
        }
    
    def process_rekey_mlkem_pubkey(self, inner: dict) -> dict:
        """(B) Process A's mlkem_pubkey; generate B's keys, encapsulate, return mlkem_ct_keys payload."""
        try:
            mlkem_pub = base64.b64decode(inner["mlkem_public_key"], validate=True)
            mldsa_sig = base64.b64decode(inner["mldsa_signature"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise ValueError(f"Invalid rekey mlkem_pubkey: {e}") from e
        
        if not ml_dsa_87.verify(self._rke_peer_mldsa_pub, mlkem_pub, mldsa_sig):
            raise ValueError("ML-DSA signature verification failed on rekey mlkem_pubkey")
        
        self._rke_peer_mlkem_pub = mlkem_pub
        
        # B generates HQC and X25519 keypairs
        hqc_pub, hqc_priv = hqc_256.generate_keypair()
        self._rke_hqc_pub = hqc_pub
        self._rke_hqc_priv = hqc_priv
        dh_priv = X25519PrivateKey.generate()
        self._rke_b_dh_priv = dh_priv
        self._rke_b_dh_pub_bytes = dh_priv.public_key().public_bytes_raw()
        
        # B encapsulates ML-KEM; store shared secret for use in _rke_finalize later
        mlkem_ciphertext, mlkem_shared_secret = ml_kem_1024.encrypt(mlkem_pub)
        self._rke_mlkem_shared_secret = mlkem_shared_secret
        
        # Derive int_key_1; store for use in process_rekey_x25519_hqc_ct
        int_key_1 = self._rke_derive_intermediary_key_1(mlkem_shared_secret)
        self._rke_intermediary_key_1 = int_key_1
        
        # Encrypt B's HQC pubkey and X25519 pubkey with int_key_1
        encryptor = KeyExchangeDoubleEncryptor(int_key_1)
        nonce1 = os.urandom(NONCE_SIZE)
        nonce2 = os.urandom(NONCE_SIZE)
        encrypted_hqc_pubkey = encryptor.encrypt(nonce1, hqc_pub)
        encrypted_x25519_pubkey = encryptor.encrypt(nonce2, self._rke_b_dh_pub_bytes)
        
        signed_payload = mlkem_ciphertext + encrypted_hqc_pubkey + encrypted_x25519_pubkey + nonce1 + nonce2
        signature = ml_dsa_87.sign(self._rke_mldsa_priv, signed_payload)
        
        return {
            "type":                    MessageType.REKEY,
            "action":                  "mlkem_ct_keys",
            "mlkem_ciphertext":        base64.b64encode(mlkem_ciphertext).decode('utf-8'),
            "encrypted_hqc_pubkey":    base64.b64encode(encrypted_hqc_pubkey).decode('utf-8'),
            "encrypted_x25519_pubkey": base64.b64encode(encrypted_x25519_pubkey).decode('utf-8'),
            "nonce1":                  base64.b64encode(nonce1).decode('utf-8'),
            "nonce2":                  base64.b64encode(nonce2).decode('utf-8'),
            "mldsa_signature":         base64.b64encode(signature).decode('utf-8'),
        }
    
    def process_rekey_mlkem_ct_keys(self, inner: dict) -> dict:
        """(A) Process B's mlkem_ct_keys; decapsulate, decrypt, finalize pending keys; return x25519_hqc_ct."""
        try:
            mlkem_ct = base64.b64decode(inner["mlkem_ciphertext"], validate=True)
            enc_hqc_pub = base64.b64decode(inner["encrypted_hqc_pubkey"], validate=True)
            enc_x25519_pub = base64.b64decode(inner["encrypted_x25519_pubkey"], validate=True)
            nonce1 = base64.b64decode(inner["nonce1"], validate=True)
            nonce2 = base64.b64decode(inner["nonce2"], validate=True)
            mldsa_sig = base64.b64decode(inner["mldsa_signature"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise ValueError(f"Invalid rekey mlkem_ct_keys: {e}") from e
        
        signed_payload = mlkem_ct + enc_hqc_pub + enc_x25519_pub + nonce1 + nonce2
        if not ml_dsa_87.verify(self._rke_peer_mldsa_pub, signed_payload, mldsa_sig):
            raise ValueError("ML-DSA signature verification failed on rekey mlkem_ct_keys")
        
        # A decapsulates ML-KEM
        mlkem_shared_secret = ml_kem_1024.decrypt(self._rke_mlkem_priv, mlkem_ct)
        
        # Derive int_key_1
        int_key_1 = self._rke_derive_intermediary_key_1(mlkem_shared_secret)
        self._rke_intermediary_key_1 = int_key_1
        
        # Decrypt B's HQC pubkey and X25519 pubkey
        decryptor = KeyExchangeDoubleEncryptor(int_key_1)
        peer_hqc_pub = decryptor.decrypt(nonce1, enc_hqc_pub)
        peer_x25519_pub_bytes = decryptor.decrypt(nonce2, enc_x25519_pub)
        self._rke_peer_hqc_pub = peer_hqc_pub
        
        # A performs DH with B's X25519 public key
        dh_shared_secret = self._rke_dh_priv.exchange(
                X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes))
        
        # A encapsulates HQC with B's pubkey
        hqc_ciphertext, hqc_secret = hqc_256.encrypt(peer_hqc_pub)
        
        # Derive int_key_2
        int_key_2 = self._rke_derive_intermediary_key_2(int_key_1, dh_shared_secret)
        
        # Encrypt A's X25519 pubkey with int_key_1, HQC ciphertext with int_key_2
        enc1 = KeyExchangeDoubleEncryptor(int_key_1)
        enc2 = KeyExchangeDoubleEncryptor(int_key_2)
        out_nonce1 = os.urandom(NONCE_SIZE)
        out_nonce2 = os.urandom(NONCE_SIZE)
        encrypted_x25519_pubkey = enc1.encrypt(out_nonce1, self._rke_dh_pub_bytes)
        encrypted_hqc_ciphertext = enc2.encrypt(out_nonce2, hqc_ciphertext)
        
        # Sign before finalizing (finalize does not discard mldsa keys; they'll be cleared by _rke_reset)
        out_signed_payload = encrypted_x25519_pubkey + encrypted_hqc_ciphertext + out_nonce1 + out_nonce2
        signature = ml_dsa_87.sign(self._rke_mldsa_priv, out_signed_payload)
        
        # Finalize A's pending keys
        self._rke_finalize(dh_shared_secret, hqc_secret, mlkem_shared_secret,
                           self._rke_dh_priv, peer_x25519_pub_bytes)
        
        return {
            "type":                     MessageType.REKEY,
            "action":                   "x25519_hqc_ct",
            "encrypted_x25519_pubkey":  base64.b64encode(encrypted_x25519_pubkey).decode('utf-8'),
            "encrypted_hqc_ciphertext": base64.b64encode(encrypted_hqc_ciphertext).decode('utf-8'),
            "nonce1":                   base64.b64encode(out_nonce1).decode('utf-8'),
            "nonce2":                   base64.b64encode(out_nonce2).decode('utf-8'),
            "mldsa_signature":          base64.b64encode(signature).decode('utf-8'),
        }
    
    def process_rekey_x25519_hqc_ct(self, inner: dict) -> None:
        """(B) Process A's x25519_hqc_ct; derive and store pending session keys."""
        try:
            enc_x25519_pub = base64.b64decode(inner["encrypted_x25519_pubkey"], validate=True)
            enc_hqc_ct = base64.b64decode(inner["encrypted_hqc_ciphertext"], validate=True)
            nonce1 = base64.b64decode(inner["nonce1"], validate=True)
            nonce2 = base64.b64decode(inner["nonce2"], validate=True)
            mldsa_sig = base64.b64decode(inner["mldsa_signature"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise ValueError(f"Invalid rekey x25519_hqc_ct: {e}") from e
        
        signed_payload = enc_x25519_pub + enc_hqc_ct + nonce1 + nonce2
        if not ml_dsa_87.verify(self._rke_peer_mldsa_pub, signed_payload, mldsa_sig):
            raise ValueError("ML-DSA signature verification failed on rekey x25519_hqc_ct")
        
        # Decrypt A's X25519 pubkey with int_key_1
        dec1 = KeyExchangeDoubleEncryptor(self._rke_intermediary_key_1)
        peer_x25519_pub_bytes = dec1.decrypt(nonce1, enc_x25519_pub)
        
        # B performs DH with A's X25519 public key
        dh_shared_secret = self._rke_b_dh_priv.exchange(
                X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes))
        
        # Derive int_key_2
        int_key_2 = self._rke_derive_intermediary_key_2(self._rke_intermediary_key_1, dh_shared_secret)
        
        # Decrypt HQC ciphertext with int_key_2, then decapsulate
        dec2 = KeyExchangeDoubleEncryptor(int_key_2)
        hqc_ciphertext = dec2.decrypt(nonce2, enc_hqc_ct)
        hqc_secret = hqc_256.decrypt(self._rke_hqc_priv, hqc_ciphertext)
        
        # Finalize B's pending keys
        self._rke_finalize(dh_shared_secret, hqc_secret, self._rke_mlkem_shared_secret,
                           self._rke_b_dh_priv, peer_x25519_pub_bytes)
    
    def create_rekey_verification(self) -> dict:
        """Return a rekey verification payload (HMAC of pending key material)."""
        h = HMAC(self._pending_key_verification_material, hashes.SHA3_512())
        h.update(b"key-verification-v1")
        proof = h.finalize()
        return {
            "type":             MessageType.REKEY,
            "action":           "verification",
            "verification_key": base64.b64encode(proof).decode('utf-8'),
        }
    
    @property
    def rekey_pending_keys_exist(self) -> bool:
        """True when pending rekey keys have been computed but not yet activated."""
        return bool(self._pending_send_chain_key)
    
    def process_rekey_verification(self, inner: dict) -> bool:
        """Verify peer's rekey verification proof. Returns True on match.

        Uses pending key material when available (A's path, or B before activation).
        Falls back to active key material when B has already activated via queue_json_then_switch.
        """
        try:
            peer_proof = base64.b64decode(inner["verification_key"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise ValueError(f"Invalid rekey verification: {e}") from e
        
        key_material = self._pending_key_verification_material or self._key_verification_material
        if not key_material:
            raise ValueError("No rekey verification key material available")
        
        h = HMAC(key_material, hashes.SHA3_512())
        h.update(b"key-verification-v1")
        expected = h.finalize()
        return bytes_eq(peer_proof, expected)
