# shared.py - Shared cryptographic utilities and protocol definitions
# pylint: disable=trailing-whitespace, line-too-long
import base64
import binascii
import enum
import json
import os
import socket
import struct
import threading
import time
from collections import deque
from typing import Any, TYPE_CHECKING

from SecureChatABCs.protocol_base import ProtocolBase
from protocol._rekey_state import _RekeyState
from protocol.file_handler import ProtocolFileHandler
from config import ClientConfigHandler
from utils.network_utils import send_message
from protocol.crypto_classes import DoubleEncryptor, KeyExchangeDoubleEncryptor, _KeyDerivation
from protocol.constants import (
    DEFAULT_MAX_RATCHET_FORWARD, MessageType,
    MAGIC_NUMBER_FILE_TRANSFER,
    NONCE_SIZE,
    CLIENT_RANDOM_SIZE,
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


def _build_aad(msg_type: MessageType, counter: int, nonce: bytes, dh_pub: bytes) -> bytes:
    """
    Build the JSON-encoded AAD used by both message and file-chunk encryption.
    
    :param msg_type: ``MessageType.ENCRYPTED_MESSAGE`` or ``MessageType.FILE_CHUNK``.
    :param counter:  The message / chunk counter.
    :param nonce:    The raw nonce bytes (will be base64-encoded in the AAD).
    :param dh_pub:   The sender's ephemeral DH public key bytes (base64-encoded).
    :returns:        UTF-8–encoded JSON bytes suitable for passing to
                     ``DoubleEncryptor.encrypt`` / ``.decrypt`` as ``associated_data``.
    """
    aad_data = {
        "type":          msg_type,
        "counter":       counter,
        "nonce":         base64.b64encode(nonce).decode('utf-8'),
        "dh_public_key": base64.b64encode(dh_pub).decode('utf-8'),
    }
    return json.dumps(aad_data).encode('utf-8')

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

        Rekey-related state (both in-flight KE attributes and pending post-rekey session keys)
        lives on the composed :class:`_RekeyState` instance at ``self._rekey``.  See that class
        for the full attribute list.  A small set of rekey attributes is still exposed on the
        protocol via explicit ``@property`` passthroughs (``messages_since_last_rekey``,
        ``rekey_interval``, ``rekey_in_progress``).
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
        
        # Rekey state: all _rke_* / _pending_* attributes + every create_rekey_* /
        # process_rekey_* method live on _RekeyState.
        self._rekey: _RekeyState = _RekeyState(self)
    
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
        return self._rekey.rekey_in_progress
    
    @property
    def encryption_ready(self) -> bool:
        """Check if encryption is ready (shared key and chain keys established)."""
        return bool(self.shared_key and self._send_chain_key and self._receive_chain_key)
    
    @property
    def should_auto_rekey(self) -> bool:
        """Check if automatic rekey should be initiated based on message count."""
        return (self.messages_since_last_rekey >= self.rekey_interval and
                not self.rekey_in_progress and
                self.encryption_ready)
    
    @property
    def send_dummy_messages(self) -> bool:
        """Check if dummy messages should be sent."""
        return self._send_dummy_messages and not self.rekey_in_progress and not self.has_active_file_transfers
    
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
            if self._sender_thread.is_alive():
                self._report_error("Sender thread still running. Ignoring.")
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
        server_id = self._server_identifier.encode("utf-8")
        
        self._otp_material = _KeyDerivation.derive_otp_material(
                self._hqc_secret, self._combined_random, server_id,
        )
        own_chain_key_root = _KeyDerivation.derive_chain_key_root(
                self._ke_mlkem_shared_secret, dh_shared_secret,
                self._ke_client_random, server_id,
        )
        peer_chain_key_root = _KeyDerivation.derive_chain_key_root(
                self._ke_mlkem_shared_secret, dh_shared_secret,
                self._peer_client_random, server_id,
        )
        
        self._send_chain_key = own_chain_key_root
        self._receive_chain_key = peer_chain_key_root
        
        self._verification_key, self._key_verification_material = (
            _KeyDerivation.compute_verification_pair(
                    self._otp_material, own_chain_key_root, peer_chain_key_root,
                    self._combined_random,
            )
        )
        
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
        return _KeyDerivation.derive_combined_random(
                self._ke_client_random, self._peer_client_random,
                self._server_identifier.encode("utf-8"),
        )
    
    def _derive_intermediary_key_1(self, mlkem_shared_secret: bytes) -> bytes:
        return _KeyDerivation.derive_intermediary_key_1(
                mlkem_shared_secret, self._combined_random,
                self._server_identifier.encode("utf-8"),
        )
    
    def _derive_intermediary_key_2(self, intermediary_key_1: bytes, dh_shared_secret: bytes) -> bytes:
        return _KeyDerivation.derive_intermediary_key_2(
                intermediary_key_1, dh_shared_secret,
                self._server_identifier.encode("utf-8"),
        )
    
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
        
        nonce, eph_pub_bytes, message_key = self._ratchet_send_step()
        
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        aad = _build_aad(MessageType.ENCRYPTED_MESSAGE, self.message_counter, nonce, eph_pub_bytes)
        encryptor = DoubleEncryptor(message_key, self._otp_material, message_counter=self.message_counter)
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
        except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error, TypeError) as e:
            raise ValueError("Message decoding failed, message dropped") from e
        except KeyError as e:
            raise ValueError("Message missing field, message dropped") from e
        
        verif_hasher = HMAC(self._verification_key, hashes.SHA512())
        verif_hasher.update(json.dumps({
            "counter":       counter,
            "nonce":         message["nonce"],
            "dh_public_key": peer_dh_pub_b64,
        }).encode('utf-8'))
        actual_verification = verif_hasher.finalize()
        if not bytes_eq(expected_verification, actual_verification):
            raise ValueError("Message verification failed, message dropped")
        
        message_key, new_chain_key, use_saved = self._advance_recv_ratchet(counter, peer_dh_pub_bytes)
        
        aad = _build_aad(MessageType.ENCRYPTED_MESSAGE, counter, nonce, peer_dh_pub_bytes)
        
        decryptor = DoubleEncryptor(message_key, self._otp_material, counter)
        try:
            decrypted_data = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise ValueError("Message is probably legitimate but failed to decrypt, InvalidTag")
        
        try:
            decrypted_data_str = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Message is probably legitimate but failed to decode, UnicodeDecodeError")
        
        self._commit_recv_state(counter, peer_dh_pub_bytes, new_chain_key, use_saved)
        if not use_saved and new_chain_key:
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
        
        self.message_counter += 1
        
        nonce, eph_pub_bytes, message_key = self._ratchet_send_step()
        
        header = {
            "type":        MessageType.FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index,
        }
        header_json = json.dumps(header).encode('utf-8')
        
        aad = _build_aad(MessageType.FILE_CHUNK, self.message_counter, nonce, eph_pub_bytes)
        
        header_len = struct.pack('!H', len(header_json))
        plaintext = header_len + header_json + chunk_data
        encryptor = DoubleEncryptor(message_key, self._otp_material, self.message_counter)
        ciphertext = encryptor.encrypt(nonce, plaintext, aad)
        
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
        
        message_key, new_chain_key, use_saved = self._advance_recv_ratchet(counter, peer_eph_pub)
        
        aad = _build_aad(MessageType.FILE_CHUNK, counter, nonce, peer_eph_pub)
        
        decryptor = DoubleEncryptor(message_key, self._otp_material, counter)
        try:
            plaintext = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise ValueError("File chunk decryption failed: InvalidTag")
        
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
        
        self._commit_recv_state(counter, peer_eph_pub, new_chain_key, use_saved)

        return {
            "transfer_id": header["transfer_id"],
            "chunk_index": header["chunk_index"],
            "chunk_data":  chunk_data,
        }
    
    def _ratchet_send_step(self) -> tuple[bytes, bytes, bytes]:
        """
        Perform one Double Ratchet send step using the current ``message_counter``.

        Generates a fresh ephemeral X25519 keypair, computes the DH shared secret
        with the peer's current DH public key, mixes it into the send chain, derives
        the per-message key, and advances the send chain.

        Must be called *after* ``message_counter`` has already been incremented.

        :returns: ``(nonce, eph_pub_bytes, message_key)``
        :raises ValueError: If the peer DH public key is missing or
            ``_msg_recv_private`` is not initialised.
        """
        peer_pub_bytes = self.peer_dh_public_key_bytes
        if not peer_pub_bytes:
            raise ValueError("Missing peer DH public key for encryption")
        
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
        dh_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
        
        mixed_chain_key = _KeyDerivation.mix_dh_with_chain(
                self._send_chain_key, dh_shared, self.message_counter,
        )
        message_key = _KeyDerivation.derive_message_key(mixed_chain_key, self.message_counter)
        self._send_chain_key = _KeyDerivation.ratchet_chain_key(
                self._send_chain_key, self.message_counter,
        )
        
        nonce = os.urandom(NONCE_SIZE)
        return nonce, eph_pub_bytes, message_key
    
    def _ratchet_recv_step(
            self, temp_chain_key: bytes, peer_eph_pub: bytes, counter: int,
    ) -> tuple[bytes, bytes]:
        """
        Perform one Double Ratchet receive step.

        Mixes the peer's ephemeral DH public key into ``temp_chain_key`` to derive
        the per-message key, and computes the next chain key state.

        :param temp_chain_key: Chain key already advanced to ``counter - 1``.
        :param peer_eph_pub:   Raw bytes of the sender's ephemeral X25519 public key.
        :param counter:        Message counter for this message.
        :returns: ``(message_key, new_chain_key)``
        :raises ValueError: If ``_msg_recv_private`` is not initialised.
        """
        if not self._msg_recv_private:
            raise ValueError("Local DH private key not initialized for ratchet")
        
        dh_shared = self._msg_recv_private.exchange(
                X25519PublicKey.from_public_bytes(peer_eph_pub),
        )
        mixed_chain_key = _KeyDerivation.mix_dh_with_chain(temp_chain_key, dh_shared, counter)
        message_key = _KeyDerivation.derive_message_key(mixed_chain_key, counter)
        new_chain_key = _KeyDerivation.ratchet_chain_key(temp_chain_key, counter)
        return message_key, new_chain_key

    def _advance_recv_ratchet(self, counter: int, peer_pub_bytes: bytes) -> tuple[bytes, bytes, bool]:
        """Resolve chain key for *counter*, save/restore skipped states, derive message key.

        Returns (message_key, new_chain_key, use_saved).
        new_chain_key is b"" when use_saved is True.
        """
        if counter <= self.peer_counter:
            saved = self.skipped_counters[counter]
            if saved is None:
                raise ValueError("Message is probably legitimate but counter has unexpected value: " +
                                 f"higher than {self.peer_counter} got {counter}")
            message_key, _ = self._ratchet_recv_step(saved, peer_pub_bytes, counter)
            return message_key, b"", True

        if counter - (self.peer_counter + 1) > DEFAULT_MAX_RATCHET_FORWARD:
            raise ValueError("Message is probably legitimate but we would have to ratchet " +
                             "further than the configured maximum to attempt decryption.")
        temp_chain_key = self._receive_chain_key
        for i in range(self.peer_counter + 1, counter):
            if self.skipped_counters[i] is None:
                self.skipped_counters[i] = temp_chain_key
            temp_chain_key = _KeyDerivation.ratchet_chain_key(temp_chain_key, i)
        message_key, new_chain_key = self._ratchet_recv_step(temp_chain_key, peer_pub_bytes, counter)
        return message_key, new_chain_key, False

    def _commit_recv_state(
            self, counter: int, peer_pub_bytes: bytes, new_chain_key: bytes, use_saved: bool,
    ) -> None:
        """Update receive-side ratchet state after a successful decryption."""
        if use_saved:
            try:
                self.skipped_counters.pop(counter)
            except KeyError:
                pass
        elif new_chain_key:
            self._receive_chain_key = new_chain_key
            self.peer_counter = counter
            self.msg_peer_base_public = peer_pub_bytes

    # rekey delegates
    
    def activate_pending_keys(self) -> None:
        self._rekey.activate()
    
    def reset_rekey(self, error_msg: str = "") -> None:
        self._rekey.abort(error_msg)
    
    @property
    def rekey_pending_keys_exist(self) -> bool:
        return self._rekey.pending_exists()
    
    def create_rekey_dsa_random(self, is_initiator: bool) -> dict:
        return self._rekey.create_dsa_random(is_initiator)
    
    def process_rekey_dsa_random(self, inner: dict) -> dict | None:
        return self._rekey.process_dsa_random(inner)
    
    def process_rekey_mlkem_pubkey(self, inner: dict) -> dict:
        return self._rekey.process_mlkem_pubkey(inner)
    
    def process_rekey_mlkem_ct_keys(self, inner: dict) -> dict:
        return self._rekey.process_mlkem_ct_keys(inner)
    
    def process_rekey_x25519_hqc_ct(self, inner: dict) -> None:
        self._rekey.process_x25519_hqc_ct(inner)
    
    def create_rekey_verification(self) -> dict:
        return self._rekey.create_verification()
    
    def process_rekey_verification(self, inner: dict) -> bool:
        return self._rekey.process_verification(inner)
    
    # rekey attribute proxies
    
    @property
    def messages_since_last_rekey(self) -> int:
        return self._rekey.messages_since_last_rekey
    
    @messages_since_last_rekey.setter
    def messages_since_last_rekey(self, value: int) -> None:
        self._rekey.messages_since_last_rekey = value
    
    @property
    def rekey_interval(self) -> int:
        return self._rekey.rekey_interval
    
    @rekey_interval.setter
    def rekey_interval(self, value: int) -> None:
        self._rekey.rekey_interval = value
    
