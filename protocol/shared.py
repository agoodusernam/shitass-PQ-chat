# shared.py - Shared cryptographic utilities and protocol definitions
# pylint: disable=trailing-whitespace, line-too-long
import base64
import binascii
import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Buffer
from typing import Any, SupportsIndex, SupportsBytes

from SecureChatABCs.protocol_base import ProtocolBase
from config import ConfigHandler
from utils.network_utils import send_message
from protocol.crypto_classes import DoubleEncryptor, KeyExchangeDoubleEncryptor
from protocol.constants import (
    MessageType,
    MAGIC_NUMBER_FILE_TRANSFER,
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
    create_rekey_init_message,
    create_rekey_response_message,
    create_rekey_commit_message,
)
from protocol.parse_messages import (
    process_key_verification_message,
    parse_ke_dsa_random,
    parse_ke_mlkem_pubkey,
    parse_ke_mlkem_ct_keys,
    parse_ke_x25519_hqc_ct,
    parse_ke_verification,
    parse_rekey_init,
    parse_rekey_response,
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


class SecureChatProtocol(ProtocolBase):
    """
    SecureChatProtocol - Implements the cryptographic protocol for secure chat using ML-KEM and AES-GCM.
    """
    
    def __init__(self) -> None:
        """
        Initialise the secure chat protocol with the default cryptographic state.

        Sets up all necessary state variables for the ML-KEM-1024 + X25519 + HQC-256 key
        exchange, double-encrypted AES-GCM + ChaCha20Poly1305 messaging, a Double Ratchet
        for perfect forward secrecy, replay protection, and file transfer functionality.

        Attributes are grouped below by their role. "Guaranteed" attributes always hold a
        valid, usable value after __init__. "Unsafe" attributes default to a zero/empty/None
        sentinel and are only valid after the corresponding protocol phase has completed.

        Guaranteed Attributes:
            config (ConfigHandler): The configuration handler instance.
            message_counter (int): Outgoing message counter for the current session.
            peer_counter (int): Last confirmed incoming message counter.
            messages_since_last_rekey (int): Number of messages sent/received since the last rekey.
            rekey_interval (int): Randomised message threshold that triggers an automatic rekey.
            rekey_in_progress (bool): Whether a rekey exchange is currently in flight.

            message_queue (deque): Queue of outgoing items pending encryption and dispatch.
            sender_running (bool): Whether the background sender thread is active.
            sender_lock (threading.Lock): Mutex protecting access to message_queue.

            skipped_counters (LRUCache): Cache of out-of-order chain states keyed by counter.

            file_handler (ProtocolFileHandler): Delegate for all file-transfer I/O.

        Unsafe Attributes:
            shared_key (bool): Set to True once a session shared secret has been established.
            verification_key (bytes): HMAC key derived during key exchange; empty until then.
            send_chain_key (bytes): Current symmetric ratchet key for outgoing messages.
            receive_chain_key (bytes): Current symmetric ratchet key for incoming messages.

            mlkem_public_key (bytes): Own ML-KEM-1024 public key; empty until key exchange.
            mlkem_private_key (bytes): Own ML-KEM-1024 private key; empty until key exchange.
            hqc_public_key (bytes): Own HQC-256 public key; empty until key exchange.
            hqc_private_key (bytes): Own HQC-256 private key; empty until key exchange.
            peer_mlkem_public_key (bytes): Peer's ML-KEM-1024 public key; empty until key exchange.
            peer_hqc_public_key (bytes): Peer's HQC-256 public key; empty until key exchange.

            dh_private_key (X25519PrivateKey | None): Ephemeral X25519 private key for session setup.
            dh_public_key_bytes (bytes): Raw bytes of the own session-setup X25519 public key.
            peer_dh_public_key_bytes (bytes): Raw bytes of the peer's session-setup X25519 public key.

            msg_recv_private (X25519PrivateKey | None): X25519 private key used in the Double Ratchet.
            msg_peer_base_public (bytes): Peer's last known Double Ratchet public key.

            socket (socket.socket | None): Active socket; None when not connected.
            sender_thread (threading.Thread | None): Background sender thread; None when stopped.

            pending_shared_key (bytes): Combined shared secret staged for the next rekey activation.
            pending_encryption_key (bytes): Verification key staged for the next rekey activation.
            pending_send_chain_key (bytes): Send chain key staged for the next rekey activation.
            pending_receive_chain_key (bytes): Receive chain key staged for the next rekey activation.
            pending_hqc_secret (bytes): HQC secret staged for the next rekey activation.
            pending_message_counter (int): Outgoing counter value for the pending session.
            pending_peer_counter (int): Incoming counter value for the pending session.

            rekey_mlkem_private_key (bytes): Ephemeral ML-KEM private key used during an active rekey.
            rekey_hqc_private_key (bytes): Ephemeral HQC private key used during an active rekey.
            rekey_dh_private (X25519PrivateKey | None): Ephemeral X25519 private key for the active rekey.
            rekey_dh_public (X25519PublicKey | None): Corresponding X25519 public key for the active rekey.

            peer_version (str): Protocol version string advertised by the peer (set during key exchange init).
        """
        
        # Configuration + protocol
        self.config: ConfigHandler = ConfigHandler()
        
        # Transport + queuing
        self._message_queue: deque = deque()
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
        self.rekey_in_progress: bool = False
        self._pending_shared_key: bytes = b""
        self._pending_encryption_key: bytes = b""
        self._pending_send_chain_key: bytes = b""
        self._pending_receive_chain_key: bytes = b""
        self._pending_hqc_secret: bytes = b""
        self._pending_otp_material: bytes = b""
        self.pending_message_counter: int = 0
        self.pending_peer_counter: int = 0
        self._rekey_mlkem_private_key: bytes = b""
        self._rekey_hqc_private_key: bytes = b""
        self.rekey_dh_public: X25519PublicKey | None = None
        self._rekey_dh_private: X25519PrivateKey | None = None
        
        # Automatic rekey tracking
        self.messages_since_last_rekey: int = 0
        # Randomise the rekey interval by ±10% of the base value
        base_interval = self.config["rekey_interval"]
        variation = round(base_interval * 0.1)
        self.rekey_interval: int = base_interval + (secrets.randbelow(variation + 1) - variation)
    
    def has_active_file_transfers(self) -> bool:
        # Set in __init__ of the file handler.
        ...
    
    def reset_auto_rekey_counter(self) -> None:
        self.messages_since_last_rekey = 1
    
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
        return self._send_dummy_messages and not self.rekey_in_progress and not self.has_active_file_transfers()
    
    @send_dummy_messages.setter
    def send_dummy_messages(self, value: bool) -> None:
        """Set whether dummy messages should be sent."""
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
            self._sender_thread.join(timeout=1.0)  # Wait up to 1 second for thread to stop
        self._sender_thread = None
        self._socket = None
    
    def queue_json_and_encrypt(self, message: dict[str, Any]) -> None:
        """
        Add a json message in form of a dict to the send queue, to be encrypted and sent.
        """
    
    def queue_message(self, message: bytes | str | dict[str, Any] | tuple[str, Any]) -> None:
        """
        Add a message to the send queue.
        
        The message can be one of the following:
        - bytes: already-prepared data to send as-is (control or pre-encrypted)
        - str: plaintext to be encrypted and sent
        - dict: JSON-serializable object to be encrypted and sent
        - tuple: instruction for the sender loop, supported forms:
            ("encrypt_text", str)
            ("encrypt_json", dict)
            ("encrypt_json_then_switch", dict) # send encrypted under current keys, then activate pending keys
            ("file_chunk", transfer_id: str, chunk_index: int, chunk_data: bytes)
            ("plaintext", bytes) # send as-is (control)
            ("encrypted", bytes) # send as-is (already encrypted)
        """
        with self._sender_lock:
            self._message_queue.append(message)
    
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
        
        This loop is responsible for performing encryption for all queued
        non-control messages before sending them over the socket.
        Control messages (key exchange, explicit plaintext items) are sent as-is.
        """
        while self._sender_running:
            item = self._get_next_item()
            to_send, post_action = self._prepare_item_for_sending(item)
            
            if to_send is not None and self._socket is not None:
                self._send_prepared_item(to_send, post_action)
            
            time.sleep(0.25)
    
    def _get_next_item(self):
        """Get the next item from the queue or generate a dummy message."""
        with self._sender_lock:
            if self._message_queue:
                return self._message_queue.popleft()
        
        # Generate dummy message if appropriate
        if self.send_dummy_messages and self.encryption_ready and self.config["send_dummy_packets"]:
            return self._generate_dummy_message()
        
        return None
    
    def _prepare_item_for_sending(self, item) -> tuple[bytes | None, str | None]:
        """Convert a queue item into bytes ready for transmission."""
        if item is None:
            return None, None
        
        try:
            if isinstance(item, (bytes, bytearray)):
                return bytes(item), None
            
            if isinstance(item, (str, dict)):
                return self._encrypt_plaintext_item(item), None
            
            if isinstance(item, tuple) and item:
                return self._process_instruction_tuple(item)
            
            raise ValueError(f"Unsupported item type: {type(item)}")
        
        except (ValueError, TypeError) as e:
            print(f"Message preparation error (dropped): {e}")
            return None, None
        except Exception as e:
            print(f"Unexpected error preparing message (dropped): {e}")
            return None, None
    
    def _encrypt_plaintext_item(self, item) -> bytes:
        """Encrypt a string or dict item."""
        if isinstance(item, dict):
            item = json.dumps(item)
        
        if not (self.shared_key and self._send_chain_key):
            raise ValueError("Encryption keys not ready for plaintext item")
        
        return self.encrypt_message(item)
    
    def _process_instruction_tuple(self, item: tuple) -> tuple[bytes, str | None]:
        """Process instruction tuples like ('encrypt_text', data)."""
        kind = item[0]
        
        if kind == "encrypt_text" and len(item) >= 2:
            return self._encrypt_text_message(item[1]), None
        
        if kind == "encrypt_json" and len(item) >= 2:
            return self._encrypt_json_message(item[1]), None
        
        if kind == "encrypt_json_then_switch" and len(item) >= 2:
            return self._encrypt_json_message(item[1]), "switch_keys"
        
        if kind in ("plaintext", "encrypted") and len(item) >= 2:
            data = item[1]
            if isinstance(data, (SupportsIndex, SupportsBytes, Buffer)):
                return bytes(data), None
            raise TypeError("Provided data is not bytes-like for plaintext/encrypted send")
        
        raise ValueError(f"Unsupported instruction tuple: {kind}")
    
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
    
    def _send_prepared_item(self, to_send: bytes, post_action: str | None) -> None:
        """Send prepared bytes and perform any post-send actions."""
        assert self._socket is not None
        result = send_message(self._socket, to_send)
        if result is not None:
            print(f"Failed to send message: {result}")
        
        if post_action == "switch_keys":
            self.activate_pending_keys()
    
    def generate_dsa_keys(self) -> None:
        """Generate ML-DSA keypair for key exchange signing."""
        self._mldsa_public_key, self._mldsa_private_key = ml_dsa_87.generate_keypair()
    
    def set_server_identifier(self, identifier: str) -> None:
        """Set the server identifier for use in key derivations."""
        self._server_identifier = identifier
    
    def create_ke_dsa_random(self) -> bytes:
        """Create KE_DSA_RANDOM message: send our DSA public key and a client random."""
        self.generate_dsa_keys()
        self._ke_client_random = os.urandom(32)
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
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)
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
        nonce1 = os.urandom(12)
        encrypted_x25519_pubkey = encryptor_1.encrypt(nonce1, self.dh_public_key_bytes)
        
        # Encrypt HQC ciphertext with intermediary key 2
        encryptor_2 = KeyExchangeDoubleEncryptor(intermediary_key_2)
        nonce2 = os.urandom(12)
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
            length=64,
            salt=self._combined_random,
            info=server_id + b'otp_material',
        )
        self._otp_material = otp_hkdf.derive(self._hqc_secret)
        
        # Own chain key root = SHA-3-512-HKDF(ML-KEM secret + X25519 secret, salt=own_random, info=server_id + 'chain_key_root')
        own_chain_hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=self._ke_client_random,
            info=server_id + b'chain_key_root',
        )
        own_chain_key_root = own_chain_hkdf.derive(self._ke_mlkem_shared_secret + dh_shared_secret)
        
        # Peer chain key root = same but with peer's random as salt
        peer_chain_hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=self._peer_client_random,
            info=server_id + b'chain_key_root',
        )
        peer_chain_key_root = peer_chain_hkdf.derive(self._ke_mlkem_shared_secret + dh_shared_secret)
        
        # Set chain keys: own root for sending, peer root for receiving
        self._send_chain_key = own_chain_key_root
        self._receive_chain_key = peer_chain_key_root
        
        # Verification key = SHA3-512(sorted([otp_material, own_chain_key_root, peer_chain_key_root])) truncated to 256 bits
        sorted_materials = sorted([self._otp_material, own_chain_key_root, peer_chain_key_root])
        verification_hash = hashlib.sha3_512(b''.join(sorted_materials)).digest()
        self._verification_key = verification_hash[:32]
        
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
        return create_ke_verification(self._verification_key)
    
    def process_ke_verification(self, data: bytes) -> bool:
        """Process peer's KE_VERIFICATION and check it matches our derived key.
        Returns True if verification succeeds."""
        parsed = parse_ke_verification(data)
        return bytes_eq(parsed["verification_key"], self._verification_key)
    
    def _derive_combined_random(self) -> bytes:
        """Derive combined random from both client randoms using SHA2-512-HKDF.
        combined_random = SHA2-512-HKDF(larger_random, salt=smaller_random, info=server_id + 'comb_rand')"""
        randoms = sorted([self._ke_client_random, self._peer_client_random])
        smaller_random = randoms[0]
        larger_random = randoms[1]
        server_id = self._server_identifier.encode('utf-8')
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=64,
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
            length=64,
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
            length=64,
            salt=dh_shared_secret,
            info=server_id + b'int_key_2',
        )
        return hkdf.derive(intermediary_key_1)
    
    @staticmethod
    def _derive_combined_shared_secret(mlkem_shared_secret: bytes, dh_shared_secret: bytes) -> bytes:
        """Combine ML-KEM and X25519 shared secrets into a single shared secret (used by rekey)."""
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=64,
            salt=mlkem_shared_secret,
            info=b"combined_shared_secret",
        )
        return hkdf.derive(dh_shared_secret)
    
    @staticmethod
    def _derive_keys_and_chain(shared_secret: bytes, own_pub: bytes = b"", peer_pub: bytes = b"") -> tuple[bytes, bytes]:
        """Derive encryption key and root chain key from a shared secret (used by rekey)."""
        if own_pub and peer_pub:
            keys = sorted([own_pub, peer_pub])
            combined_keys = keys[0] + keys[1]
        else:
            combined_keys = b""
        
        enc_salt = hashlib.sha512(combined_keys + b"enc_key_salt").digest()[:32]
        chain_salt = hashlib.sha512(combined_keys + b"chain_salt").digest()[:32]
        
        hkdf_keys = HKDF(
                algorithm=hashes.SHA3_512(),
                length=32,
                salt=enc_salt,
                info=b"key_derivation",
        )
        derived = hkdf_keys.derive(shared_secret)
        
        hkdf_chain = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=chain_salt,
                info=b"chain_key_root",
        )
        root_chain_key = hkdf_chain.derive(shared_secret)
        return derived, root_chain_key
    
    @staticmethod
    def _derive_rekey_otp_material(hqc_secret: bytes) -> bytes:
        """Derive OTP material from HQC secret during rekey."""
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=None,
            info=b"rekey_otp_material",
        )
        return hkdf.derive(hqc_secret)
    
    @staticmethod
    def _derive_message_key(chain_key: bytes, counter: int) -> bytes:
        """Derive a message key from the chain key and counter."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=64,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"message_key_{counter}".encode(),
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def _ratchet_chain_key(chain_key: bytes, counter: int) -> bytes:
        """Advance the chain key (ratchet forward)."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
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
                length=64,
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
        if not self._verification_key:
            raise ValueError("Verification key not available - key exchange not completed")
        
        return generate_key_fingerprint(self._verification_key, self.config["wordlist_file"])
    
    @staticmethod
    def create_key_verification_message(verified: bool) -> bytes:
        """Create a key verification status message."""
        return create_key_verification_message(verified)
    
    @staticmethod
    def process_key_verification_message(data: bytes) -> bool:
        """Process a key verification message from peer."""
        return process_key_verification_message(data)
    
    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Encrypt a message with authentication and replay protection using perfect forward secrecy.
        Integrates a Double Ratchet step using X25519 by including a fresh sender public key per message
        and mixing the DH shared secret into the chain key derivation.
        
        Additional MAC rationale:
            For authentication with AES or Poly1305, the message must be decrypted.
            To decrypt the message we need to derive the key.
            If there is no additional MAC, a bad actor could send a message with a very high counter,
            making the program essentially DoS itself.
            It also makes it possible to differentiate between forged messages and messages
            that have been corrupted or manipulated in flight
        
        :param plaintext: The plaintext message to encrypt.
        :return: The encrypted message as bytes, ready to send.
        :raises: ValueError: If no shared key or send chain key is established.
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
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Create AAD from message metadata for authentication
        nonce = os.urandom(12)
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
        del encryptor
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
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
            # May or may not actually remove it from memory but it's better than nothing
            message_key = b'\x00' * len(message_key)
            raise ValueError("Message is probably legitimate but failed to decrypt, InvalidTag")
        
        try:
            decrypted_data_str = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            # May or may not actually remove it from memory but it's better than nothing
            message_key = b'\x00' * len(message_key)
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
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        return decrypted_data_str
    
    def encrypt_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes) -> bytes:
        """
        Encrypt a file chunk using the Double Ratchet, identical in structure to encrypt_message
        but operating on raw binary data rather than JSON text.

        Frame layout: [1-byte magic][4-byte counter][12-byte nonce][32-byte eph_pub][ciphertext]

        :return: The encrypted frame as bytes, ready to send.
        :raises ValueError: If encryption state is not ready or peer DH key is missing.
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
        nonce = os.urandom(12)
        
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
        
        # This may or may not actually remove it from memory, but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Pack: magic (1) + counter (4) + nonce (12) + eph_pub (32) + ciphertext
        counter_bytes = struct.pack('!I', self.message_counter)
        return MAGIC_NUMBER_FILE_TRANSFER + counter_bytes + nonce + eph_pub_bytes + ciphertext
    
    def decrypt_file_chunk(self, encrypted_data: bytes) -> dict:
        """
        Decrypt a file chunk frame produced by encrypt_file_chunk.
        Expects frame: [1-byte magic][4-byte counter][12-byte nonce][32-byte eph_pub][ciphertext].

        :return: dict with keys ``transfer_id``, ``chunk_index``, ``chunk_data``.
        :raises ValueError: If decryption fails or the frame is malformed.
        """
        if not self.shared_key or not self._receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        if len(encrypted_data) < 1 + 4 + 12 + 32:
            raise ValueError("Invalid chunk message format")
        
        try:
            counter = int(struct.unpack('!I', encrypted_data[1:5])[0])
        except struct.error:
            raise ValueError("Invalid chunk message format")
        except ValueError:
            raise ValueError("Invalid counter in chunk message")
        
        nonce = encrypted_data[5:17]
        peer_eph_pub = encrypted_data[17:49]
        ciphertext = encrypted_data[49:]
        
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
            message_key = b'\x00' * len(message_key)
            raise ValueError("File chunk decryption failed: InvalidTag")
        
        # Parse the decrypted header and extract chunk data
        if len(plaintext) < 2:
            raise ValueError("Invalid decrypted data: too short")
        
        try:
            header_len = struct.unpack('!H', plaintext[:2])[0]
        except struct.error:
            raise ValueError("Invalid decrypted data: header length")
        
        if len(plaintext) < 2 + header_len:
            raise ValueError("Invalid decrypted data: header length mismatch")
        
        header_json = plaintext[2:2 + header_len]
        chunk_data = plaintext[2 + header_len:]
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
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        return {
            "transfer_id": header["transfer_id"],
            "chunk_index": header["chunk_index"],
            "chunk_data":  chunk_data,
        }
    
    # Rekey methods
    def activate_pending_keys(self) -> None:
        """Atomically switch active session to the pending keys (if available)."""
        if not self.rekey_in_progress:
            return
        if not (self._pending_shared_key and self._pending_encryption_key and
                self._pending_send_chain_key and self._pending_receive_chain_key):
            # Incomplete pending state, do not switch
            return
        # Activate
        self.shared_key = True
        self._verification_key = self._pending_encryption_key
        self._send_chain_key = self._pending_send_chain_key
        self._receive_chain_key = self._pending_receive_chain_key
        self.message_counter = 0
        self.peer_counter = 0
        # Reset automatic rekey counter
        self.messages_since_last_rekey = 0
        # Activate OTP material if present
        if self._pending_otp_material:
            self._otp_material = self._pending_otp_material
        if self._pending_hqc_secret:
            self._hqc_secret = self._pending_hqc_secret
        # Clear pending state
        self._pending_shared_key = b""
        self._pending_encryption_key = b""
        self._pending_send_chain_key = b""
        self._pending_receive_chain_key = b""
        self._pending_hqc_secret = b""
        self._pending_otp_material = b""
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        # Clear rekey ephemeral keys
        self._rekey_mlkem_private_key = b""
        self._rekey_hqc_private_key = b""
        self._rekey_dh_private = None
        self.rekey_dh_public = None
        self.rekey_in_progress = False
    
    def create_rekey_init(self) -> dict[str, str | int]:
        """Create a REKEY init payload to be sent inside an encrypted message using the old key."""
        # Generate ephemeral KEM keypair for this rekey only
        mlkem_public_key, mlkem_private_key = ml_kem_1024.generate_keypair()
        hqc_public_key, hqc_private_key = hqc_256.generate_keypair()
        dh_private = X25519PrivateKey.generate()
        dh_public = dh_private.public_key()
        
        self._rekey_mlkem_private_key = mlkem_private_key
        self._rekey_hqc_private_key = hqc_private_key
        self._rekey_dh_private = dh_private
        self.rekey_dh_public = dh_public
        self.rekey_in_progress = True
        return create_rekey_init_message(mlkem_public_key, hqc_public_key, dh_public.public_bytes_raw())
    
    def process_rekey_init(self, message: dict[Any, Any]) -> dict[str, int | str]:
        """Process a REKEY init payload; derive pending keys and return REKEY response payload.
        This must be called on the responder, and the response must be sent under the old key.
        """
        parsed = parse_rekey_init(message)
        peer_dh_public_key = X25519PublicKey.from_public_bytes(parsed["dh_public_key"])
        
        # Produce new shared secret and ciphertext for the initiator
        mlkem_ciphertext, mlkem_shared_secret = ml_kem_1024.encrypt(parsed["mlkem_public_key"])
        hqc_ciphertext, hqc_secret = hqc_256.encrypt(parsed["hqc_public_key"])
        self._rekey_dh_private = X25519PrivateKey.generate()
        dh_shared_secret = self._rekey_dh_private.exchange(peer_dh_public_key)
        # Combine ML-KEM and DH secrets (HQC stored separately like in initial key exchange)
        combined_shared = self._derive_combined_shared_secret(mlkem_shared_secret, dh_shared_secret)
        # Store pending derived keys without touching active ones
        enc_key, root_chain = self._derive_keys_and_chain(combined_shared)
        self._pending_shared_key = combined_shared
        self._pending_encryption_key = enc_key
        self._pending_send_chain_key = root_chain
        self._pending_receive_chain_key = root_chain
        self._pending_hqc_secret = hqc_secret
        self._pending_otp_material = self._derive_rekey_otp_material(hqc_secret)
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        self.rekey_in_progress = True
        return create_rekey_response_message(
                mlkem_ciphertext, hqc_ciphertext,
                self._rekey_dh_private.public_key().public_bytes_raw())
    
    def process_rekey_response(self, message: dict) -> dict:
        """Process a REKEY response payload on the initiator; set pending keys and return commit payload."""
        if not self._rekey_mlkem_private_key:
            raise ValueError("No ephemeral ML-KEM private key for REKEY response")
        if not self._rekey_hqc_private_key:
            raise ValueError("No ephemeral HQC private key for REKEY response")
        if not self._rekey_dh_private:
            raise ValueError("No ephemeral DH private key for REKEY response")
        
        parsed = parse_rekey_response(message)
        
        # Decrypt ML-KEM and HQC ciphertexts
        mlkem_shared_secret = ml_kem_1024.decrypt(self._rekey_mlkem_private_key, parsed["mlkem_ciphertext"])
        hqc_secret = hqc_256.decrypt(self._rekey_hqc_private_key, parsed["hqc_ciphertext"])
        
        # Compute DH shared secret
        peer_dh_public_key = X25519PublicKey.from_public_bytes(parsed["dh_public_key"])
        dh_shared_secret = self._rekey_dh_private.exchange(peer_dh_public_key)
        
        # Combine ML-KEM and DH secrets (HQC stored separately like in initial key exchange)
        combined_shared = self._derive_combined_shared_secret(mlkem_shared_secret, dh_shared_secret)
        
        # Derive keys and store pending state
        enc_key, root_chain = self._derive_keys_and_chain(combined_shared)
        self._pending_shared_key = combined_shared
        self._pending_encryption_key = enc_key
        self._pending_send_chain_key = root_chain
        self._pending_receive_chain_key = root_chain
        self._pending_hqc_secret = hqc_secret
        self._pending_otp_material = self._derive_rekey_otp_material(hqc_secret)
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        self.rekey_in_progress = True
        return create_rekey_commit_message()
