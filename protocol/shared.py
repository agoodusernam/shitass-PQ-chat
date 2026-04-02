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
from config.config import ConfigHandler
from network_utils import send_message
from protocol.crypto_classes import DoubleEncryptor
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
    create_key_exchange_init,
    create_key_exchange_response,
    create_rekey_init_message,
    create_rekey_response_message,
    create_rekey_commit_message,
)
from protocol.parse_messages import (
    process_key_verification_message,
    parse_key_exchange_init,
    parse_key_exchange_response,
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

            mlkem_public_key (bytes): Own ML-KEM-1024 public key; empty until generate_keys().
            mlkem_private_key (bytes): Own ML-KEM-1024 private key; empty until generate_keys().
            hqc_public_key (bytes): Own HQC-256 public key; empty until generate_keys().
            hqc_private_key (bytes): Own HQC-256 private key; empty until generate_keys().
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
            rekey_dh_public_bytes (bytes): Raw bytes of rekey_dh_public.

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
        
        # Session keys
        self.shared_key: bool = False
        self._verification_key: bytes = b""
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
        self.pending_message_counter: int = 0
        self.pending_peer_counter: int = 0
        self._rekey_mlkem_private_key: bytes = b""
        self._rekey_hqc_private_key: bytes = b""
        self.rekey_dh_public: X25519PublicKey | None = None
        self.rekey_dh_public_bytes: bytes = b""
        self._rekey_dh_private: X25519PrivateKey | None = None
        
        # Automatic rekey tracking
        self.messages_since_last_rekey: int = 0
        # Randomise the rekey interval by ±30% of the base value
        base_interval = self.config["rekey_interval"]
        variation = round(base_interval * 0.3)
        self.rekey_interval: int = base_interval + (secrets.randbelow(variation + 1) - variation)
    
    def has_active_file_transfers(self) -> bool:
        # Set in __init__ of the file handler.
        ...
    
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
        # Clear file transfer state as well
        
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
    
    def generate_keys(self) -> bytes:
        """Generate ML-KEM keypair for key exchange."""
        self.mlkem_public_key, self._mlkem_private_key = ml_kem_1024.generate_keypair()
        self._dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key_bytes = self._dh_private_key.public_key().public_bytes_raw()
        self.hqc_public_key, self._hqc_private_key = hqc_256.generate_keypair()
        return self.mlkem_public_key
    
    def _derive_keys(self, shared_secret: bytes) -> bytes:
        """Derive encryption and MAC keys from shared secret using HKDF."""
        # Sort public keys lexicographically for deterministic order
        keys = sorted([self.mlkem_public_key, self.peer_mlkem_public_key])
        combined_keys = keys[0] + keys[1]
        salt = hashlib.sha512(combined_keys + b"verification_key_salt").digest()[:32]
        
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                info=b"derive_root_mac_keys",
        )
        derived = hkdf.derive(shared_secret)
        
        # Initialize chain keys for perfect forward secrecy
        self._initialize_chain_keys(shared_secret)
        
        return derived
    
    def _initialize_chain_keys(self, shared_secret: bytes) -> None:
        """Initialize separate chain keys for sending and receiving."""
        # Sort public keys lexicographically for deterministic order
        keys = sorted([self.mlkem_public_key, self.peer_mlkem_public_key, self.dh_public_key_bytes,
                       self.peer_dh_public_key_bytes, self.hqc_public_key, self.peer_hqc_public_key])
        combined_keys = b''.join(keys)
        salt = hashlib.sha512(combined_keys + b"chain_key_salt").digest()
        
        # Derive a root chain key that both parties will use as the starting point
        chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=salt,
                info=b"chain_key_root",
        )
        
        root_chain_key = chain_hkdf.derive(shared_secret)
        
        # Both send and receive chain keys start with the same value
        # They will diverge as messages are sent and received
        self._send_chain_key = root_chain_key
        self._receive_chain_key = root_chain_key
    
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
    
    @staticmethod
    def _derive_keys_and_chain(shared_secret: bytes, own_pub: bytes = b"", peer_pub: bytes = b"") -> tuple[bytes, bytes]:
        """Derive encryption key, MAC key, and root chain key from a shared secret without mutating state."""
        # Sort public keys lexicographically for deterministic order (if available)
        if own_pub and peer_pub:
            keys = sorted([own_pub, peer_pub])
            combined_keys = keys[0] + keys[1]
        else:
            combined_keys = b""
        
        enc_salt = hashlib.sha512(combined_keys + b"enc_key_salt").digest()[:32]
        chain_salt = hashlib.sha512(combined_keys + b"chain_salt").digest()[:32]
        
        # Derive encryption and MAC keys
        hkdf_keys = HKDF(
                algorithm=hashes.SHA3_512(),
                length=32,
                salt=enc_salt,
                info=b"key_derivation",
        )
        derived = hkdf_keys.derive(shared_secret)
        
        # Derive root chain key
        hkdf_chain = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=chain_salt,
                info=b"chain_key_root",
        )
        root_chain_key = hkdf_chain.derive(shared_secret)
        return derived, root_chain_key
    
    def get_own_key_fingerprint(self) -> str:
        """
        Generate a consistent fingerprint for the session that both users will see.
        Includes both ML-KEM public keys and the ephemeral X25519 DH public keys from the key exchange.
        """
        # Ensure we have all required key materials
        if not all([self.mlkem_public_key, self.peer_mlkem_public_key, self.dh_public_key_bytes,
                    self.peer_dh_public_key_bytes, self.hqc_public_key, self.peer_hqc_public_key]):
            if not self.mlkem_public_key:
                raise ValueError("Own ML-KEM public key not available")
            if not self.peer_mlkem_public_key:
                raise ValueError("Peer ML-KEM public key not available")
            if not self.dh_public_key_bytes:
                raise ValueError("Own DH public key bytes not available")
            if not self.peer_dh_public_key_bytes:
                raise ValueError("Peer DH public key bytes not available")
            if not self.hqc_public_key:
                raise ValueError("Own HQC public key not available")
            if not self.peer_hqc_public_key:
                raise ValueError("Peer HQC public key not available")
        
        # Build a deterministic, order-independent combination of all four keys
        components: list[bytes] = [
            self.mlkem_public_key,
            self.peer_mlkem_public_key,
            self.dh_public_key_bytes,
            self.peer_dh_public_key_bytes,
            self.hqc_public_key,
            self.peer_hqc_public_key,
        ]
        # Sort lexicographically to make result independent of initiator/responder roles
        components.sort()
        combined = b"".join(components)
        
        # Generate fingerprint from combined keys
        return generate_key_fingerprint(combined, self.config["wordlist_file"])
    
    @staticmethod
    def create_key_verification_message(verified: bool) -> bytes:
        """Create a key verification status message."""
        return create_key_verification_message(verified)
    
    @staticmethod
    def process_key_verification_message(data: bytes) -> bool:
        """Process a key verification message from peer."""
        return process_key_verification_message(data)
    
    def create_key_exchange_init(self, public_key: bytes) -> bytes:
        """Create initial key exchange message with X25519 DH public key."""
        return create_key_exchange_init(public_key, self.dh_public_key_bytes, self.hqc_public_key)
    
    def create_key_exchange_response(self, mlkem_ciphertext: bytes, hqc_ciphertext: bytes) -> bytes:
        """Create key exchange response message including our X25519 DH public key, mlkem and hqc ciphertext, and pk"""
        return create_key_exchange_response(
                mlkem_ciphertext, hqc_ciphertext,
                self.mlkem_public_key, self.hqc_public_key, self.dh_public_key_bytes)
    
    @staticmethod
    def _derive_combined_shared_secret(kem_shared: bytes, dh_shared: bytes) -> bytes:
        """Combine a KEM shared secret and an X25519 DH shared secret via HKDF-SHA512.

        The KEM secret is used as the HKDF salt so that both inputs contribute
        to the output with independent roles, following hybrid KEM best practices.

        Args:
            kem_shared: The shared secret produced by ML-KEM encapsulation/decapsulation.
            dh_shared:  The shared secret produced by the X25519 key exchange.

        Returns:
            32 bytes of derived key material.
        """
        return HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=kem_shared,
                info=b"hybrid kem+x25519",
        ).derive(dh_shared)
    
    def process_key_exchange_init(self, data: bytes) -> tuple[bytes, bytes, str]:
        """Process initial key exchange and return HQC ciphertext, KEM ciphertext, and version warning if any.
        
        Returns:
            tuple: (hqc_ciphertext, mlkem_ciphertext, warning_message)
                  warning_message is "" if protocol versions match
        """
        parsed = parse_key_exchange_init(data)
        
        self.peer_version = parsed["peer_version"]
        kem_public_key = parsed["mlkem_public_key"]
        peer_dh_pub_bytes = parsed["dh_public_key"]
        hqc_public_key = parsed["hqc_public_key"]
        version_warning = parsed["version_warning"]
        
        # Store peer's KEM public key for verification
        self.peer_mlkem_public_key = kem_public_key
        self.peer_hqc_public_key = hqc_public_key
        # Store peer's DH public key for fingerprinting/verification context
        self.peer_dh_public_key_bytes = peer_dh_pub_bytes
        
        # Generate our own KEM keypair if we don't have one yet (for verification purposes)
        if not self.mlkem_public_key or not self.hqc_public_key:
            self.generate_keys()
        
        # Generate our ephemeral X25519 keypair for DH and compute DH shared secret
        self._dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key_bytes = self._dh_private_key.public_key().public_bytes_raw()
        peer_dh_pub = X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)
        dh_shared_secret = self._dh_private_key.exchange(peer_dh_pub)
        
        # Perform KEM encapsulation to obtain KEM shared secret and ciphertext to send back
        mlkem_ciphertext, kem_shared_secret = ml_kem_1024.encrypt(kem_public_key)
        hqc_ciphertext, self._hqc_secret = hqc_256.encrypt(hqc_public_key)
        
        # Combine secrets
        combined_shared = self._derive_combined_shared_secret(kem_shared_secret, dh_shared_secret)
        
        # Derive keys from combined shared secret
        self._verification_key = self._derive_keys(combined_shared)
        self.shared_key = True
        
        # Initialise message-phase Double Ratchet baseline
        self._msg_recv_private = self._dh_private_key
        self.msg_peer_base_public = self.peer_dh_public_key_bytes
        
        return hqc_ciphertext, mlkem_ciphertext, version_warning
    
    def process_key_exchange_response(self, data: bytes) -> str | None:
        """Process key exchange response and derive combined shared key using KEM ⊕ X25519 DH.
        
        Returns:
            tuple: (combined_shared_secret, warning_message)
                  warning_message is None if protocol versions match
        
        Raises:
            DecodeError: Something was wrong with the received data
        """
        parsed = parse_key_exchange_response(data)
        
        mlkem_ciphertext = parsed["mlkem_ciphertext"]
        self.peer_mlkem_public_key = parsed["mlkem_public_key"]
        hqc_ciphertext = parsed["hqc_ciphertext"]
        self.peer_hqc_public_key = parsed["hqc_public_key"]
        peer_dh_pub_bytes = parsed["dh_public_key"]
        version_warning = parsed["version_warning"]
        
        # Store peer's DH public key for fingerprinting/verification context
        self.peer_dh_public_key_bytes = peer_dh_pub_bytes
        if not self._dh_private_key:
            raise ValueError("Local DH private key not initialized for key exchange response")
        peer_dh_pub = X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)
        dh_shared_secret = self._dh_private_key.exchange(peer_dh_pub)
        
        kem_shared_secret = ml_kem_1024.decrypt(self._mlkem_private_key, mlkem_ciphertext)
        combined_shared = self._derive_combined_shared_secret(kem_shared_secret, dh_shared_secret)
        self._hqc_secret = hqc_256.decrypt(self._hqc_private_key, hqc_ciphertext)
        
        # Derive keys from combined shared secret
        self._verification_key = self._derive_keys(combined_shared)
        self.shared_key = True
        
        # Initialize message-phase Double Ratchet baseline
        self._msg_recv_private = self._dh_private_key
        self.msg_peer_base_public = self.peer_dh_public_key_bytes
        
        return version_warning
    
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
        encryptor = DoubleEncryptor(message_key, self._hqc_secret, message_counter=self.message_counter)
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
        decryptor = DoubleEncryptor(message_key, self._hqc_secret, counter)
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
        encryptor = DoubleEncryptor(message_key, self._hqc_secret, self.message_counter)
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
        decryptor = DoubleEncryptor(message_key, self._hqc_secret, counter)
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
        # Activate HQC secret if present
        if self._pending_hqc_secret:
            self._hqc_secret = self._pending_hqc_secret
        # Clear pending state
        self._pending_shared_key = b""
        self._pending_encryption_key = b""
        self._pending_send_chain_key = b""
        self._pending_receive_chain_key = b""
        self._pending_hqc_secret = b""
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        # Clear rekey ephemeral keys
        self._rekey_mlkem_private_key = b""
        self._rekey_hqc_private_key = b""
        self._rekey_dh_private = None
        self.rekey_dh_public = None
        self.rekey_dh_public_bytes = b""
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
        self.rekey_dh_public_bytes = dh_public.public_bytes_raw()
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
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        self.rekey_in_progress = True
        return create_rekey_commit_message()
