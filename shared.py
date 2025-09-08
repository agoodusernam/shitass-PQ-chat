# shared.py - Shared cryptographic utilities and protocol definitions
# pylint: disable=trailing-whitespace, line-too-long
import base64
import os
import json
import socket
import struct
import hashlib
import shutil
import gzip
import io
from io import BufferedRandom
import threading
import time
import random
from collections import deque
from enum import IntEnum
from typing import Final
from collections.abc import Generator

try:
    from kyber_py.ml_kem import ML_KEM_1024
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Required cryptographic libraries not found.")
    raise ImportError("Please install the required libraries with pip install -r requirements.txt")
# Protocol constants
PROTOCOL_VERSION: Final[float] = 2.1


class MessageType(IntEnum):
    """Enumeration of all message types used in the secure chat protocol."""
    KEY_EXCHANGE_INIT = 1
    KEY_EXCHANGE_RESPONSE = 2
    ENCRYPTED_MESSAGE = 3
    ERROR = 4
    KEY_VERIFICATION = 5
    FILE_METADATA = 6
    FILE_ACCEPT = 7
    FILE_REJECT = 8
    FILE_CHUNK = 9
    FILE_COMPLETE = 10
    KEY_EXCHANGE_RESET = 11
    KEEP_ALIVE = 12
    KEEP_ALIVE_RESPONSE = 13
    DELIVERY_CONFIRMATION = 14
    EMERGENCY_CLOSE = 15
    INITIATE_KEY_EXCHANGE = 16
    SERVER_FULL = 17
    KEY_EXCHANGE_COMPLETE = 18
    SERVER_VERSION_INFO = 19
    DUMMY_MESSAGE = 20
    EPHEMERAL_MODE_CHANGE = 21
    DUMMY_DELIVERY_CONFIRMATION = 22


# File transfer constants
SEND_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB chunks for sending

# Maps protocol versions to compatible versions for key exchange and message processing
# Some features may be limited when using older versions
PROTOCOL_COMPATIBILITY: Final[dict[float, list[float]]] = {
    1: [1],
    2: [2, 2.1],
    2.1: [2, 2.1],
}


def bytes_to_human_readable(size: int) -> str:
    """Convert a byte count to a human-readable format with appropriate units.
    
    Args:
        size (int): The number of bytes to convert.
        
    Returns:
        str: A formatted string with the size and appropriate unit (B, KB, MB, or GB).
        
    """
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    if size < 1024 ** 3:
        return f"{size / 1024 ** 2:.1f} MB"
    
    return f"{size / 1024 ** 3:.1f} GB"


class StreamingGzipCompressor:
    """A streaming gzip compressor that yields compressed chunks as they're ready."""
    
    def __init__(self):
        self.buffer = io.BytesIO()
        self.compressor = gzip.GzipFile(fileobj=self.buffer, mode='wb', compresslevel=9)
    
    def compress_chunk(self, data: bytes) -> bytes:
        """Compress a chunk of data and return any available compressed output."""
        if data:
            self.compressor.write(data)
        
        # Get any compressed data that's ready
        self.buffer.seek(0)
        compressed_data = self.buffer.read()
        
        # Reset buffer for next chunk
        self.buffer.seek(0)
        self.buffer.truncate(0)
        
        return compressed_data
    
    def finalize(self) -> bytes:
        """Finalize compression and return any remaining compressed data."""
        self.compressor.close()
        
        # Get any remaining compressed data
        self.buffer.seek(0)
        final_data = self.buffer.read()
        self.buffer.close()
        
        return final_data


# noinspection PyBroadException
class SecureChatProtocol:
    """
    SecureChatProtocol - Implements the cryptographic protocol for secure chat using ML-KEM and AES-GCM.
    """
    
    # noinspection PyUnresolvedReferences
    def __init__(self) -> None:
        """Initialize the secure chat protocol with default cryptographic state.
        
        Sets up all necessary state variables for the ML-KEM-1024 key exchange,
        AES-GCM encryption, perfect forward secrecy, replay protection, and
        file transfer functionality.
        
        Attributes:
            shared_key (bytes | None): The derived shared secret from key exchange.
            message_counter (int): Counter for outgoing messages (for PFS).
            peer_counter (int): Expected counter for incoming messages (for PFS).
            peer_public_key (bytes | None): The peer's public key from key exchange.
            peer_key_verified (bool): Whether the peer's key has been verified.
            own_public_key (bytes | None): This client's public key.
            private_key (bytes | None): This client's private key for key exchange.
            chain_key (bytes | None): Root key for perfect forward secrecy ratcheting.
            seen_counters (set): Set of seen message counters for replay protection.
            file_transfers (dict): Dictionary tracking ongoing file transfers.
            received_chunks (dict): Buffer for received file chunks during transfer.
        """
        self.mac_key: bytes
        self.encryption_key: bytes
        self.shared_key: bytes | None = None
        self.message_counter: int = 0
        self.peer_counter: int = 0
        self.peer_public_key: bytes | None = None
        self.peer_key_verified = False
        self.own_public_key: bytes | None = None
        self.private_key: bytes | None = None  # Initialize private key properly
        # Perfect Forward Secrecy - Key Ratcheting
        self.send_chain_key: bytes | None = None  # For encrypting outgoing messages
        self.receive_chain_key: bytes | None = None  # For decrypting incoming messages
        self.seen_counters: set[int] = set()  # Track seen counters for replay protection
        
        # File transfer state
        self.file_transfers: dict[str, dict] = {}  # Track ongoing file transfers
        self.received_chunks: dict[str, set[int]] = {}  # Track received chunk indices (set of indices per transfer)
        self.temp_file_paths: dict[str, str] = {}  # Track temporary file paths for receiving chunks
        self.open_file_handles: dict[str, BufferedRandom] = {}  # Track open file handles for active transfers
        self.sending_transfers: dict[str, dict] = {}  # Track outgoing file transfers
        
        # Message queuing system for traffic analysis prevention
        self.message_queue: deque = deque()  # FIFO queue for outgoing messages
        self.socket: socket.socket | None = None  # Socket reference for sending messages
        self.sender_thread: threading.Thread | None = None  # Background thread for sending messages
        self.sender_running: bool = False  # Flag to control sender thread
        self.sender_lock: threading.Lock = threading.Lock()  # Lock for thread-safe queue operations
        
        self.send_dummy_messages: bool = True
    
    def reset_key_exchange(self) -> None:
        """Reset all cryptographic state to initial values for key exchange restart."""
        # Stop sender thread if running
        self.stop_sender_thread()
        
        self.shared_key = None
        self.message_counter = 0
        self.peer_counter = 0
        self.peer_public_key = None
        self.peer_key_verified = False
        self.own_public_key = None
        self.send_chain_key = None
        self.receive_chain_key = None
        self.seen_counters = set()
        # Clear file transfer state as well
        self.file_transfers = {}
        self.received_chunks = {}
        
        # Clear message queue
        with self.sender_lock:
            self.message_queue.clear()
        
        # Close any open file handles
        for file_handle in self.open_file_handles.values():
            try:
                file_handle.close()
            except:
                pass  # Ignore errors closing file handles; they may already be closed.
                # If they are still open, the OS will close them eventually.
        self.open_file_handles = {}
        
        # Clean up any temporary files
        for temp_path in self.temp_file_paths.values():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except:
                pass  # Don't really care if it fails to delete, it's a temporary file.
                # The OS should clean up the files eventually on its own either way.
        self.temp_file_paths = {}
        self.sending_transfers = {}
    
    def start_sending_transfer(self, transfer_id: str, metadata: dict) -> None:
        """Start tracking a sending file transfer."""
        self.sending_transfers[transfer_id] = metadata
    
    def stop_sending_transfer(self, transfer_id: str) -> None:
        """Stop tracking a sending file transfer."""
        if transfer_id in self.sending_transfers:
            del self.sending_transfers[transfer_id]
    
    def has_active_file_transfers(self) -> bool:
        """Check if any file transfers (sending or receiving) are currently active."""
        # Check for active receiving transfers
        if self.received_chunks or self.open_file_handles:
            return True
        
        # Check for active sending transfers
        if self.sending_transfers:
            return True
        
        return False
    
    def start_sender_thread(self, socket) -> None:
        """Start the background sender thread for message queuing."""
        if self.sender_thread is not None and self.sender_thread.is_alive():
            return  # Thread already running
        
        self.socket = socket
        self.sender_running = True
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.sender_thread.start()
    
    def stop_sender_thread(self) -> None:
        """Stop the background sender thread."""
        self.sender_running = False
        if self.sender_thread is not None and self.sender_thread.is_alive():
            self.sender_thread.join(timeout=1.0)  # Wait up to 1 second for thread to stop
        self.sender_thread = None
        self.socket = None
    
    def queue_message(self, message) -> None:
        """Add a message to the send queue.
        
        The message can be one of the following:
        - bytes: already-prepared data to send as-is (control or pre-encrypted)
        - str: plaintext to be encrypted and sent
        - dict: JSON-serializable object to be encrypted and sent
        - tuple: instruction for the sender loop, supported forms:
            ("encrypt_text", str)
            ("encrypt_json", dict)
            ("file_chunk", transfer_id: str, chunk_index: int, chunk_data: bytes)
            ("plaintext", bytes)  # send as-is (control)
            ("encrypted", bytes)  # send as-is (already encrypted)
        """
        with self.sender_lock:
            self.message_queue.append(message)
    
    def send_emergency_close(self) -> bool:
        """Send an emergency close message immediately, bypassing the queue.
        
        Behavior:
            - If encryption is ready, encrypt immediately and send over the socket.
            - If encryption is not ready, send plaintext immediately.
        
        Returns:
            bool: True if the message was sent successfully, False otherwise.
        """
        try:
            if not self.socket:
                return False
            emergency_message = {
                "version": PROTOCOL_VERSION,
                "type":    MessageType.EMERGENCY_CLOSE,
            }
            if self.shared_key and self.send_chain_key:
                # Encrypt immediately using normal ratcheting
                encrypted = self.encrypt_message(json.dumps(emergency_message))
                send_message(self.socket, encrypted)
            else:
                # Fall back to plaintext immediate send
                send_message(self.socket, json.dumps(emergency_message).encode('utf-8'))
            return True
        except Exception:
            return False
    
    def _generate_dummy_message(self) -> bytes:
        """Generate a dummy message with random data between 24-1536 bytes."""
        # Generate random data between 24 and 1536 bytes
        data_size = random.randint(24, 1536)
        dummy_data = os.urandom(data_size)
        
        # Create a JSON message with DUMMY_MESSAGE type
        dummy_message = {
            "type": MessageType.DUMMY_MESSAGE,
            "data": base64.b64encode(dummy_data).decode('utf-8')
        }
        
        # Convert to JSON string for encrypt_message (it expects a string)
        dummy_text = json.dumps(dummy_message)
        
        # Encrypt the dummy message like a real message
        return self.encrypt_message(dummy_text)
    
    def _sender_loop(self) -> None:
        """Background thread loop that sends messages every 500ms.
        
        This loop is responsible for performing encryption for all queued
        non-control messages before sending them over the socket.
        Control messages (key exchange, explicit plaintext items) are sent as-is.
        """
        while self.sender_running:
            try:
                item = None
                
                # Check if there's a message in the queue
                with self.sender_lock:
                    if self.message_queue:
                        item = self.message_queue.popleft()
                
                # If no real message, generate a dummy message
                # Skip dummy messages during file transfers
                if item is None and self.send_dummy_messages and not self.has_active_file_transfers():
                    if self.shared_key and self.send_chain_key:  # Only send dummy if encryption is ready
                        try:
                            item = self._generate_dummy_message()  # already encrypted bytes
                        except Exception:
                            # If dummy message generation fails, skip this cycle
                            pass
                
                # Resolve the queue item into bytes to send
                to_send: bytes | None = None
                if item is not None:
                    try:
                        # Already bytes -> send as-is
                        if isinstance(item, (bytes, bytearray)):
                            to_send = bytes(item)
                        # Plaintext string -> encrypt
                        elif isinstance(item, str):
                            if self.shared_key and self.send_chain_key:
                                to_send = self.encrypt_message(item)
                        # JSON object -> encrypt
                        elif isinstance(item, dict):
                            if self.shared_key and self.send_chain_key:
                                to_send = self.encrypt_message(json.dumps(item))
                        # Instruction tuple
                        elif isinstance(item, tuple) and item:
                            kind = item[0]
                            if kind == "encrypt_text" and len(item) >= 2:
                                text = item[1]
                                if isinstance(text, str) and self.shared_key and self.send_chain_key:
                                    to_send = self.encrypt_message(text)
                            elif kind == "encrypt_json" and len(item) >= 2:
                                obj = item[1]
                                if isinstance(obj, dict) and self.shared_key and self.send_chain_key:
                                    to_send = self.encrypt_message(json.dumps(obj))
                            elif kind == "file_chunk" and len(item) >= 4:
                                transfer_id, chunk_index, chunk_data = item[1], item[2], item[3]
                                if isinstance(transfer_id, str) and isinstance(chunk_index, int) and isinstance(chunk_data, (bytes, bytearray)):
                                    to_send = self.create_file_chunk_message(transfer_id, chunk_index, bytes(chunk_data))
                            elif kind in ("plaintext", "encrypted") and len(item) >= 2:
                                data = item[1]
                                if isinstance(data, (bytes, bytearray)):
                                    to_send = bytes(data)
                    except Exception:
                        # If preparing this item fails, drop it and continue
                        to_send = None
                
                # Send the message if we have one and a socket
                if to_send is not None and self.socket is not None:
                    try:
                        send_message(self.socket, to_send)
                    except Exception:
                        # If sending fails, the connection is likely broken
                        # The main thread will handle reconnection
                        pass
                
                # Wait 500ms before next cycle
                time.sleep(0.5)
            
            except Exception:
                # Continue running even if there's an unexpected error
                time.sleep(0.5)
    
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate ML-KEM keypair for key exchange."""
        public_key, private_key = ML_KEM_1024.keygen()
        self.own_public_key = public_key
        return public_key, private_key
    
    def derive_keys(self, shared_secret: bytes) -> tuple[bytes, bytes]:
        """Derive encryption and MAC keys from shared secret using HKDF."""
        # Derive 64 bytes: 32 for AES-GCM, 32 for HMAC
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=b"ReallyCoolAndSecureSalt",
                info=b"key_derivation"
        )
        derived = hkdf.derive(shared_secret)
        
        # Initialize chain keys for perfect forward secrecy
        self._initialize_chain_keys(shared_secret)
        
        return derived[:len(derived) // 2], derived[len(derived) // 2:]  # encryption_key, mac_key
    
    def _initialize_chain_keys(self, shared_secret: bytes) -> None:
        """Initialize separate chain keys for sending and receiving."""
        # Derive a root chain key that both parties will use as the starting point
        chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=b"ReallyCoolAndSecureSalt",
                info=b"chain_key_root"
        )
        
        root_chain_key = chain_hkdf.derive(shared_secret)
        
        # Both send and receive chain keys start with the same value
        # They will diverge as messages are sent and received
        self.send_chain_key = root_chain_key
        self.receive_chain_key = root_chain_key
        return None
    
    @staticmethod
    def _derive_message_key(chain_key: bytes, counter: int) -> bytes:
        """Derive a message key from the chain key and counter."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=b"ReallyCoolAndSecureSalt",
                info=f"message_key_{counter}".encode()
        )
        return hkdf.derive(chain_key)[:32]
    
    @staticmethod
    def _ratchet_chain_key(chain_key: bytes, counter: int) -> bytes:
        """Advance the chain key (ratchet forward)."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=b"ReallyCoolAndSecureSalt",
                info=f"chain_key_{counter}".encode()
        )
        return hkdf.derive(chain_key)
    
    def generate_key_fingerprint(self, public_key: bytes) -> str:
        """Generate a human-readable word-based fingerprint for a public key."""
        # Create SHA-256 hash of the public key
        key_hash = hashlib.sha3_256(public_key).digest()
        
        # Load the wordlist
        wordlist = self._load_wordlist()
        
        # Convert hash to word-based fingerprint
        words = self._hash_to_words(key_hash, wordlist, num_words=20)
        
        # Format the words in a user-friendly way
        # Display 5 words per line for better readability
        msg = "\n"
        for i in range(0, len(words), 5):
            msg += " ".join(words[i:i + 5]) + "\n"
        
        return msg.strip()
    
    @staticmethod
    def _load_wordlist() -> list:
        """Load the EFF large wordlist."""
        try:
            wordlist_path = os.path.join(os.path.dirname(__file__), 'eff_large_wordlist.txt')
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback if wordlist file is not found
            raise FileNotFoundError(
                "eff_large_wordlist.txt not found. Please ensure the wordlist file is in the same directory as shared.py")
    
    @staticmethod
    def _hash_to_words(hash_bytes: bytes, wordlist: list, num_words: int = 20) -> list:
        """Convert hash bytes to a list of words from the wordlist."""
        # Convert hash to integer for easier manipulation
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        
        words = []
        for i in range(num_words):
            index = (hash_int >> (i * 8)) % len(wordlist)
            words.append(wordlist[index])
        
        return words
    
    def get_own_key_fingerprint(self) -> str:
        """Get the consistent session fingerprint (same for both users)."""
        if not self.own_public_key or not self.peer_public_key:
            raise ValueError("Both public keys must be available for fingerprint generation")
        return self.generate_session_fingerprint()
    
    def get_peer_key_fingerprint(self) -> str:
        """Get the consistent session fingerprint (same for both users)."""
        if not self.own_public_key or not self.peer_public_key:
            raise ValueError("Both public keys must be available for fingerprint generation")
        return self.generate_session_fingerprint()
    
    def generate_session_fingerprint(self) -> str:
        """Generate a consistent fingerprint for the session that both users will see."""
        if not self.own_public_key or not self.peer_public_key:
            raise ValueError("Both public keys must be available")
        
        # Create a deterministic combination of both keys
        # Sort the keys to ensure consistent ordering regardless of who is "own" vs "peer"
        key1 = self.own_public_key
        key2 = self.peer_public_key
        
        # Sort keys lexicographically to ensure consistent ordering
        if key1 > key2:
            combined_keys = key2 + key1
        else:
            combined_keys = key1 + key2
        
        # Generate fingerprint from combined keys
        return self.generate_key_fingerprint(combined_keys)
    
    def verify_peer_key(self, user_confirmed: bool):
        """Mark peer's key as verified or unverified based on user confirmation."""
        self.peer_key_verified = user_confirmed
    
    def is_peer_key_verified(self) -> bool:
        """Check if peer's key has been verified."""
        return self.peer_key_verified
    
    def create_key_verification_message(self, verified: bool) -> bytes:
        """Create a key verification status message."""
        message = {
            "version":             PROTOCOL_VERSION,
            "type":                MessageType.KEY_VERIFICATION,
            "verified":            verified,
            "own_key_fingerprint": self.get_own_key_fingerprint() if self.own_public_key else ""
        }
        return json.dumps(message).encode('utf-8')
    
    @staticmethod
    def process_key_verification_message(data: bytes) -> dict:
        """Process a key verification message from peer."""
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MessageType.KEY_VERIFICATION:
                raise ValueError("Invalid message type")
            
            return {
                "verified":         message.get("verified", False),
                "peer_fingerprint": message.get("own_key_fingerprint", "")
            }
        except Exception as e:
            raise ValueError(f"Key verification message processing failed: {e}")
    
    def should_allow_communication(self) -> tuple[bool, str]:
        """Check if communication should be allowed based on verification status."""
        if not self.shared_key:
            return False, "No shared key established"
        
        if not self.peer_key_verified:
            return True, "WARNING: Peer's key is not verified - communication may not be secure!"
        
        return True, "Secure communication established with verified peer"
    
    @staticmethod
    def create_key_exchange_init(public_key: bytes) -> bytes:
        """Create initial key exchange message."""
        message = {
            "version":    PROTOCOL_VERSION,
            "type":       MessageType.KEY_EXCHANGE_INIT,
            "public_key": base64.b64encode(public_key).decode('utf-8')
        }
        return json.dumps(message).encode('utf-8')
    
    def create_key_exchange_response(self, ciphertext: bytes) -> bytes:
        """Create key exchange response message."""
        message = {
            "version":    PROTOCOL_VERSION,
            "type":       MessageType.KEY_EXCHANGE_RESPONSE,
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "public_key": base64.b64encode(self.own_public_key).decode('utf-8') if self.own_public_key else ""
        }
        return json.dumps(message).encode('utf-8')
    
    def process_key_exchange_init(self, data: bytes) -> tuple[bytes, bytes, str | None]:
        """Process initial key exchange and return shared key, response ciphertext, and version warning if any.
        
        Returns:
            tuple: (shared_secret, ciphertext, warning_message)
                  warning_message is None if protocol versions match
        """
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MessageType.KEY_EXCHANGE_INIT:
                raise ValueError("Invalid message type")
            
            # Check protocol version
            peer_version = message.get("version")
            version_warning = None
            if peer_version is not None and peer_version != PROTOCOL_VERSION:
                version_warning = f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: {peer_version}. Communication may not work properly."
            
            public_key = base64.b64decode(message["public_key"])
            # Store peer's public key for verification
            self.peer_public_key = public_key
            
            # Generate our own keypair if we don't have one yet
            # This ensures the second client has its own public key for verification
            if not self.own_public_key:
                self.own_public_key, self.own_private_key = self.generate_keypair()
            
            shared_secret, ciphertext = ML_KEM_1024.encaps(public_key)
            
            # Derive keys from shared secret
            self.encryption_key, self.mac_key = self.derive_keys(shared_secret)
            self.shared_key = shared_secret
            
            return shared_secret, ciphertext, version_warning
        except Exception as e:
            raise ValueError(f"Key exchange init failed: {e}")
    
    def process_key_exchange_response(self, data: bytes, private_key: bytes) -> tuple[bytes, str | None]:
        """Process key exchange response and derive shared key.
        
        Returns:
            tuple: (shared_secret, warning_message)
                  warning_message is None if protocol versions match
        """
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MessageType.KEY_EXCHANGE_RESPONSE:
                raise ValueError("Invalid message type")
            
            # Check protocol version
            peer_version = message.get("version")
            version_warning = None
            if peer_version is not None and peer_version != PROTOCOL_VERSION:
                version_warning = f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: {peer_version}. Communication may not work properly."
            
            ciphertext = base64.b64decode(message["ciphertext"])
            # Store peer's public key for verification
            if "public_key" in message and message["public_key"]:
                self.peer_public_key = base64.b64decode(message["public_key"])
            
            shared_secret = ML_KEM_1024.decaps(private_key, ciphertext)
            
            # Derive keys from shared secret
            self.encryption_key, self.mac_key = self.derive_keys(shared_secret)
            self.shared_key = shared_secret
            
            return shared_secret, version_warning
        except Exception as e:
            raise ValueError(f"Key exchange response failed: {e}")
    
    
    def encrypt_message(self, plaintext: str) -> bytes:
        """Encrypt a message with authentication and replay protection using perfect forward secrecy."""
        if not self.shared_key or not self.send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        self.message_counter += 1
        
        # Derive unique message key for this message
        message_key = self._derive_message_key(self.send_chain_key, self.message_counter)
        
        # Ratchet the send chain key forward for the next message
        self.send_chain_key = self._ratchet_chain_key(self.send_chain_key, self.message_counter)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Add padding to prevent message size analysis
        # Pad to next KiB boundary (1KiB, 2KiB, 3KiB, etc.)
        kib = 1024
        current_size = len(plaintext_bytes)
        current_kib = (current_size + kib - 1) // kib  # Ceiling division
        target_size = current_kib * kib
        if target_size == current_size:
            target_size += kib  # If already at boundary, go to next KiB
        
        padding_needed = target_size - current_size
        # Use null bytes for padding (will be removed during decryption)
        padded_plaintext = plaintext_bytes + b'\x00' * padding_needed
        
        # Create AAD from message metadata for authentication
        nonce: bytes = os.urandom(12)
        aad_data = {
            "type":    MessageType.ENCRYPTED_MESSAGE,
            "counter": self.message_counter,
            "nonce":   base64.b64encode(nonce).decode('utf-8')
        }
        aad = json.dumps(aad_data, sort_keys=True).encode('utf-8')
        
        # Encrypt with AES-GCM using the unique message key and AAD
        aesgcm: AESGCM = AESGCM(message_key)
        
        ciphertext: bytes = aesgcm.encrypt(nonce, padded_plaintext, aad)
        
        # Securely delete the message key
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Create authenticated message
        encrypted_message = {
            "type":       MessageType.ENCRYPTED_MESSAGE,
            "counter":    self.message_counter,
            "nonce":      base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        
        return json.dumps(encrypted_message).encode('utf-8')
    
    def decrypt_message(self, data: bytes) -> str:
        """Decrypt and authenticate a message using perfect forward secrecy with proper state management."""
        if not self.shared_key or not self.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MessageType.ENCRYPTED_MESSAGE:
                raise ValueError("Invalid message type")
            
            nonce = base64.b64decode(message["nonce"])
            ciphertext = base64.b64decode(message["ciphertext"])
            counter = message["counter"]
            
            # Check for replay attacks or very old messages
            if counter <= self.peer_counter:
                raise ValueError(
                        f"Replay attack or out-of-order message detected. Expected > {self.peer_counter}, got {counter}")
            
            temp_chain_key = self.receive_chain_key
            for i in range(self.peer_counter + 1, counter):
                temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
            
            # Derive the message key for the current message
            message_key = self._derive_message_key(temp_chain_key, counter)
            
            # Calculate what the new chain key state WOULD be
            new_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
            
            # Create AAD from message metadata for authentication verification
            aad_data = {
                "type":    MessageType.ENCRYPTED_MESSAGE,
                "counter": counter,
                "nonce":   base64.b64encode(nonce).decode('utf-8')
            }
            aad = json.dumps(aad_data, sort_keys=True).encode('utf-8')
            
            # Decrypt with the derived message key and verify AAD
            aesgcm = AESGCM(message_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, aad)
            
            # Remove padding (null bytes) that was added during encryption
            # Find the first null byte and truncate there
            null_index = decrypted_data.find(b'\x00')
            if null_index != -1:
                decrypted_data = decrypted_data[:null_index]
            
            self.receive_chain_key = new_chain_key
            self.peer_counter = counter
            
            # Securely delete the message key
            message_key = b'\x00' * len(message_key)
            del message_key
            
            return decrypted_data.decode('utf-8')
        
        except ValueError as e:
            raise e
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    # High-level wrapper methods for GUI client compatibility
    def initiate_key_exchange(self) -> bytes:
        """Initiate key exchange by generating keypair and creating init message."""
        # Generate keypair and store private key
        public_key, self.private_key = self.generate_keypair()
        
        # Create key exchange init message
        return self.create_key_exchange_init(public_key)
    
    def handle_key_exchange_init(self, message_data: bytes) -> bytes:
        """Handle key exchange initiation from peer and return response."""
        # Process the init message and get shared secret + ciphertext
        _, ciphertext, _ = self.process_key_exchange_init(message_data)
        
        # Create and return the response message
        return self.create_key_exchange_response(ciphertext)
    
    def handle_key_exchange_response(self, message_data: bytes) -> bytes:
        """Handle key exchange response from peer and return completion message."""
        if self.private_key is None:
            raise ValueError("No private key available for key exchange response")
        
        # Process the response to get shared secret
        self.process_key_exchange_response(message_data, self.private_key)
        
        # Create completion message
        complete_message = {
            "version": PROTOCOL_VERSION,
            "type":    "key_exchange_complete"
        }
        return json.dumps(complete_message).encode('utf-8')
    
    def start_key_verification(self) -> bytes:
        """Start key verification process and return verification request."""
        if not self.shared_key:
            raise ValueError("No shared key established for verification")
        
        # Generate session fingerprint words
        session_fingerprint = self.generate_session_fingerprint()
        words = session_fingerprint.split()
        
        # Create verification request message
        verification_request = {
            "version":           PROTOCOL_VERSION,
            "type":              MessageType.KEY_VERIFICATION,
            "verification_type": "verification_request",
            "words":             words
        }
        return json.dumps(verification_request).encode('utf-8')
    
    def handle_key_verification_message(self, message_data: bytes) -> dict:
        """Handle key verification message and return verification info."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            
            if message["type"] != MessageType.KEY_VERIFICATION:
                raise ValueError("Invalid message type for key verification")
            
            verification_type = message.get("verification_type")
            
            if verification_type == "verification_request":
                # Return the words for user confirmation
                return {
                    "type":  "verification_request",
                    "words": message["words"]
                }
            elif verification_type == "verification_response":
                # Process peer's verification response
                peer_verified = message["verified"]
                return {
                    "type":     "verification_response",
                    "verified": peer_verified
                }
            else:
                raise ValueError(f"Unknown verification type: {verification_type}")
        
        except Exception as e:
            raise ValueError(f"Failed to handle key verification message: {e}")
    
    def confirm_key_verification(self, verified: bool) -> bytes:
        """Confirm key verification result and return response message."""
        # Update local verification status
        self.verify_peer_key(verified)
        
        # Create verification response message
        verification_response = {
            "version":           PROTOCOL_VERSION,
            "type":              MessageType.KEY_VERIFICATION,
            "verification_type": "verification_response",
            "verified":          verified
        }
        return json.dumps(verification_response).encode('utf-8')
    
    # File transfer methods
    def create_file_metadata_message(self, file_path: str, return_metadata: bool = False,
                                     compress: bool = True) -> bytes | tuple[bytes, dict]:
        """Create a file metadata message for file transfer initiation."""
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Calculate file hash for integrity verification (of original uncompressed file)
        file_hash = hashlib.blake2b(digest_size=32)
        with open(file_path, 'rb') as f:
            while chunk := f.read(16384):
                file_hash.update(chunk)
        
        # Calculate the actual number of chunks that will be sent
        # This is critical for large files to ensure correct progress tracking
        total_chunks = 0
        total_processed_size = 0
        
        try:
            # Use the same chunking logic as chunk_file to get accurate count
            for chunk in self.chunk_file(file_path, compress=compress):
                total_chunks += 1
                total_processed_size += len(chunk)
        except Exception as e:
            # Fallback to estimation if chunking fails
            print(f"Warning: Could not pre-calculate chunks, using estimation: {e}")
            total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
            total_processed_size = file_size if not compress else int(file_size * 0.85)  # Rough estimate
        
        # Generate unique transfer ID
        transfer_id = hashlib.sha3_512(f"{file_name}{file_size}{file_hash.hexdigest()}".encode()).hexdigest()[:16]
        
        metadata = {
            "version":        PROTOCOL_VERSION,
            "type":           MessageType.FILE_METADATA,
            "transfer_id":    transfer_id,
            "filename":       file_name,
            "file_size":      file_size,  # Original file size for integrity verification
            "file_hash":      file_hash.hexdigest(),  # Hash of original file
            "total_chunks":   total_chunks,  # Actual number of chunks
            "compressed":     compress,  # Whether the transfer is compressed
            "processed_size": total_processed_size  # Total processed size for progress tracking
        }
        
        encrypted_message = self.encrypt_message(json.dumps(metadata))
        
        if return_metadata:
            return encrypted_message, metadata
        return encrypted_message
    
    def create_file_accept_message(self, transfer_id: str) -> bytes:
        """Create a file acceptance message."""
        message = {
            "version":     PROTOCOL_VERSION,
            "type":        MessageType.FILE_ACCEPT,
            "transfer_id": transfer_id
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_file_reject_message(self, transfer_id: str, reason: str = "User declined") -> bytes:
        """Create a file rejection message."""
        message = {
            "version":     PROTOCOL_VERSION,
            "type":        MessageType.FILE_REJECT,
            "transfer_id": transfer_id,
            "reason":      reason
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_file_chunk_message(self, transfer_id: str, chunk_index: int, chunk_data: bytes) -> bytes:
        """Create an optimized file chunk message with direct binary encryption."""
        if not self.shared_key or not self.send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        self.message_counter += 1
        
        # Derive unique message key for this chunk
        message_key = self._derive_message_key(self.send_chain_key, self.message_counter)
        
        # Ratchet the send chain key forward for the next message
        self.send_chain_key = self._ratchet_chain_key(self.send_chain_key, self.message_counter)
        
        # Create compact header (no JSON, no base64 for chunk data)
        header = {
            "version":     PROTOCOL_VERSION,
            "type":        MessageType.FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index
        }
        header_json = json.dumps(header).encode('utf-8')
        
        # Encrypt header and chunk data separately but in one operation
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        
        # Create AAD from counter and nonce for authentication
        aad_data = {
            "type":    MessageType.FILE_CHUNK,
            "counter": self.message_counter,
            "nonce":   base64.b64encode(nonce).decode('utf-8')
        }
        aad = json.dumps(aad_data, sort_keys=True).encode('utf-8')
        
        # Combine header length + header + chunk data for encryption
        header_len = struct.pack('!H', len(header_json))  # 2 bytes for header length
        plaintext = header_len + header_json + chunk_data
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        # Securely delete the message key
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Pack counter (4 bytes) + nonce (12 bytes) + ciphertext
        counter_bytes = struct.pack('!I', self.message_counter)
        return counter_bytes + nonce + ciphertext
    
    def create_file_complete_message(self, transfer_id: str) -> bytes:
        """Create a file transfer completion message."""
        message = {
            "version":     PROTOCOL_VERSION,
            "type":        MessageType.FILE_COMPLETE,
            "transfer_id": transfer_id
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_delivery_confirmation_message(self, confirmed_message_counter: int) -> bytes:
        """Create a delivery confirmation message for a received text message."""
        message = {
            "version":           PROTOCOL_VERSION,
            "type":              MessageType.DELIVERY_CONFIRMATION,
            "confirmed_counter": confirmed_message_counter
        }
        return self.encrypt_message(json.dumps(message))
    
    def chunk_file(self, file_path: str, compress: bool = True) -> Generator[bytes, None, None]:
        """Generate file chunks for transmission one at a time.

        This is a streaming generator function that optionally compresses and yields chunks
        without loading the entire file into memory. This approach is memory-efficient 
        for large files and provides a steady stream of data for network transmission.
        
        Args:
            file_path: Path to the file to chunk
            compress: Whether to compress the chunks (default: True)
        """
        
        if compress:
            # Use streaming compression
            compressor = StreamingGzipCompressor()
            pending_data = b''
            
            try:
                with open(file_path, 'rb') as original_file:
                    while True:
                        # Read a chunk from the original file
                        file_chunk = original_file.read(SEND_CHUNK_SIZE)
                        
                        if not file_chunk:
                            # End of file - finalize compression
                            final_compressed = compressor.finalize()
                            if final_compressed:
                                pending_data += final_compressed
                            break
                        
                        # Compress this chunk
                        compressed_chunk = compressor.compress_chunk(file_chunk)
                        if compressed_chunk:
                            pending_data += compressed_chunk
                        
                        # Yield complete chunks when we have enough data
                        while len(pending_data) >= SEND_CHUNK_SIZE:
                            yield pending_data[:SEND_CHUNK_SIZE]
                            pending_data = pending_data[SEND_CHUNK_SIZE:]
                    
                    # Yield any remaining data
                    if pending_data:
                        yield pending_data
            
            except Exception as e:
                # Clean up on error
                try:
                    compressor.finalize()
                except:
                    pass
                raise e
        else:
            # Send uncompressed chunks directly
            try:
                with open(file_path, 'rb') as original_file:
                    while True:
                        # Read a chunk from the original file
                        file_chunk = original_file.read(SEND_CHUNK_SIZE)
                        
                        if not file_chunk:
                            break
                        
                        yield file_chunk
            
            except Exception as e:
                raise e
    
    def process_file_metadata(self, decrypted_data: str) -> dict:
        """Process a file metadata message."""
        try:
            message = json.loads(decrypted_data)
            if message["type"] != MessageType.FILE_METADATA:
                raise ValueError("Invalid message type")
            
            return {
                "transfer_id":    message["transfer_id"],
                "filename":       message["filename"],
                "file_size":      message["file_size"],
                "file_hash":      message["file_hash"],
                "total_chunks":   message["total_chunks"],
                "compressed":     message.get("compressed", True),  # Default to compressed for backward compatibility
                "processed_size": message.get("processed_size", message.get("compressed_size", 0))
                # Support old field name
            }
        except Exception as e:
            raise ValueError(f"File metadata processing failed: {e}")
    
    def process_file_chunk(self, encrypted_data: bytes) -> dict:
        """Process an optimized file chunk message with binary format."""
        if not self.shared_key or not self.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        
        try:
            # Extract counter, nonce, and ciphertext from the message
            if len(encrypted_data) < 16:  # 4 bytes for counter + 12 for nonce
                raise ValueError("Invalid chunk message format")
            
            counter = struct.unpack('!I', encrypted_data[:4])[0]
            nonce = encrypted_data[4:16]
            ciphertext = encrypted_data[16:]
            
            # Check for replay attacks or very old messages
            if counter <= self.peer_counter:
                raise ValueError(
                        f"Replay attack or out-of-order message detected. Expected > {self.peer_counter}, got {counter}")
            
            # Advance the chain key to the correct state for this message
            temp_chain_key = self.receive_chain_key
            for i in range(self.peer_counter + 1, counter):
                temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
            
            # Derive the message key for the current message
            message_key = self._derive_message_key(temp_chain_key, counter)
            
            # Create AAD from counter and nonce for authentication verification
            aad_data = {
                "type":    MessageType.FILE_CHUNK,
                "counter": counter,
                "nonce":   base64.b64encode(nonce).decode('utf-8')
            }
            aad = json.dumps(aad_data, sort_keys=True).encode('utf-8')
            
            # Decrypt the chunk payload with AAD verification
            aesgcm = AESGCM(message_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            
            # Parse the decrypted header and extract chunk data
            if len(plaintext) < 2:
                raise ValueError("Invalid decrypted data: too short")
            
            header_len = struct.unpack('!H', plaintext[:2])[0]
            if len(plaintext) < 2 + header_len:
                raise ValueError("Invalid decrypted data: header length mismatch")
            
            header_json = plaintext[2:2 + header_len]
            chunk_data = plaintext[2 + header_len:]
            header = json.loads(header_json.decode('utf-8'))
            
            if header["type"] != MessageType.FILE_CHUNK:
                raise ValueError("Invalid message type in decrypted chunk")
            
            # Decryption successful, update the state
            self.receive_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
            self.peer_counter = counter
            
            # Securely delete the message key
            message_key = b'\x00' * len(message_key)
            del message_key
            
            return {
                "transfer_id": header["transfer_id"],
                "chunk_index": header["chunk_index"],
                "chunk_data":  chunk_data
            }
        
        except ValueError as e:
            # Re-raise specific value errors to be handled by the caller
            raise e
        except Exception as e:
            raise ValueError(f"File chunk processing failed: {e}")
    
    def add_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes, total_chunks: int) -> bool:
        """Add a received file chunk and return True if file is complete.
        
        Instead of storing chunks in memory, this method writes them directly to a temporary file.
        It keeps track of which chunks have been received using a set of indices.
        Uses persistent file handles to avoid the performance overhead of opening/closing files for each chunk.
        """
        # Initialize tracking structures if this is the first chunk for this transfer
        if transfer_id not in self.received_chunks:
            self.received_chunks[transfer_id] = set()
            
            # Create a temporary file for this transfer
            temp_file_path = os.path.join(os.getcwd(), f".tmp_transfer_{transfer_id}")
            self.temp_file_paths[transfer_id] = temp_file_path
            
            # Create and open the file for writing, keep the handle open
            self.open_file_handles[transfer_id] = open(temp_file_path, 'w+b')
        
        # Get the open file handle
        file_handle = self.open_file_handles[transfer_id]
        
        # Write the chunk to the temporary file at the correct position
        # Calculate the position based on chunk index and send chunk size
        # Use explicit 64-bit integer calculation to handle large files
        position = int(chunk_index) * int(SEND_CHUNK_SIZE)
        
        try:
            # Seek to the correct position with error handling for large files
            file_handle.seek(position, 0)  # 0 = SEEK_SET (absolute positioning)
            
            # Verify we're at the correct position
            actual_position = file_handle.tell()
            if actual_position != position:
                raise ValueError(f"Failed to seek to position {position}, got {actual_position}")
            
            # Write the chunk data
            bytes_written = file_handle.write(chunk_data)
            if bytes_written != len(chunk_data):
                raise ValueError(f"Failed to write complete chunk: wrote {bytes_written} of {len(chunk_data)} bytes")
            
            # Flush to ensure data is written to disk
            file_handle.flush()
        
        except (OSError, IOError) as e:
            raise ValueError(f"Failed to write chunk {chunk_index} at position {position}: {e}")
        
        # Mark this chunk as received
        self.received_chunks[transfer_id].add(chunk_index)
        
        # Check if all chunks are received
        is_complete = len(self.received_chunks[transfer_id]) == total_chunks
        
        # If transfer is complete, close the file handle
        if is_complete:
            file_handle.close()
            del self.open_file_handles[transfer_id]
        
        return is_complete
    
    def reassemble_file(self, transfer_id: str, output_path: str, expected_hash: str, compressed: bool = True) -> bool:
        """Finalize file transfer, optionally decompress, and verify integrity.
        
        Since chunks are already written to a temporary file, this method:
        1. Ensures any open file handle is closed
        2. Optionally decompresses the temporary file (if compressed=True)
        3. Calculates the hash of the final file
        4. Verifies the hash against the expected hash
        5. Moves the final file to the output path
        
        Args:
            transfer_id: The transfer ID
            output_path: Final output path for the file
            expected_hash: Expected SHA3-512 hash of the original file
            compressed: Whether the received data is compressed (default: True for backward compatibility)
        """
        if transfer_id not in self.received_chunks or transfer_id not in self.temp_file_paths:
            raise ValueError(f"No data found for transfer {transfer_id}")
        
        # Ensure any open file handle is closed before proceeding
        if transfer_id in self.open_file_handles:
            try:
                self.open_file_handles[transfer_id].close()
            except Exception:
                pass  # Ignore errors during cleanup
            del self.open_file_handles[transfer_id]
        
        temp_received_path = self.temp_file_paths[transfer_id]
        
        if not os.path.exists(temp_received_path):
            raise ValueError(f"Temporary file not found: {temp_received_path}")
        
        final_file_path = temp_received_path
        
        try:
            if compressed:
                # Create a temporary path for the decompressed file
                temp_decompressed_path = temp_received_path + ".decompressed"
                
                # Decompress the file
                with open(temp_received_path, 'rb') as compressed_file:
                    with gzip.GzipFile(fileobj=compressed_file, mode='rb') as gzip_file:
                        with open(temp_decompressed_path, 'wb') as decompressed_file:
                            # Decompress in chunks to avoid memory issues
                            while chunk := gzip_file.read(16384):
                                decompressed_file.write(chunk)
                
                final_file_path = temp_decompressed_path
            
            # Calculate hash of the final file
            file_hash = hashlib.blake2b(digest_size=32)
            with open(final_file_path, 'rb') as f:
                while chunk := f.read(16384):  # Read in small chunks to avoid memory issues
                    file_hash.update(chunk)
            
            # Verify file integrity
            if file_hash.hexdigest() != expected_hash:
                # Clean up temporary files
                os.remove(temp_received_path)
                if compressed and os.path.exists(final_file_path):
                    os.remove(final_file_path)
                raise ValueError("File integrity check failed")
            
            # Move the final file to the output path
            try:
                # If the output file already exists, remove it first
                if os.path.exists(output_path):
                    os.remove(output_path)
                
                # Move the final file to the output path
                os.rename(final_file_path, output_path)
            except Exception as e:
                # If moving fails, try copying instead
                try:
                    shutil.copy2(final_file_path, output_path)
                    os.remove(final_file_path)
                except Exception as copy_error:
                    raise ValueError(f"Failed to move file: {e}, copy error: {copy_error}")
            
            # Clean up the temporary received file (if different from final file)
            if compressed and os.path.exists(temp_received_path):
                os.remove(temp_received_path)
        
        except Exception as e:
            # Clean up any temporary files on error
            if os.path.exists(temp_received_path):
                os.remove(temp_received_path)
            if compressed and final_file_path != temp_received_path and os.path.exists(final_file_path):
                os.remove(final_file_path)
            raise ValueError(f"File processing failed: {e}")
        
        # Clean up tracking data
        del self.received_chunks[transfer_id]
        del self.temp_file_paths[transfer_id]
        
        return True


def create_error_message(error_text: str) -> bytes:
    """Create an error message"""
    message = {
        "version": PROTOCOL_VERSION,
        "type":    MessageType.ERROR,
        "error":   error_text
    }
    return json.dumps(message).encode('utf-8')


def create_reset_message() -> bytes:
    """Create a key exchange reset message."""
    message = {
        "version": PROTOCOL_VERSION,
        "type":    MessageType.KEY_EXCHANGE_RESET,
        "message": "Key exchange reset - other client disconnected"
    }
    return json.dumps(message).encode('utf-8')


def send_message(sock, data: bytes):
    """Send a length-prefixed message over a socket."""
    length = struct.pack('!I', len(data))
    sock.send(length + data)


def receive_message(sock) -> bytes:
    """Receive a length-prefixed message from a socket."""
    # First, receive the length
    length_data = b''
    while len(length_data) < 4:
        chunk = sock.recv(4 - len(length_data))
        if not chunk:
            raise ConnectionError("Connection closed")
        length_data += chunk
    
    length = struct.unpack('!I', length_data)[0]
    
    # Then receive the message
    message_data = b''
    while len(message_data) < length:
        chunk = sock.recv(length - len(message_data))
        if not chunk:
            raise ConnectionError("Connection closed")
        message_data += chunk
    
    return message_data
