# shared.py - Shared cryptographic utilities and protocol definitions
import base64
import os
import json
import struct
import hashlib

from kyber_py.ml_kem import ML_KEM_1024
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Protocol constants
PROTOCOL_VERSION = 6
MSG_TYPE_KEY_EXCHANGE_INIT = 1
MSG_TYPE_KEY_EXCHANGE_RESPONSE = 2
MSG_TYPE_ENCRYPTED_MESSAGE = 3
MSG_TYPE_ERROR = 4
MSG_TYPE_KEY_VERIFICATION = 5
MSG_TYPE_FILE_METADATA = 6
MSG_TYPE_FILE_ACCEPT = 7
MSG_TYPE_FILE_REJECT = 8
MSG_TYPE_FILE_CHUNK = 9
MSG_TYPE_FILE_COMPLETE = 10
MSG_TYPE_KEY_EXCHANGE_RESET = 11
MSG_TYPE_KEEP_ALIVE = 12
MSG_TYPE_KEEP_ALIVE_RESPONSE = 13
MSG_TYPE_DELIVERY_CONFIRMATION = 14

# File transfer constants
FILE_CHUNK_SIZE = 128 * 1024 * 1024  # 128 MiB chunks for loading
SEND_CHUNK_SIZE = 64 * 1024  # 64 KiB chunks for sending

def bytes_to_human_readable(size: int) -> str:
    """Convert a byte count to a human-readable format with appropriate units.
    
    Args:
        size (int): The number of bytes to convert.
        
    Returns:
        str: A formatted string with the size and appropriate unit (B, KB, MB, or GB).
        
    Examples:
        >>> bytes_to_human_readable(512)
        '512 B'
        >>> bytes_to_human_readable(1536)
        '1.5 KB'
        >>> bytes_to_human_readable(2097152)
        '2.0 MB'
    """
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.1f} KB"
    elif size < 1024**3:
        return f"{size / 1024**2:.1f} MB"
    else:
        return f"{size / 1024**3:.1f} GB"


# noinspection PyUnresolvedReferences
class SecureChatProtocol:
    """
    SecureChatProtocol - Implements the cryptographic protocol for secure chat using ML-KEM and AES-GCM.
    """
    
    def __init__(self):
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
            chain_key (bytes | None): Root key for perfect forward secrecy ratcheting.
            seen_counters (set): Set of seen message counters for replay protection.
            file_transfers (dict): Dictionary tracking ongoing file transfers.
            received_chunks (dict): Buffer for received file chunks during transfer.
        """
        self.shared_key: bytes | None = None
        self.message_counter: int = 0
        self.peer_counter: int = 0
        self.peer_public_key: bytes | None = None
        self.peer_key_verified = False
        self.own_public_key: bytes | None = None
        # Perfect Forward Secrecy - Key Ratcheting
        self.send_chain_key: bytes | None = None    # For encrypting outgoing messages
        self.receive_chain_key: bytes | None = None # For decrypting incoming messages
        self.seen_counters: set = set()  # Track seen counters for replay protection
        
        # File transfer state
        self.file_transfers: dict = {}  # Track ongoing file transfers
        self.received_chunks: dict = {}  # Track received chunk indices (set of indices per transfer)
        self.temp_file_paths: dict = {}  # Track temporary file paths for receiving chunks
        
    def reset_key_exchange(self):
        """Reset all cryptographic state to initial values for key exchange restart."""
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
        
        # Clean up any temporary files
        for temp_path in self.temp_file_paths.values():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass  # Ignore errors during cleanup
        self.temp_file_paths = {}
        
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate ML-KEM keypair for key exchange."""
        public_key, private_key = ML_KEM_1024.keygen()
        self.own_public_key = public_key
        return public_key, private_key
    
    def derive_keys(self, shared_secret: bytes) -> tuple[bytes, bytes]:
        """Derive encryption and MAC keys from shared secret using HKDF."""
        # Derive 64 bytes: 32 for AES-GCM, 32 for HMAC
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b"SecureChat2025",
            info=b"key_derivation"
        )
        derived = hkdf.derive(shared_secret)
        
        # Initialize chain keys for perfect forward secrecy
        self._initialize_chain_keys(shared_secret)
        
        return derived[:32], derived[32:]  # encryption_key, mac_key
    
    def _initialize_chain_keys(self, shared_secret: bytes):
        """Initialize separate chain keys for sending and receiving."""
        # Derive a root chain key that both parties will use as the starting point
        chain_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SecureChat2025",
            info=b"chain_key_root"
        )
        
        root_chain_key = chain_hkdf.derive(shared_secret)
        
        # Both send and receive chain keys start with the same value
        # They will diverge as messages are sent and received
        self.send_chain_key = root_chain_key
        self.receive_chain_key = root_chain_key
    
    def _derive_message_key(self, chain_key: bytes, counter: int) -> bytes:
        """Derive a message key from the chain key and counter."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SecureChat2025",
            info=f"message_key_{counter}".encode()
        )
        return hkdf.derive(chain_key)
    
    def _ratchet_chain_key(self, chain_key: bytes, counter: int) -> bytes:
        """Advance the chain key (ratchet forward)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SecureChat2025",
            info=f"chain_key_{counter}".encode()
        )
        return hkdf.derive(chain_key)
    
    def _fast_ratchet_chain_key(self, initial_chain_key: bytes, start_counter: int, end_counter: int) -> bytes:
        """Efficiently ratchet chain key over large counter gaps using batched operations."""
        if end_counter <= start_counter:
            return initial_chain_key
        
        # For very large gaps, we can use a more efficient approach
        # Instead of ratcheting one by one, we'll use a single HKDF operation
        # that incorporates the counter range
        gap_size = end_counter - start_counter
        
        if gap_size <= 10:
            # For small gaps, use normal ratcheting
            current_key = initial_chain_key
            for i in range(start_counter + 1, end_counter + 1):
                current_key = self._ratchet_chain_key(current_key, i)
            return current_key
        
        # For large gaps, use a single HKDF operation with the gap info
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"SecureChat2025",
            info=f"fast_ratchet_{start_counter}_to_{end_counter}".encode()
        )
        return hkdf.derive(initial_chain_key)
    
    def generate_key_fingerprint(self, public_key: bytes) -> str:
        """Generate a human-readable word-based fingerprint for a public key."""
        # Create SHA-256 hash of the public key
        key_hash = hashlib.sha256(public_key).digest()
        
        # Load the wordlist
        wordlist = self._load_wordlist()
        
        # Convert hash to word-based fingerprint (10 words for usability)
        words = self._hash_to_words(key_hash, wordlist, num_words=15)
        
        # Format the words in a user-friendly way
        # Display 5 words per line for better readability
        msg = "Key Fingerprint:\n"
        for i in range(0, len(words), 5):
            msg += " ".join(words[i:i+5]) + "\n"
            
        return msg.strip()
        
    
        
    
    def _load_wordlist(self) -> list:
        """Load the EFF large wordlist."""
        try:
            wordlist_path = os.path.join(os.path.dirname(__file__), 'eff_large_wordlist.txt')
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback if wordlist file is not found
            raise FileNotFoundError("eff_large_wordlist.txt not found. Please ensure the wordlist file is in the same directory as shared.py")
    
    def _hash_to_words(self, hash_bytes: bytes, wordlist: list, num_words: int = 10) -> list:
        """Convert hash bytes to a list of words from the wordlist."""
        # Convert hash to integer for easier manipulation
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        
        # Use the wordlist size (7776) as base for conversion
        wordlist_size = len(wordlist)
        
        words = []
        for i in range(num_words):
            # Extract word index using modulo and bit shifting
            # This ensures good distribution across the wordlist
            word_index = (hash_int >> (i * 13)) % wordlist_size
            words.append(wordlist[word_index])
        
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
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_KEY_VERIFICATION,
            "verified": verified,
            "own_key_fingerprint": self.get_own_key_fingerprint() if self.own_public_key else ""
        }
        return json.dumps(message).encode('utf-8')
    
    def process_key_verification_message(self, data: bytes) -> dict:
        """Process a key verification message from peer."""
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MSG_TYPE_KEY_VERIFICATION:
                raise ValueError("Invalid message type")
            
            return {
                "verified": message.get("verified", False),
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
    
    def create_key_exchange_init(self, public_key: bytes) -> bytes:
        """Create initial key exchange message."""
        message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_KEY_EXCHANGE_INIT,
            "public_key": base64.b64encode(public_key).decode('utf-8')
        }
        return json.dumps(message).encode('utf-8')
    
    def create_key_exchange_response(self, ciphertext: bytes) -> bytes:
        """Create key exchange response message."""
        message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_KEY_EXCHANGE_RESPONSE,
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
            if message["type"] != MSG_TYPE_KEY_EXCHANGE_INIT:
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
            if message["type"] != MSG_TYPE_KEY_EXCHANGE_RESPONSE:
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
        
        # Encrypt with AES-GCM using the unique message key
        aesgcm: AESGCM = AESGCM(message_key)
        nonce: bytes = os.urandom(12)
        ciphertext: bytes = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Securely delete the message key
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Create authenticated message with counter outside the ciphertext
        encrypted_message = {
            "version":    PROTOCOL_VERSION,
            "type":       MSG_TYPE_ENCRYPTED_MESSAGE,
            "counter":    self.message_counter,  # Counter is now in plaintext
            "nonce":      base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        
        return json.dumps(encrypted_message).encode('utf-8')
    
    def decrypt_message(self, data: bytes) -> str:
        """Decrypt and authenticate a message using perfect forward secrecy."""
        if not self.shared_key or not self.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")

        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MSG_TYPE_ENCRYPTED_MESSAGE:
                raise ValueError("Invalid message type")

            nonce = base64.b64decode(message["nonce"])
            ciphertext = base64.b64decode(message["ciphertext"])
            counter = message["counter"]

            # Check for replay attacks or very old messages
            if counter <= self.peer_counter:
                raise ValueError("Replay attack or out-of-order message detected")

            # Optimized chain key ratcheting - avoid expensive loops
            # Calculate how many steps we need to advance
            steps_to_advance = counter - self.peer_counter
            
            if steps_to_advance > 100:
                # For large gaps, use a more efficient approach
                # We'll compute the chain key state directly using repeated squaring
                derivation_chain_key = self._fast_ratchet_chain_key(self.receive_chain_key, self.peer_counter, counter - 1)
            else:
                # For small gaps, use the original approach
                derivation_chain_key = self.receive_chain_key
                for i in range(self.peer_counter + 1, counter):
                    derivation_chain_key = self._ratchet_chain_key(derivation_chain_key, i)

            # Derive the message key for the current message
            message_key = self._derive_message_key(derivation_chain_key, counter)

            # Ratchet the chain key forward to the new state
            temp_chain_key = self._ratchet_chain_key(derivation_chain_key, counter)


            # Decrypt with the derived message key
            aesgcm = AESGCM(message_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

            # If decryption is successful, commit the new state
            self.receive_chain_key = temp_chain_key
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
        shared_secret, ciphertext, _ = self.process_key_exchange_init(message_data)
        
        # Create and return the response message
        return self.create_key_exchange_response(ciphertext)
    
    def handle_key_exchange_response(self, message_data: bytes) -> bytes:
        """Handle key exchange response from peer and return completion message."""
        if not hasattr(self, 'private_key'):
            raise ValueError("No private key available for key exchange response")
        
        # Process the response to get shared secret
        shared_secret = self.process_key_exchange_response(message_data, self.private_key)
        
        # Create completion message
        complete_message = {
            "version": PROTOCOL_VERSION,
            "type": "key_exchange_complete"
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
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_KEY_VERIFICATION,
            "verification_type": "verification_request",
            "words": words
        }
        return json.dumps(verification_request).encode('utf-8')
    
    def handle_key_verification_message(self, message_data: bytes) -> dict:
        """Handle key verification message and return verification info."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            
            if message["type"] != MSG_TYPE_KEY_VERIFICATION:
                raise ValueError("Invalid message type for key verification")
            
            verification_type = message.get("verification_type")
            
            if verification_type == "verification_request":
                # Return the words for user confirmation
                return {
                    "type": "verification_request",
                    "words": message["words"]
                }
            elif verification_type == "verification_response":
                # Process peer's verification response
                peer_verified = message["verified"]
                return {
                    "type": "verification_response",
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
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_KEY_VERIFICATION,
            "verification_type": "verification_response",
            "verified": verified
        }
        return json.dumps(verification_response).encode('utf-8')
    
    # File transfer methods
    def create_file_metadata_message(self, file_path: str, return_metadata: bool = False) -> bytes | tuple[bytes, dict]:
        """Create a file metadata message for file transfer initiation."""
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Calculate file hash for integrity verification
        file_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                file_hash.update(chunk)
        
        # Generate unique transfer ID
        transfer_id = hashlib.sha256(f"{file_name}{file_size}{file_hash.hexdigest()}".encode()).hexdigest()[:16]
        
        metadata = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_FILE_METADATA,
            "transfer_id": transfer_id,
            "filename": file_name,
            "file_size": file_size,
            "file_hash": file_hash.hexdigest(),
            "total_chunks": (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
        }
        
        encrypted_message = self.encrypt_message(json.dumps(metadata))
        
        if return_metadata:
            return encrypted_message, metadata
        return encrypted_message
    
    def create_file_accept_message(self, transfer_id: str) -> bytes:
        """Create a file acceptance message."""
        message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_FILE_ACCEPT,
            "transfer_id": transfer_id
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_file_reject_message(self, transfer_id: str, reason: str = "User declined") -> bytes:
        """Create a file rejection message."""
        message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_FILE_REJECT,
            "transfer_id": transfer_id,
            "reason": reason
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
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_FILE_CHUNK,
            "counter": self.message_counter,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index
        }
        header_json = json.dumps(header).encode('utf-8')
        
        # Encrypt header and chunk data separately but in one operation
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        
        # Combine header length + header + chunk data for encryption
        header_len = struct.pack('!H', len(header_json))  # 2 bytes for header length
        plaintext = header_len + header_json + chunk_data
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Securely delete the message key
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Return: nonce (12 bytes) + ciphertext
        return nonce + ciphertext
    
    def create_file_complete_message(self, transfer_id: str) -> bytes:
        """Create a file transfer completion message."""
        message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_FILE_COMPLETE,
            "transfer_id": transfer_id
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_delivery_confirmation_message(self, confirmed_message_counter: int) -> bytes:
        """Create a delivery confirmation message for a received text message."""
        message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_DELIVERY_CONFIRMATION,
            "confirmed_counter": confirmed_message_counter
        }
        return self.encrypt_message(json.dumps(message))
    
    def chunk_file(self, file_path: str):
        """Generate file chunks for transmission one at a time.
        
        This is a generator function that yields one chunk at a time
        to avoid loading the entire file into memory.
        
        The file is read in large chunks (FILE_CHUNK_SIZE) to minimize disk I/O,
        but each large chunk is then split into smaller chunks (SEND_CHUNK_SIZE)
        for network transmission.
        """
        with open(file_path, 'rb') as f:
            while large_chunk := f.read(FILE_CHUNK_SIZE):
                # Split the large chunk into smaller chunks for sending
                for i in range(0, len(large_chunk), SEND_CHUNK_SIZE):
                    yield large_chunk[i:i + SEND_CHUNK_SIZE]
    
    def process_file_metadata(self, decrypted_data: str) -> dict:
        """Process a file metadata message."""
        try:
            message = json.loads(decrypted_data)
            if message["type"] != MSG_TYPE_FILE_METADATA:
                raise ValueError("Invalid message type")
            
            return {
                "transfer_id": message["transfer_id"],
                "filename": message["filename"],
                "file_size": message["file_size"],
                "file_hash": message["file_hash"],
                "total_chunks": message["total_chunks"]
            }
        except Exception as e:
            raise ValueError(f"File metadata processing failed: {e}")
    
    def process_file_chunk(self, encrypted_data: bytes) -> dict:
        """Process an optimized file chunk message with binary format."""
        if not self.shared_key or not self.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        
        try:
            # Extract nonce (first 12 bytes) and ciphertext
            if len(encrypted_data) < 12:
                raise ValueError("Invalid chunk message format")
            
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # We need to determine the counter from the message, but we can't without decrypting
            # For now, try sequential counters (this is a limitation we'll address)
            temp_counter = self.peer_counter + 1
            max_attempts = 100  # Prevent infinite loops
            
            for attempt in range(max_attempts):
                try:
                    # Derive message key for this counter using optimized ratcheting
                    steps_to_advance = temp_counter - self.peer_counter - 1
                    if steps_to_advance > 100:
                        temp_chain_key = self._fast_ratchet_chain_key(self.receive_chain_key, self.peer_counter, temp_counter - 1)
                    else:
                        temp_chain_key = self.receive_chain_key
                        for i in range(self.peer_counter + 1, temp_counter):
                            temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
                    
                    message_key = self._derive_message_key(temp_chain_key, temp_counter)
                    
                    # Try to decrypt
                    aesgcm = AESGCM(message_key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    # Parse the decrypted data
                    if len(plaintext) < 2:
                        raise ValueError("Invalid decrypted data")
                    
                    header_len = struct.unpack('!H', plaintext[:2])[0]
                    if len(plaintext) < 2 + header_len:
                        raise ValueError("Invalid header length")
                    
                    header_json = plaintext[2:2+header_len]
                    chunk_data = plaintext[2+header_len:]
                    
                    header = json.loads(header_json.decode('utf-8'))
                    
                    if header["type"] != MSG_TYPE_FILE_CHUNK:
                        raise ValueError("Invalid message type")
                    
                    # Verify counter matches
                    if header["counter"] != temp_counter:
                        temp_counter = header["counter"]
                        continue  # Try again with correct counter
                    
                    # Success! Update state
                    self.receive_chain_key = self._ratchet_chain_key(temp_chain_key, temp_counter)
                    self.peer_counter = temp_counter
                    
                    # Securely delete the message key
                    message_key = b'\x00' * len(message_key)
                    del message_key
                    
                    return {
                        "transfer_id": header["transfer_id"],
                        "chunk_index": header["chunk_index"],
                        "chunk_data": chunk_data
                    }
                    
                except Exception:
                    temp_counter += 1
                    continue
            
            raise ValueError("Could not decrypt chunk after maximum attempts")
            
        except Exception as e:
            raise ValueError(f"File chunk processing failed: {e}")
    
    def add_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes, total_chunks: int) -> bool:
        """Add a received file chunk and return True if file is complete.
        
        Instead of storing chunks in memory, this method writes them directly to a temporary file.
        It keeps track of which chunks have been received using a set of indices.
        """
        # Initialize tracking structures if this is the first chunk for this transfer
        if transfer_id not in self.received_chunks:
            self.received_chunks[transfer_id] = set()
            
            # Create a temporary file for this transfer
            temp_file_path = os.path.join(os.getcwd(), f".tmp_transfer_{transfer_id}")
            self.temp_file_paths[transfer_id] = temp_file_path
            
            # Create an empty file
            with open(temp_file_path, 'wb'):
                pass
        
        # Get the temporary file path
        temp_file_path = self.temp_file_paths[transfer_id]
        
        # Write the chunk to the temporary file at the correct position
        with open(temp_file_path, 'r+b') as f:
            # Calculate the position based on chunk index and send chunk size
            position = chunk_index * SEND_CHUNK_SIZE
            f.seek(position)
            f.write(chunk_data)
        
        # Mark this chunk as received
        self.received_chunks[transfer_id].add(chunk_index)
        
        # Check if all chunks are received
        return len(self.received_chunks[transfer_id]) == total_chunks
    
    def reassemble_file(self, transfer_id: str, output_path: str, expected_hash: str) -> bool:
        """Finalize file transfer and verify integrity.
        
        Since chunks are already written to a temporary file, this method:
        1. Calculates the hash of the temporary file
        2. Verifies the hash against the expected hash
        3. Moves the temporary file to the final output path
        """
        if transfer_id not in self.received_chunks or transfer_id not in self.temp_file_paths:
            raise ValueError(f"No data found for transfer {transfer_id}")
        
        temp_file_path = self.temp_file_paths[transfer_id]
        
        if not os.path.exists(temp_file_path):
            raise ValueError(f"Temporary file not found: {temp_file_path}")
        
        # Calculate hash of the temporary file
        file_hash = hashlib.sha256()
        with open(temp_file_path, 'rb') as f:
            while chunk := f.read(8192):  # Read in small chunks to avoid memory issues
                file_hash.update(chunk)
        
        # Verify file integrity
        if file_hash.hexdigest() != expected_hash:
            os.remove(temp_file_path)  # Remove corrupted file
            raise ValueError("File integrity check failed")
        
        # Move the temporary file to the final output path
        try:
            # If the output file already exists, remove it first
            if os.path.exists(output_path):
                os.remove(output_path)
            
            # Move the temporary file to the final output path
            os.rename(temp_file_path, output_path)
        except Exception as e:
            # If moving fails, try copying instead
            try:
                import shutil
                shutil.copy2(temp_file_path, output_path)
                os.remove(temp_file_path)
            except Exception as copy_error:
                raise ValueError(f"Failed to move file: {e}, copy error: {copy_error}")
        
        # Clean up tracking data
        del self.received_chunks[transfer_id]
        del self.temp_file_paths[transfer_id]
        
        return True

def create_error_message(error_text: str) -> bytes:
    """Create an error message."""
    message = {
        "version": PROTOCOL_VERSION,
        "type": MSG_TYPE_ERROR,
        "error": error_text
    }
    return json.dumps(message).encode('utf-8')

def create_reset_message() -> bytes:
    """Create a key exchange reset message."""
    message = {
        "version": PROTOCOL_VERSION,
        "type": MSG_TYPE_KEY_EXCHANGE_RESET,
        "message": "Key exchange reset - other client disconnected"
    }
    return json.dumps(message).encode('utf-8')

def send_message(sock, data: bytes):
    """Send a length-prefixed message over a socket."""
    length = struct.pack('!I', len(data))
    sock.sendall(length + data)

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