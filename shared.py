# shared.py - Shared cryptographic utilities and protocol definitions
import base64
import os
import json
import struct
import hashlib
import hmac
from kyber_py.ml_kem import ML_KEM_1024
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Protocol constants
PROTOCOL_VERSION = 1
MSG_TYPE_KEY_EXCHANGE_INIT = 1
MSG_TYPE_KEY_EXCHANGE_RESPONSE = 2
MSG_TYPE_ENCRYPTED_MESSAGE = 3
MSG_TYPE_ERROR = 4
MSG_TYPE_KEY_VERIFICATION = 5

class SecureChatProtocol:
    """Handles the secure chat protocol including key exchange and message encryption."""
    
    def __init__(self):
        self.shared_key: bytes | None = None
        self.message_counter = 0
        self.peer_counter = 0
        self.peer_public_key: bytes | None = None
        self.peer_key_verified = False
        self.own_public_key: bytes | None = None
        
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
        return derived[:32], derived[32:]  # encryption_key, mac_key
    
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
    
    def process_key_exchange_init(self, data: bytes) -> tuple[bytes, bytes]:
        """Process initial key exchange and return shared key and response ciphertext."""
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MSG_TYPE_KEY_EXCHANGE_INIT:
                raise ValueError("Invalid message type")
            
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
            
            return shared_secret, ciphertext
        except Exception as e:
            raise ValueError(f"Key exchange init failed: {e}")
    
    def process_key_exchange_response(self, data: bytes, private_key: bytes) -> bytes:
        """Process key exchange response and derive shared key."""
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MSG_TYPE_KEY_EXCHANGE_RESPONSE:
                raise ValueError("Invalid message type")
            
            ciphertext = base64.b64decode(message["ciphertext"])
            # Store peer's public key for verification
            if "public_key" in message and message["public_key"]:
                self.peer_public_key = base64.b64decode(message["public_key"])
            
            shared_secret = ML_KEM_1024.decaps(private_key, ciphertext)
            
            # Derive keys from shared secret
            self.encryption_key, self.mac_key = self.derive_keys(shared_secret)
            self.shared_key = shared_secret
            
            return shared_secret
        except Exception as e:
            raise ValueError(f"Key exchange response failed: {e}")
    
    def encrypt_message(self, plaintext: str) -> bytes:
        """Encrypt a message with authentication and replay protection."""
        if not self.shared_key:
            raise ValueError("No shared key established")
        
        # Increment message counter for replay protection
        self.message_counter += 1
        
        # Create message with counter
        message_data = {
            "counter": self.message_counter,
            "text": plaintext
        }
        message_json = json.dumps(message_data).encode('utf-8')
        
        # Encrypt with AES-GCM (provides built-in authentication)
        aesgcm = AESGCM(self.encryption_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message_json, None)
        
        # Create authenticated message
        encrypted_message = {
            "version": PROTOCOL_VERSION,
            "type": MSG_TYPE_ENCRYPTED_MESSAGE,
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        
        message_bytes = json.dumps(encrypted_message).encode('utf-8')
        
        # Return message directly (AES-GCM already provides authentication)
        return message_bytes
    
    def decrypt_message(self, data: bytes) -> str:
        """Decrypt and authenticate a message."""
        if not self.shared_key:
            raise ValueError("No shared key established")
        
        try:
            message = json.loads(data.decode('utf-8'))
            if message["type"] != MSG_TYPE_ENCRYPTED_MESSAGE:
                raise ValueError("Invalid message type")
            
            nonce = base64.b64decode(message["nonce"])
            ciphertext = base64.b64decode(message["ciphertext"])
            
            # Decrypt with AES-GCM (provides built-in authentication)
            aesgcm = AESGCM(self.encryption_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse decrypted message
            message_data = json.loads(decrypted_data.decode('utf-8'))
            
            # Check counter for replay protection
            if message_data["counter"] <= self.peer_counter:
                raise ValueError("Replay attack detected")
            
            self.peer_counter = message_data["counter"]
            return message_data["text"]
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

def create_error_message(error_text: str) -> bytes:
    """Create an error message."""
    message = {
        "version": PROTOCOL_VERSION,
        "type": MSG_TYPE_ERROR,
        "error": error_text
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