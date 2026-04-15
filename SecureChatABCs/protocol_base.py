from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from SecureChatABCs.client_base import ClientBase


class ProtocolBase(ABC):
    """
    Abstract base class defining the interface for the SecureChatProtocol.
    
    This class defines the methods that the client core expects from the protocol implementation.
    The protocol is responsible for handling the actual cryptographic operations,
    like key exchange and message en- and decryption.
    """
    
    @abstractmethod
    def __init__(self, client: "ClientBase | None" = None) -> None:
        self.peer_counter: int = 0
        self.ke_step: int = 0
        self.message_counter: int = 0
    
    @property
    @abstractmethod
    def encryption_ready(self) -> bool:
        """Check if encryption is ready (shared key and chain keys established)."""
    
    @property
    @abstractmethod
    def should_auto_rekey(self) -> bool:
        """Check if automatic rekey should be initiated based on message count."""
    
    @property
    @abstractmethod
    def rekey_in_progress(self) -> bool:
        """Check if a rekey is currently in progress."""
    
    @property
    @abstractmethod
    def send_dummy_messages(self) -> bool:
        """Check if dummy messages should be sent."""
    
    @send_dummy_messages.setter
    @abstractmethod
    def send_dummy_messages(self, value: bool) -> None:
        """Set whether the client wants dummy messages to be sent."""
    
    @property
    @abstractmethod
    def has_active_file_transfers(self) -> bool:
        """Return True if any file transfers are currently active."""
    
    # Transport
    
    @abstractmethod
    def start_sender_thread(self, sock) -> None:
        """Start the background sender thread for message queuing."""
    
    @abstractmethod
    def stop_sender_thread(self) -> None:
        """Stop the background sender thread."""
    
    @abstractmethod
    def queue_json(self, obj: dict[str, Any]) -> None:
        """Encrypt a JSON-serialisable dict and add it to the send queue."""
    
    @abstractmethod
    def queue_text(self, text: str) -> None:
        """Encrypt a plain-text chat message and add it to the send queue."""
    
    @abstractmethod
    def queue_json_then_switch(self, obj: dict[str, Any]) -> None:
        """Encrypt a JSON dict, send it under the current keys, then activate pending keys."""
    
    @abstractmethod
    def send_emergency_close(self) -> bool:
        """Send an emergency close message immediately, bypassing the queue."""
    
    # Key generation & exchange
    
    @abstractmethod
    def reset_key_exchange(self) -> None:
        """Reset all cryptographic state to initial values for key exchange restart."""
    
    @abstractmethod
    def get_own_key_fingerprint(self) -> str:
        """Generate a consistent fingerprint for the session."""
    
    @staticmethod
    @abstractmethod
    def create_key_verification_message(verified: bool) -> bytes:
        """Create a key verification status message."""
    
    @staticmethod
    @abstractmethod
    def process_key_verification_message(data: bytes) -> bool:
        """Process a key verification message from peer."""
    
    @abstractmethod
    def create_ke_dsa_random(self) -> bytes:
        """Create KE_DSA_RANDOM message: DSA public key + client random."""
    
    @abstractmethod
    def process_ke_dsa_random(self, data: bytes) -> str:
        """Process peer's KE_DSA_RANDOM message."""
    
    @abstractmethod
    def create_ke_mlkem_pubkey(self) -> bytes:
        """Create KE_MLKEM_PUBKEY message: signed ML-KEM public key."""
    
    @abstractmethod
    def process_ke_mlkem_pubkey(self, data: bytes) -> None:
        """Process peer's KE_MLKEM_PUBKEY message."""
    
    @abstractmethod
    def create_ke_mlkem_ct_keys(self) -> bytes:
        """Create KE_MLKEM_CT_KEYS message."""
    
    @abstractmethod
    def process_ke_mlkem_ct_keys(self, data: bytes) -> None:
        """Process peer's KE_MLKEM_CT_KEYS message."""
    
    @abstractmethod
    def create_ke_x25519_hqc_ct(self) -> bytes:
        """Create KE_X25519_HQC_CT message."""
    
    @abstractmethod
    def process_ke_x25519_hqc_ct(self, data: bytes) -> None:
        """Process peer's KE_X25519_HQC_CT message."""
    
    @abstractmethod
    def create_ke_verification(self) -> bytes:
        """Create KE_VERIFICATION message."""
    
    @abstractmethod
    def process_ke_verification(self, data: bytes) -> bool:
        """Process peer's KE_VERIFICATION message."""
    
    @abstractmethod
    def set_server_identifier(self, identifier: str) -> None:
        """Set the server identifier for use in key derivations."""
    
    # Encryption / decryption
    
    @abstractmethod
    def encrypt_message(self, plaintext: str) -> bytes:
        """Encrypt a plaintext message with authentication and replay protection."""
    
    @abstractmethod
    def decrypt_message(self, data: bytes) -> str:
        """Decrypt and authenticate a message."""
    
    @abstractmethod
    def encrypt_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes) -> bytes:
        """Encrypt a file chunk using the Double Ratchet."""
    
    @abstractmethod
    def decrypt_file_chunk(self, encrypted_data: bytes) -> dict:
        """Decrypt a file chunk frame produced by encrypt_file_chunk."""
    
    # Rekeying
    
    @abstractmethod
    def activate_pending_keys(self) -> None:
        """Atomically switch active session to the pending keys."""
    
    @abstractmethod
    def create_rekey_init(self) -> dict[str, str | int]:
        """Create a REKEY init payload."""
    
    @abstractmethod
    def process_rekey_init(self, message: dict[Any, Any]) -> dict[str, int | str]:
        """Process a REKEY init payload and return REKEY response payload."""
    
    @abstractmethod
    def process_rekey_response(self, message: dict) -> dict:
        """Process a REKEY response payload and return commit payload."""
    
    @abstractmethod
    def reset_auto_rekey_counter(self) -> None:
        """Reset the automatic rekey message counter"""
    
    @property
    @abstractmethod
    def client(self) -> "ClientBase | None":
        """The client instance this protocol reports errors to."""
    
    @client.setter
    @abstractmethod
    def client(self, value: "ClientBase") -> None:
        """Set the client instance."""
