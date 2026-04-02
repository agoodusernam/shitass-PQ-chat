"""
Abstract base class for chat client implementations.

Every concrete client must subclass ``ClientBase`` and implement the
abstract methods.  If a client does not support a particular feature it
must raise ``UnsupportedError``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from protocol.types import FileMetadata
from SecureChatABCs.ui_base import UIBase


class UnsupportedError(Exception):
    """Raised when a client does not support a requested feature."""
    pass


class ClientBase(ABC):
    """
    Abstract base that every chat-client implementation must satisfy.

    The methods below are the *only* surface a UI layer is allowed to call.
    The client is responsible for calling the appropriate methods on the UI,
    networking, and message handling.
    The client calls the Protocol layer to handle the actual protocol logic,
    including cryptographic operations.
    """
    
    @abstractmethod
    def __init__(self, ui: UIBase | None = None) -> None:
        ...
    
    # -- connection lifecycle -----------------------------------------------
    
    @abstractmethod
    def connect(self, host: str, port: int) -> bool:
        """Connect to the server at *host*:*port*.

        Returns ``True`` on success, ``False`` on failure.
        """
        ...
    
    @abstractmethod
    def disconnect(self) -> None:
        """Gracefully disconnect from the server."""
        ...
    
    # -- session state -------------------------------
    
    @property
    @abstractmethod
    def connected(self) -> bool:
        """Whether the client is currently connected to the server."""
        ...
    
    @property
    @abstractmethod
    def key_exchange_complete(self) -> bool:
        """Whether the initial key exchange has finished."""
        ...
    
    @property
    @abstractmethod
    def verification_complete(self) -> bool:
        """Whether key verification with the peer has completed."""
        ...
    
    @property
    @abstractmethod
    def verification_started(self) -> bool:
        """Whether key verification has been started."""
        ...
    
    @property
    @abstractmethod
    def peer_key_verified(self) -> bool:
        """Whether the peer's key has been verified by us."""
        ...
    
    @peer_key_verified.setter
    @abstractmethod
    def peer_key_verified(self, value: bool) -> None:
        ...
    
    @property
    @abstractmethod
    def voice_call_active(self) -> bool:
        """Whether a voice call is currently in progress."""
        ...
    
    @property
    @abstractmethod
    def voice_muted(self) -> bool:
        """Whether the local microphone is muted during a voice call."""
        ...
    
    @voice_muted.setter
    @abstractmethod
    def voice_muted(self, value: bool) -> None:
        ...
    
    @property
    def file_transfer_active(self) -> bool:
        """Whether any file transfer is currently in progress."""
        return False
    
    @property
    def file_transfer_update_interval(self) -> int:
        """The interval for sending file transfer updates to the UI"""
        return -1
    
    @file_transfer_update_interval.setter
    def file_transfer_update_interval(self, value: int) -> None:
        ...
    
    # -- preferences ----------------------------------------
    # Whether incoming file transfers are accepted
    allow_file_transfers: bool = False
    
    # The interval for sending chunk progress to the UI
    file_transfer_progress_interval: int = -1
    
    # Whether delivery receipts are sent to the peer
    send_delivery_receipts: bool = False
    
    @property
    def next_message_counter(self) -> int:
        return 0
    
    @property
    @abstractmethod
    def own_nickname(self) -> str:
        """Retrieve the nickname of the local user."""
    
    @own_nickname.setter
    @abstractmethod
    def own_nickname(self, value: str) -> None:
        """Set the nickname of the local user."""
    
    # -- messaging ----------------------------------------------------------
    
    @abstractmethod
    def send_message(self, text: str) -> bool:
        """Encrypt and send a text message to the peer.

        Returns ``True`` if the message was queued/sent successfully.
        """
        ...
    
    # -- file transfer ------------------------------------------------------
    
    def send_file(self, file_path: Path | str, compress: bool = True) -> None:
        """Initiate sending a file to the peer."""
        raise UnsupportedError("File transfer not supported")
    
    def reject_file_transfer(self, transfer_id: str) -> None:
        """Reject a pending incoming file transfer."""
        raise UnsupportedError("File transfer not supported")
    
    @property
    def pending_file_requests(self) -> dict[str, FileMetadata]:
        """Mapping of transfer-id → metadata for pending incoming files."""
        raise UnsupportedError("File transfer not supported")
    
    # -- key exchange & verification ----------------------------------------
    
    @abstractmethod
    def initiate_rekey(self) -> None:
        """Start a new key exchange (rekey) with the peer."""
        ...
    
    @abstractmethod
    def confirm_key_verification(self, verified: bool) -> None:
        """Report the result of the user's fingerprint verification.

        *verified* is ``True`` when the user confirms the fingerprint
        matches, ``False`` otherwise.
        """
        ...
    
    @property
    @abstractmethod
    def own_key_fingerprint(self) -> str:
        """Return the local key fingerprint string for display."""
        ...
    
    # -- voice calls --------------------------------------------------------
    
    def request_voice_call(
            self,
            rate: int,
            chunk_size: int,
            audio_format: int,
    ) -> None:
        """Initiate a voice call with the given audio parameters."""
        raise UnsupportedError("Voice calls are not supported")
    
    def on_user_response(
            self,
            accepted: bool,
            rate: int,
            chunk_size: int,
            audio_format: int,
    ) -> None:
        """Relay the user's accept/reject decision for an incoming voice call."""
        raise UnsupportedError("Voice calls are not supported")
    
    def end_call(self, notify_peer: bool = True) -> None:
        """End the current voice call."""
        ...
    
    def send_voice_data(self, audio_data: bytes) -> None:
        """Send a chunk of voice audio data to the peer."""
        raise UnsupportedError("Voice calls are not supported")
    
    # -- ephemeral messaging ------------------------------------------------
    
    @abstractmethod
    def send_ephemeral_mode_change(self, mode: str, owner_id: str | None) -> None:
        """Notify the peer of an ephemeral-mode change."""
        ...
    
    # -- deaddrop -----------------------------------------------------------
    
    def deaddrop_session_active(self) -> bool:
        """Whether a deaddrop session is currently active."""
        raise UnsupportedError("Deaddrop is not supported")
    
    def start_deaddrop(self) -> None:
        """Initiate a deaddrop session with the server."""
        raise UnsupportedError("Deaddrop is not supported")
    
    def wait_for_deaddrop_handshake(self, timeout: float = 3.0) -> bool:
        """Block until the deaddrop handshake completes.

        Returns ``True`` if the handshake succeeded within *timeout*
        seconds, ``False`` otherwise.
        """
        raise UnsupportedError("Deaddrop is not supported")
    
    def deaddrop_upload(self, name: str, password: str, file_path: Path) -> None:
        """Upload a file to the deaddrop under *name* protected by *password*."""
        raise UnsupportedError("Deaddrop is not supported")
    
    def deaddrop_check(self, name: str) -> None:
        """Check whether a deaddrop entry with *name* exists."""
        raise UnsupportedError("Deaddrop is not supported")
    
    def deaddrop_download(self, name: str, password: str) -> None:
        """Download a deaddrop entry identified by *name* and *password*."""
        raise UnsupportedError("Deaddrop is not supported")
    
    @abstractmethod
    def emergency_close(self) -> None:
        """Perform an emergency close: wipe keys and disconnect immediately."""
        ...
