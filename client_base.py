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


class UnsupportedError(Exception):
    """Raised when a client does not support a requested feature."""
    pass


class ClientBase(ABC):
    """Abstract base that every chat-client implementation must satisfy.

    The methods below are the *only* surface a UI layer is allowed to call.
    Internal/background helpers (message handling, crypto, networking) are
    intentionally excluded.
    """

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
    def voice_muted(self, value: bool) -> None: ...

    @property
    @abstractmethod
    def file_transfer_active(self) -> bool:
        """Whether any file transfer is currently in progress."""
        ...

    # -- preferences ----------------------------------------

    @property
    @abstractmethod
    def allow_file_transfers(self) -> bool:
        """Whether incoming file transfers are accepted."""
        ...
    
    @allow_file_transfers.setter
    @abstractmethod
    def allow_file_transfers(self, value: bool) -> None:
        ...
    
    @property
    @abstractmethod
    def file_transfer_progress_interval(self) -> int:
        """The interval for sending chunk progress to the UI"""
        ...
    
    @file_transfer_progress_interval.setter
    @abstractmethod
    def file_transfer_progress_interval(self, value: int) -> None:
        ...

    @property
    @abstractmethod
    def send_delivery_receipts(self) -> bool:
        """Whether delivery receipts are sent to the peer."""
        ...
    
    @send_delivery_receipts.setter
    @abstractmethod
    def send_delivery_receipts(self, value: bool):
        ...


    # -- messaging ----------------------------------------------------------

    @abstractmethod
    def send_message(self, text: str) -> bool:
        """Encrypt and send a text message to the peer.

        Returns ``True`` if the message was queued/sent successfully.
        """
        ...

    # -- file transfer ------------------------------------------------------

    @abstractmethod
    def send_file(self, file_path: Path | str, compress: bool = True) -> None:
        """Initiate sending a file to the peer."""
        ...

    @abstractmethod
    def reject_file_transfer(self, transfer_id: str) -> None:
        """Reject a pending incoming file transfer."""
        ...

    @property
    @abstractmethod
    def pending_file_requests(self) -> dict[str, FileMetadata]:
        """Mapping of transfer-id → metadata for pending incoming files."""
        ...

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

    @abstractmethod
    def get_own_key_fingerprint(self) -> str:
        """Return the local key fingerprint string for display."""
        ...

    # -- voice calls --------------------------------------------------------

    @abstractmethod
    def request_voice_call(
        self,
        rate: int,
        chunk_size: int,
        audio_format: int,
    ) -> None:
        """Initiate a voice call with the given audio parameters."""
        ...

    @abstractmethod
    def on_user_response(
        self,
        accepted: bool,
        rate: int,
        chunk_size: int,
        audio_format: int,
    ) -> None:
        """Relay the user's accept/reject decision for an incoming voice call."""
        ...

    @abstractmethod
    def end_call(self, notify_peer: bool = True) -> None:
        """End the current voice call."""
        ...

    @abstractmethod
    def send_voice_data(self, audio_data: bytes) -> None:
        """Send a chunk of voice audio data to the peer."""
        ...

    # -- ephemeral messaging ------------------------------------------------

    @abstractmethod
    def send_ephemeral_mode_change(self, mode: str, owner_id: str | None) -> None:
        """Notify the peer of an ephemeral-mode change."""
        ...

    # -- deaddrop -----------------------------------------------------------

    @abstractmethod
    def start_deaddrop(self) -> None:
        """Initiate a deaddrop session with the server."""
        ...

    @abstractmethod
    def wait_for_deaddrop_handshake(self, timeout: float = 3.0) -> bool:
        """Block until the deaddrop handshake completes.

        Returns ``True`` if the handshake succeeded within *timeout*
        seconds, ``False`` otherwise.
        """
        ...

    @abstractmethod
    def deaddrop_upload(self, name: str, password: str, file_path: str) -> None:
        """Upload a file to the deaddrop under *name* protected by *password*."""
        ...

    @abstractmethod
    def deaddrop_check(self, name: str) -> None:
        """Check whether a deaddrop entry with *name* exists."""
        ...

    @abstractmethod
    def deaddrop_download(self, name: str, password: str) -> None:
        """Download a deaddrop entry identified by *name* and *password*."""
        ...

    # -- emergency close ----------------------------------------------------

    @abstractmethod
    def emergency_close(self) -> None:
        """Perform an emergency close: wipe keys and disconnect immediately."""
        ...
    