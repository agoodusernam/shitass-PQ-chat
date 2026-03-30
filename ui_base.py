"""
Abstract base class for UI implementations.

Every concrete UI must subclass ``UIBase`` and populate the ``capabilities``
dictionary.  The client core calls into the UI through the methods defined
here; a UI may also register event callbacks via ``register_event_handler``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Flag, auto
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Capability flags
# ---------------------------------------------------------------------------

class UICapability(Flag):
    """Bit-flags that describe what a UI front-end supports.

    The client core inspects these to decide whether to offer certain
    features (e.g. automatically reject voice calls when the UI cannot
    handle them).
    """
    NONE = 0
    TEXT_MESSAGING = auto()
    FILE_TRANSFER = auto()
    VOICE_CALLS = auto()
    EPHEMERAL_MODE = auto()
    DEADDROP = auto()
    DELIVERY_STATUS = auto()
    NICKNAMES = auto()
    
    ALL = (
        TEXT_MESSAGING
        | FILE_TRANSFER # type: ignore
        | VOICE_CALLS
        | EPHEMERAL_MODE
        | DEADDROP
        | DELIVERY_STATUS
        | NICKNAMES
    )

# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class UIBase(ABC):
    """Abstract base for all UI front-ends (GUI, TUI, headless, …)."""
    
    # -- capabilities -------------------------------------------------------
    
    @property
    def capabilities(self) -> UICapability:
        """Return the set of features this UI supports.

        Subclasses should override this to advertise their capabilities.
        The default is ``TEXT_MESSAGING`` only.
        """
        return UICapability.TEXT_MESSAGING
    
    def has_capability(self, cap: UICapability) -> bool:
        """Convenience: check whether *cap* is among the UI's capabilities."""
        return bool(self.capabilities & cap)
    
    # -- display (required) -------------------------------------------------
    
    @abstractmethod
    def display_regular_message(self, message: str, nickname: str | None = None) -> None:
        """Display a regular chat message from the peer."""
        ...
    
    @abstractmethod
    def display_error_message(self, message: str) -> None:
        """Display an error message."""
        ...
    
    @abstractmethod
    def display_system_message(self, message: str) -> None:
        """Display a system/status message."""
        ...
    
    @abstractmethod
    def display_raw_message(self, message: str) -> None:
        """Display a message as-is."""
        ...
    
    # -- prompts (required) -------------------------------------------------
    
    @abstractmethod
    def prompt_key_verification(self, fingerprint: str) -> bool:
        """Show *fingerprint* and ask the user whether it matches.

        Returns ``True`` if the user confirms the fingerprint, ``False``
        otherwise.
        """
        ...
    
    @abstractmethod
    def prompt_file_transfer(
            self,
            filename: str,
            file_size: int,
            total_chunks: int,
            compressed_file_size: int | None = None
            ) -> Path | bool | None:
        """Ask the user whether to accept an incoming file transfer.
        If compressed_file_size is None, the file is uncompressed.
        If not, compressed_file_size is the claimed size of the actual data being sent,
        and file_size is the claimed size of the file when uncompressed.

        Should return either: the path of where to save to,
        True to save to the current directory,
        False to explicitly deny,
        and None to defer a response.
        """
        ...
    
    @abstractmethod
    def prompt_rekey(self) -> bool | None:
        """Ask the user whether to proceed with a rekey.

        Returns True to proceed, False to disconnect,
        and None to reject the rekey, but stay connected.
        The user SHOULD be warned if they choose to reject but stay connected.
        """
        ...
    
    # -- connection lifecycle -----------------------------------------------
    
    @abstractmethod
    def on_connected(self) -> None:
        """Called when the client successfully connects to the server."""
        ...
    
    @abstractmethod
    def on_graceful_disconnect(self, reason: str) -> None:
        """Called when the connection to the server is gracefully closed."""
        ...
    
    @abstractmethod
    def on_unexpected_disconnect(self, reason: str) -> None:
        """Called when the client gets unexpectedly disconnected"""
        ...
    
    # -- rekey events -------------------------------------------------------
    
    def on_rekey_initiated_by_peer(self) -> None:
        """Called when the peer initiates a rekey."""
    
    def on_rekey_complete(self) -> None:
        """Called when a rekey completes successfully."""
    
    def on_auto_rekey(self) -> None:
        """Called when an automatic rekey is triggered (message-count threshold)."""
    
    # -- key verification status from peer ----------------------------------
    
    def on_peer_verified_our_key(self, verified: bool) -> None:
        """Called when the peer reports whether they verified our key.

        *verified* is ``True`` when the peer confirmed the fingerprint,
        ``False`` when they explicitly rejected it.
        """
    
    # -- deaddrop events ----------------------------------------------------
    
    def on_deaddrop_handshake_started(self) -> None:
        """Called when a deaddrop handshake begins."""
    
    def on_deaddrop_handshake_complete(self) -> None:
        """Called when the deaddrop handshake finishes successfully."""
    
    def on_deaddrop_handshake_failed(self, reason: str) -> None:
        """Called when the deaddrop handshake fails."""
    
    def on_deaddrop_upload_started(self, name: str) -> None:
        """Called when a deaddrop upload begins."""
    
    def on_deaddrop_upload_progress(
            self,
            name: str,
            bytes_uploaded: int,
            total_bytes: int
            ) -> None:
        """Called to report deaddrop upload progress."""
    
    def on_deaddrop_upload_complete(self, name: str) -> None:
        """Called when a deaddrop upload finishes successfully."""
    
    def on_deaddrop_download_started(self, name: str) -> None:
        """Called when a deaddrop download begins."""
    
    def on_deaddrop_download_progress(
            self,
            name: str,
            bytes_downloaded: int,
            total_bytes: int,
            ) -> None:
        """Called to report deaddrop download progress."""
    
    def on_deaddrop_download_complete(self, name: str, output_path: str) -> None:
        """Called when a deaddrop download finishes successfully."""
    
    def on_deaddrop_check_result(self, name: str, exists: bool) -> None:
        """Called with the result of a deaddrop existence check."""
    
    # -- optional: voice calls ----------------------------------------------
    
    def on_voice_call_init(self, init_msg: dict[str, Any]) -> None:
        """Called when an incoming voice call is received."""
    
    def on_voice_call_accept(self, message: dict[str, Any]) -> None:
        """Called when the peer accepts a voice call."""
    
    def on_voice_call_reject(self) -> None:
        """Called when the peer rejects a voice call."""
    
    def on_voice_call_data(self, data: dict[str, Any]) -> None:
        """Called when voice-call audio data arrives."""
    
    def on_voice_call_end(self) -> None:
        """Called when a voice call ends."""
    
    # -- optional: file transfer progress -----------------------------------
    
    def file_download_progress(
            self,
            transfer_id: str,
            filename: str,
            received_chunks: int,
            total_chunks: int,
            bytes_transferred: int = -1,
            ) -> None:
        """Called to report file-transfer chunk progress."""
    
    def file_upload_progress(
            self,
            transfer_id: str,
            filename: str,
            sent_chunks: int,
            total_chunks: int,
            bytes_transferred: int = -1,
            ) -> None:
        """Called to report file-transfer chunk progress."""
    
    def on_file_transfer_complete(self, transfer_id: str, output_path: str) -> None:
        """Called when a file transfer finishes successfully."""
    
    # -- optional: delivery status ------------------------------------------
    
    def on_delivery_confirmation(self, message_counter: int) -> None:
        """Called when a sent message's delivery is confirmed by the peer."""
    
    # -- optional: ephemeral messages ---------------------------------------
    
    def on_ephemeral_mode_change(self, mode: str, owner_id: str | None) -> None:
        """Called when the ephemeral-message mode changes."""
    
    # -- optional: emergency close ------------------------------------------
    
    def on_emergency_close(self) -> None:
        """Called when the peer triggers an emergency close."""
    
    # -- optional: key exchange UI updates ----------------------------------
    
    def on_key_exchange_started(self) -> None:
        """Called when a key exchange begins."""
    
    def on_key_exchange_complete(self) -> None:
        """Called when a key exchange completes."""
    
    # -- optional: nickname -------------------------------------------------
    
    def on_nickname_change(self, new_nickname: str) -> None:
        """Called when the peer changes their nickname."""
