"""Voice call manager.

Owns voice call state (active, muted) and handles signaling frames
(init/accept/reject/end) plus encrypted audio data frames.
"""
from __future__ import annotations

import base64
import json
from socket import socket
from typing import TYPE_CHECKING, Any

from SecureChatABCs.ui_base import UIBase, UICapability
from SecureChatABCs.protocol_base import ProtocolBase
from protocol.constants import MessageType
from utils import network_utils

if TYPE_CHECKING:
    from new_client import SecureChatClient


class VoiceCallManager:
    """Manages voice call signaling and audio data transport."""

    def __init__(self, client: "SecureChatClient") -> None:
        self._client = client
        self._active: bool = False
        self.muted: bool = False

    @property
    def _ui(self) -> UIBase:
        return self._client.ui

    @property
    def _protocol(self) -> ProtocolBase:
        return self._client._protocol

    @property
    def _socket(self) -> socket:
        return self._client._socket

    @property
    def active(self) -> bool:
        return self._active

    def request(self, rate: int, chunk_size: int, audio_format: int) -> None:
        """Send a voice call initiation request to the peer."""
        if not self._client.peer_key_verified:
            self._ui.display_system_message(
                    "Warning: Requesting a voice call over an unverified connection. "
                    "This is vulnerable to MitM attacks.",
            )
        # Flip active now so inbound VOICE_CALL_DATA frames bypass the rate limiter.
        # Peer's audio thread writes directly to the socket (not through the 250 ms
        # sender queue), so audio frames can arrive before the queued VOICE_CALL_ACCEPT.
        self._active = True
        self._protocol.queue_json({
            "type":         MessageType.VOICE_CALL_INIT,
            "rate":         rate,
            "chunk_size":   chunk_size,
            "audio_format": audio_format,
        })

    def on_user_response(self, accepted: bool, rate: int, chunk_size: int, audio_format: int) -> None:
        """Handle local user's response to an incoming voice call."""
        if accepted:
            self._active = True
            self._protocol.queue_json({
                "type":         MessageType.VOICE_CALL_ACCEPT,
                "rate":         rate,
                "chunk_size":   chunk_size,
                "audio_format": audio_format,
            })
        else:
            self._protocol.queue_json({"type": MessageType.VOICE_CALL_REJECT})
            self._ui.display_system_message("Rejected voice call")

    def send_audio(self, audio_data: bytes) -> None:
        """Send voice data to peer during an active voice call."""
        if not (self._active and self._protocol):
            return
        message = json.dumps({
            "type":       MessageType.VOICE_CALL_DATA,
            "audio_data": base64.b64encode(audio_data).decode('utf-8'),
        })
        network_utils.send_message(self._socket, self._protocol.encrypt_message(message))

    def end(self, notify_peer: bool = True) -> None:
        """End current voice call and optionally notify the peer."""
        if not self._active:
            return
        self._active = False
        self._protocol.send_dummy_messages = True
        if notify_peer:
            self._protocol.queue_json({"type": MessageType.VOICE_CALL_END})
            self._ui.display_system_message("Voice call ended")
        self._ui.on_voice_call_end()

    # incoming handlers

    def handle_init(self, init_msg: dict[str, Any]) -> None:
        """Handle incoming voice call request."""
        if not self._ui.has_capability(UICapability.VOICE_CALLS):
            self._protocol.queue_json({"type": MessageType.VOICE_CALL_REJECT})
            self._ui.display_system_message("Auto-rejected incoming voice call (unsupported by UI).")
            return

        if not self._client.peer_key_verified:
            self._ui.display_system_message(
                    "Warning: Incoming voice call over an unverified connection. "
                    "This is vulnerable to MitM attacks.",
            )

        self._ui.on_voice_call_init(init_msg)

    def handle_accept(self, message: dict[str, Any]) -> None:
        self._active = True
        self._ui.on_voice_call_accept(message)

    def handle_reject(self) -> None:
        self._active = False
        self._ui.on_voice_call_reject()

    def handle_data(self, data: dict[str, Any]) -> None:
        if not self._active:
            return
        self._ui.on_voice_call_data(data)

    def handle_end(self) -> None:
        self._active = False
        self._ui.on_voice_call_end()
