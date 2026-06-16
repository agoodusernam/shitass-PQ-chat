"""Tests for ``client.voice_call_manager.VoiceCallManager``."""
from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

from new_client import SecureChatClient
from protocol.constants import MessageType
from SecureChatABCs.ui_base import UICapability


def _make_ui(supports_voice: bool = True) -> MagicMock:
    ui = MagicMock()
    ui.has_capability = MagicMock(
            side_effect=lambda cap: cap == UICapability.VOICE_CALLS and supports_voice,
    )
    return ui


def _make_client(ui: MagicMock | None = None) -> SecureChatClient:
    c = SecureChatClient(ui or _make_ui())
    c._connection.queue_json = MagicMock()
    return c


class TestRequest:
    def test_sets_active_and_queues_init(self) -> None:
        c = _make_client()
        c._peer_key_verified = True
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        
        c._voice_call.request(rate=16000, chunk_size=512, audio_format=8)
        
        assert c._voice_call.active is True
        c._connection.queue_json.assert_called_once()
        payload = c._connection.queue_json.call_args.args[0]
        assert payload["type"] == MessageType.VOICE_CALL_INIT
        assert payload["rate"] == 16000
        assert payload["chunk_size"] == 512
        assert payload["audio_format"] == 8
    
    def test_unverified_warns(self) -> None:
        ui = _make_ui()
        c = _make_client(ui)
        c._peer_key_verified = False
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call.request(8000, 256, 8)
        ui.display_system_message.assert_called_once()


class TestOnUserResponse:
    def test_accept_sets_active_and_queues(self) -> None:
        c = _make_client()
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call.on_user_response(True, 8000, 256, 8)
        assert c._voice_call.active is True
        payload = c._connection.queue_json.call_args.args[0]
        assert payload["type"] == MessageType.VOICE_CALL_ACCEPT
    
    def test_reject_does_not_activate(self) -> None:
        ui = _make_ui()
        c = _make_client(ui)
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call.on_user_response(False, 8000, 256, 8)
        assert c._voice_call.active is False
        c._connection.queue_json.assert_called_once_with({"type": MessageType.VOICE_CALL_REJECT})
        ui.display_system_message.assert_called_once()


class TestSendAudio:
    def test_inactive_no_send(self) -> None:
        c = _make_client()
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        with patch.object(c, "send_raw") as send:
            c._voice_call.send_audio(b"pcm")
            send.assert_not_called()
    
    def test_active_encrypts_and_sends(self) -> None:
        c = _make_client()
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._protocol.encrypt_message = MagicMock(return_value=b"ct")
        c._voice_call._active = True
        
        with patch.object(c, "send_raw") as send:
            c._voice_call.send_audio(b"pcmpayload")
            send.assert_called_once()
            (sent_bytes,) = send.call_args.args
            assert sent_bytes == b"ct"
        
        plain = c._protocol.encrypt_message.call_args.args[0]
        body = json.loads(plain)
        assert body["type"] == MessageType.VOICE_CALL_DATA
        assert base64.b64decode(body["audio_data"]) == b"pcmpayload"


class TestEnd:
    def test_inactive_noop(self) -> None:
        c = _make_client()
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call.end()
        c._connection.queue_json.assert_not_called()
    
    def test_active_notifies_peer(self) -> None:
        c = _make_client()
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call._active = True
        c._voice_call.end(notify_peer=True)
        assert c._voice_call.active is False
        assert c.send_dummy_messages is True
        c._connection.queue_json.assert_called_once_with({"type": MessageType.VOICE_CALL_END})
        c.ui.on_voice_call_end.assert_called_once()
    
    def test_active_without_peer_notification(self) -> None:
        c = _make_client()
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call._active = True
        c._voice_call.end(notify_peer=False)
        c._connection.queue_json.assert_not_called()
        c.ui.on_voice_call_end.assert_called_once()


class TestHandleInit:
    def test_unsupported_ui_auto_rejects(self) -> None:
        ui = _make_ui(supports_voice=False)
        c = _make_client(ui)
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call.handle_init({"rate": 8000})
        c._connection.queue_json.assert_called_once_with({"type": MessageType.VOICE_CALL_REJECT})
        ui.on_voice_call_init.assert_not_called()
    
    def test_supported_forwards_to_ui(self) -> None:
        ui = _make_ui(supports_voice=True)
        c = _make_client(ui)
        c._peer_key_verified = True
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        msg = {"rate": 16000, "chunk_size": 512, "audio_format": 8}
        c._voice_call.handle_init(msg)
        ui.on_voice_call_init.assert_called_once_with(msg)
        c._connection.queue_json.assert_not_called()
    
    def test_unverified_warns(self) -> None:
        ui = _make_ui(supports_voice=True)
        c = _make_client(ui)
        c._peer_key_verified = False
        c._protocol = MagicMock(rekey_in_progress=False, has_active_file_transfers=False)
        c._voice_call.handle_init({"rate": 8000})
        # warning + ui delegation
        assert ui.display_system_message.called
        ui.on_voice_call_init.assert_called_once()


class TestHandleAcceptRejectData:
    def test_accept_sets_active(self) -> None:
        c = _make_client()
        c._voice_call.handle_accept({"rate": 8000})
        assert c._voice_call.active is True
        c.ui.on_voice_call_accept.assert_called_once_with({"rate": 8000})
    
    def test_reject_clears_active(self) -> None:
        c = _make_client()
        c._voice_call._active = True
        c._voice_call.handle_reject()
        assert c._voice_call.active is False
        c.ui.on_voice_call_reject.assert_called_once()
    
    def test_data_when_inactive_ignored(self) -> None:
        c = _make_client()
        c._voice_call.handle_data({"audio_data": "x"})
        c.ui.on_voice_call_data.assert_not_called()
    
    def test_data_when_active_forwarded(self) -> None:
        c = _make_client()
        c._voice_call._active = True
        c._voice_call.handle_data({"audio_data": "x"})
        c.ui.on_voice_call_data.assert_called_once_with({"audio_data": "x"})
    
    def test_handle_end_clears_active(self) -> None:
        c = _make_client()
        c._voice_call._active = True
        c._voice_call.handle_end()
        assert c._voice_call.active is False
        c.ui.on_voice_call_end.assert_called_once()
