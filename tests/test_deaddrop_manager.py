"""Tests for ``client.deaddrop_manager.DeaddropManager``.

These exercise the inner state transitions and the inner-message handlers
without standing up an actual server. The handshake-derived ``shared_secret``
is set directly when the test needs a session.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from new_client import SecureChatClient
from protocol.constants import (
    DEADDROP_KDF_KEY_LENGTH,
    DOUBLE_KEY_SIZE,
    MessageType,
)
from protocol.errors import ChatError


def _make_client() -> SecureChatClient:
    ui = MagicMock()
    ui.has_capability = MagicMock(return_value=False)
    c = SecureChatClient(ui)
    c._connection.server_identifier = "unit-test-server"
    return c


def _seed_session(c: SecureChatClient) -> None:
    """Skip handshake — install a fixed shared secret."""
    c._deaddrop.shared_secret = b"\x77" * DEADDROP_KDF_KEY_LENGTH
    c._deaddrop.supported = True


class TestSessionLifecycle:
    def test_session_inactive_by_default(self) -> None:
        c = _make_client()
        assert c._deaddrop.session_active is False
    
    def test_reset_clears_all_state(self) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop._chunks[0] = b"x"
        c._deaddrop._download_chunks[1] = b"y"
        c._deaddrop.download_in_progress = True
        c._deaddrop._dl_bytes_downloaded = 999
        c._deaddrop.reset()
        d = c._deaddrop
        assert d.shared_secret is None
        assert d.supported is False
        assert d._chunks == {}
        assert d._download_chunks == {}
        assert d.download_in_progress is False
        assert d._dl_bytes_downloaded == 0


class TestStartHandshake:
    def test_disconnected_errors(self) -> None:
        c = _make_client()
        c._connection._connected = False
        c._deaddrop.start_handshake()
        c.ui.on_error.assert_called_once()
    
    def test_in_progress_errors(self) -> None:
        c = _make_client()
        c._connection._connected = True
        c._deaddrop._in_progress = True
        c._deaddrop.start_handshake()
        c.ui.on_error.assert_called_once()
    
    def test_sends_start_frame(self) -> None:
        c = _make_client()
        c._connection._connected = True
        with patch.object(c, "send_encoded") as enc:
            c._deaddrop.start_handshake()
            enc.assert_called_once()
            payload = enc.call_args.args[0]
            assert payload == {"type": MessageType.DEADDROP_START}
        assert c._deaddrop._started is True


class TestWaitForHandshake:
    def test_not_started_errors(self) -> None:
        c = _make_client()
        c._connection._connected = True
        assert c._deaddrop.wait_for_handshake(timeout=0.01) is False
        c.ui.on_error.assert_called_once()
    
    def test_timeout_returns_false(self) -> None:
        c = _make_client()
        c._connection._connected = True
        c._deaddrop._started = True
        c._deaddrop._handshake_event.clear()
        assert c._deaddrop.wait_for_handshake(timeout=0.05) is False
    
    def test_completion_returns_true(self) -> None:
        c = _make_client()
        c._connection._connected = True
        c._deaddrop._started = True
        c._deaddrop.shared_secret = b"\x01" * 32
        c._deaddrop._handshake_event.set()
        assert c._deaddrop.wait_for_handshake(timeout=0.05) is True


class TestStartResponseHandler:
    def test_unsupported_clears_state(self) -> None:
        c = _make_client()
        c._deaddrop._in_progress = True
        c._deaddrop.handle_start_response({"supported": False, "reason": "no"})
        assert c._deaddrop.shared_secret is None
        assert c._deaddrop.supported is False
        c.ui.on_error.assert_called_once()
    
    def test_missing_mlkem_public_errors(self) -> None:
        c = _make_client()
        c._deaddrop.handle_start_response({"supported": True})
        c.ui.on_error.assert_called_once()
    
    def test_bad_base64_errors(self) -> None:
        c = _make_client()
        c._deaddrop.handle_start_response({"supported": True, "mlkem_public": "!!!"})
        c.ui.on_error.assert_called_once()


class TestEncryptedInputGuards:
    def test_no_session_errors(self) -> None:
        c = _make_client()
        c._deaddrop.handle_encrypted_message({"nonce": "x", "ciphertext": "y"})
        c.ui.on_error.assert_called_once()
    
    def test_malformed_fields_error(self) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop.handle_encrypted_message({"nonce": "x"})  # missing ciphertext
        c.ui.on_error.assert_called_once()
    
    def test_bad_base64_error(self) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop.handle_encrypted_message({"nonce": "!!!", "ciphertext": "!!!"})
        c.ui.on_error.assert_called_once()
    
    def test_decryption_failure_reports(self) -> None:
        c = _make_client()
        _seed_session(c)
        # well-formed b64 but garbage ciphertext
        c._deaddrop.handle_encrypted_message(
                {
                    "nonce":      base64.b64encode(b"\x00" * 12).decode(),
                    "ciphertext": base64.b64encode(b"\x00" * 32).decode(),
                },
        )
        c.ui.on_error.assert_called_once()


class TestInnerMessageRoundtrip:
    """Use ``_encrypt_inner`` to produce a real frame and feed it back in."""
    
    def _wrap(self, c: SecureChatClient, inner: dict) -> dict:
        return c._deaddrop._encrypt_inner(json.dumps(inner).encode("utf-8"))
    
    def test_check_response_dispatches(self) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop._name = "alice"
        frame = self._wrap(
                c,
                {
                    "type":   MessageType.DEADDROP_CHECK_RESPONSE,
                    "exists": True,
                    "name":   "alice",
                },
        )
        c._deaddrop.handle_encrypted_message(frame)
        c.ui.on_deaddrop_check_result.assert_called_once_with("alice", True)
    
    def test_deny_clears_in_progress(self) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop._in_progress = True
        c._deaddrop.download_in_progress = True
        c._deaddrop._upload_accept_event.clear()
        frame = self._wrap(
                c,
                {
                    "type":   MessageType.DEADDROP_DENY,
                    "reason": "nope",
                },
        )
        c._deaddrop.handle_encrypted_message(frame)
        assert c._deaddrop._in_progress is False
        assert c._deaddrop.download_in_progress is False
        assert c._deaddrop._upload_accept_event.is_set()
    
    def test_accept_upload_path(self) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop._upload_accept_event.clear()
        frame = self._wrap(c, {"type": MessageType.DEADDROP_ACCEPT})
        c._deaddrop.handle_encrypted_message(frame)
        assert c._deaddrop._upload_accepted is True
        assert c._deaddrop._upload_accept_event.is_set()
    
    def test_unknown_inner_type_errors(self) -> None:
        c = _make_client()
        _seed_session(c)
        frame = self._wrap(c, {"type": 9999})
        c._deaddrop.handle_encrypted_message(frame)
        c.ui.on_error.assert_called_once()


class TestCryptoHelpers:
    def test_encrypt_inner_requires_session(self) -> None:
        c = _make_client()
        with pytest.raises(ChatError):
            c._deaddrop._encrypt_inner(b"x")
    
    def test_encrypt_inner_roundtrip(self) -> None:
        c = _make_client()
        _seed_session(c)
        wrapped = c._deaddrop._encrypt_inner(b"payload")
        assert wrapped["type"] == MessageType.DEADDROP_MESSAGE
        assert "nonce" in wrapped and "ciphertext" in wrapped
    
    def test_derive_file_key_length(self) -> None:
        c = _make_client()
        # Argon2id is slow; keep small
        with (
            patch("client.deaddrop_manager.Argon2id") as argon,
            patch("client.deaddrop_manager.HKDF") as hkdf,
        ):
            argon.return_value.derive.return_value = b"\x00" * DOUBLE_KEY_SIZE
            hkdf.return_value.derive.return_value = b"\x01" * DOUBLE_KEY_SIZE
            out = c._deaddrop._derive_file_key("pw", b"\x00" * 16)
        assert out == b"\x01" * DOUBLE_KEY_SIZE
    
    def test_hash_password_returns_b64(self) -> None:
        c = _make_client()
        with patch("client.deaddrop_manager.Argon2id") as argon:
            argon.return_value.derive.return_value = b"\xab" * DOUBLE_KEY_SIZE
            out = c._deaddrop._hash_password("pw")
        assert base64.b64decode(out) == b"\xab" * DOUBLE_KEY_SIZE


class TestGuardsRequiringSession:
    def test_upload_requires_session(self, tmp_path: Path) -> None:
        c = _make_client()
        p = tmp_path / "x"
        p.write_bytes(b"y")
        c._deaddrop.upload("name", "pw", p)
        c.ui.on_error.assert_called_once()
    
    def test_upload_missing_file_errors(self, tmp_path: Path) -> None:
        c = _make_client()
        _seed_session(c)
        c._deaddrop.upload("name", "pw", tmp_path / "missing")
        c.ui.on_error.assert_called_once()
    
    def test_check_requires_session(self) -> None:
        c = _make_client()
        c._deaddrop.check("name")
        c.ui.on_error.assert_called_once()
    
    def test_download_requires_session(self) -> None:
        c = _make_client()
        c._deaddrop.download("name", "pw")
        c.ui.on_error.assert_called_once()


class TestStreamingDownload:
    def test_unexpected_index_errors(self) -> None:
        c = _make_client()
        c._deaddrop._dl_expected_index = 0
        c._deaddrop._process_data_streaming(7, b"x")
        c.ui.on_error.assert_called_once()
    
    def test_missing_key_errors(self) -> None:
        c = _make_client()
        c._deaddrop._dl_expected_index = 0
        c._deaddrop._download_key = None
        c._deaddrop._process_data_streaming(0, b"x")
        c.ui.on_error.assert_called_once()
