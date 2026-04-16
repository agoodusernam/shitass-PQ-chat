# mypy: disable-error-code="attr-defined, assignment, arg-type"
"""
Comprehensive tests for new_client.py — SecureChatClient.

Covers:
- Initialisation and property defaults
- send_message (guards, queuing)
- handle_message routing (KE messages, encrypted, keepalive, error, unknown)
- handle_encrypted_message (decrypt, inner type dispatch)
- handle_message_types (text, dummy, delivery confirmation, nickname change, emergency close)
- handle_ke_* dispatch (step logic)
- handle_key_verification_message
- handle_key_exchange_reset
- handle_emergency_close
- handle_rekey (init / response / commit)
- handle_delivery_confirmation
- handle_maybe_binary_chunk
- rate-limiting
- next_message_counter property
- reject_file_transfer
- own_nickname setter
- bypass_rate_limits
- End-to-end: two clients exchange keys and messages via in-memory bytes
"""

import json
import os
from unittest.mock import MagicMock, patch

from new_client import SecureChatClient
from protocol.constants import MAGIC_NUMBER_FILE_TRANSFER, MessageType
from protocol.shared import SecureChatProtocol


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_ui() -> MagicMock:
    """Return a MagicMock that satisfies the UIBase interface."""
    ui = MagicMock()
    ui.has_capability = MagicMock(return_value=False)
    # Return a real bool so JSON serialisation works
    ui.prompt_key_verification = MagicMock(return_value=True)
    ui.prompt_rekey = MagicMock(return_value=True)
    ui.prompt_file_transfer = MagicMock(return_value=False)
    return ui


def _make_client(ui=None) -> SecureChatClient:
    if ui is None:
        ui = _make_ui()
    return SecureChatClient(ui)


def _full_ke_protocol_pair(server_id: str = "test") -> tuple[SecureChatProtocol, SecureChatProtocol]:
    """Return two SecureChatProtocol instances that have completed key exchange."""
    from tests.test_protocol_shared import _full_key_exchange
    
    return _full_key_exchange(server_id)


def _inject_ready_protocol(client: SecureChatClient, protocol: SecureChatProtocol) -> None:
    """Replace the client's internal protocol with a ready one and mark KE complete."""
    client._protocol = protocol
    client._key_exchange_complete = True
    client._verification_complete = True
    client._peer_key_verified = True


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestClientInit:
    def test_connected_false_on_init(self) -> None:
        c = _make_client()
        assert c.connected is False
    
    def test_key_exchange_complete_false_on_init(self) -> None:
        c = _make_client()
        assert c.key_exchange_complete is False
    
    def test_verification_complete_false_on_init(self) -> None:
        c = _make_client()
        assert c.verification_complete is False
    
    def test_voice_call_not_active_on_init(self) -> None:
        c = _make_client()
        assert c.voice_call_active is False
    
    def test_default_peer_nickname(self) -> None:
        c = _make_client()
        assert c.peer_nickname == "Other user"
    
    def test_default_own_nickname(self) -> None:
        c = _make_client()
        assert c.own_nickname == "You"
    
    def test_protocol_instance_created(self) -> None:
        c = _make_client()
        assert isinstance(c._protocol, SecureChatProtocol)
    
    def test_file_transfer_active_false_on_init(self) -> None:
        c = _make_client()
        assert c.file_transfer_active is False
    
    def test_pending_file_requests_empty(self) -> None:
        c = _make_client()
        assert len(c.pending_file_requests) == 0


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestClientProperties:
    def test_own_nickname_setter(self) -> None:
        c = _make_client()
        c.own_nickname = "Alice"
        assert c.own_nickname == "Alice"
    
    def test_own_nickname_stored_as_given(self) -> None:
        c = _make_client()
        long_name = "A" * 50
        c.own_nickname = long_name
        assert c.own_nickname == long_name
    
    def test_next_message_counter_is_protocol_counter_plus_one(self) -> None:
        c = _make_client()
        assert c.next_message_counter == c._protocol.message_counter + 1
    
    def test_peer_verified_key_false_on_init(self) -> None:
        c = _make_client()
        assert c.peer_verified_key is False
    
    def test_peer_key_verified_false_on_init(self) -> None:
        c = _make_client()
        assert c.peer_key_verified is False
    
    def test_bypass_rate_limits_false_by_default(self) -> None:
        c = _make_client()
        assert c.bypass_rate_limits is False


# ---------------------------------------------------------------------------
# send_message
# ---------------------------------------------------------------------------


class TestSendMessage:
    def test_send_message_before_ke_returns_false(self) -> None:
        c = _make_client()
        result = c.send_message("hello")
        assert result is False
        c.ui.display_error_message.assert_called()
    
    def test_send_message_before_encryption_ready_returns_false(self) -> None:
        c = _make_client()
        c._key_exchange_complete = True
        # protocol.encryption_ready is False (no shared key)
        result = c.send_message("hello")
        assert result is False
    
    def test_send_message_queues_encrypt_text_tuple(self) -> None:
        c = _make_client()
        proto_a, _ = _full_ke_protocol_pair()
        _inject_ready_protocol(c, proto_a)
        
        result = c.send_message("test message")
        assert result is True
        assert len(c._protocol._message_queue) >= 1
        item = c._protocol._message_queue[0]
        assert isinstance(item, tuple)
        assert item[0].value == "encrypt_text"
        assert item[1] == "test message"
    
    def test_send_message_unverified_peer_shows_warning(self) -> None:
        c = _make_client()
        proto_a, _ = _full_ke_protocol_pair()
        _inject_ready_protocol(c, proto_a)
        c._peer_key_verified = False
        
        c.send_message("hi")
        c.ui.display_system_message.assert_called()
    
    # ---------------------------------------------------------------------------


# handle_message routing
# ---------------------------------------------------------------------------


class TestHandleMessageRouting:
    def _make_json_msg(self, msg_type: MessageType, extra: dict | None = None) -> bytes:
        d = {"type": int(msg_type)}
        if extra:
            d.update(extra)
        return json.dumps(d).encode()
    
    def test_routes_keepalive(self) -> None:
        c = _make_client()
        with patch.object(c, "handle_keepalive") as mock_ka:
            with patch("new_client.send_message"):
                c.handle_message(self._make_json_msg(MessageType.KEEP_ALIVE))
        mock_ka.assert_called_once()
    
    def test_routes_error_message(self) -> None:
        c = _make_client()
        c.handle_message(self._make_json_msg(MessageType.ERROR, {"error": "oops"}))
        c.ui.display_error_message.assert_called()
    
    def test_routes_server_full(self) -> None:
        c = _make_client()
        with patch.object(c, "handle_server_full") as mock_sf:
            c.handle_message(self._make_json_msg(MessageType.SERVER_FULL))
        mock_sf.assert_called_once()
    
    def test_encrypted_before_ke_shows_error(self) -> None:
        c = _make_client()
        c.handle_message(self._make_json_msg(MessageType.ENCRYPTED_MESSAGE))
        c.ui.display_error_message.assert_called()
    
    def test_invalid_json_tries_binary_chunk(self) -> None:
        c = _make_client()
        with patch.object(c, "handle_maybe_binary_chunk", return_value=True) as mock_bin:
            c.handle_message(b"\xff\xfe not json at all")
        mock_bin.assert_called_once()
    
    def test_invalid_json_not_binary_shows_error(self) -> None:
        c = _make_client()
        with patch.object(c, "handle_maybe_binary_chunk", return_value=False):
            c.handle_message(b"not json")
        c.ui.display_error_message.assert_called()
    
    def test_unexpected_outer_field_drops_message(self) -> None:
        c = _make_client()
        # Inject an unexpected field into a KE_DSA_RANDOM message
        msg = json.dumps({
            "type":       int(MessageType.KE_DSA_RANDOM),
            "evil_field": "bad",
        }).encode()
        with patch.object(c, "handle_ke_dsa_random") as mock_ke:
            c.handle_message(msg)
        mock_ke.assert_not_called()
        c.ui.display_error_message.assert_called()
    
    def test_routes_ke_verification(self) -> None:
        c = _make_client()
        with patch.object(c, "handle_ke_verification") as mock_kv:
            c.handle_message(self._make_json_msg(MessageType.KE_VERIFICATION))
        mock_kv.assert_called_once()
    
    def test_routes_key_exchange_reset(self) -> None:
        c = _make_client()
        with patch.object(c, "handle_key_exchange_reset") as mock_ker:
            c.handle_message(self._make_json_msg(MessageType.KEY_EXCHANGE_RESET,
                                                 {"message": "reset"}))
        mock_ker.assert_called_once()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def _make_json_msg(self, msg_type: MessageType) -> bytes:
        return json.dumps({"type": int(msg_type)}).encode()
    
    def test_rate_limit_drops_after_6_messages(self) -> None:
        c = _make_client()
        assert c.bypass_rate_limits is False
        # Send 6 keepalives (allowed)
        with patch.object(c, "handle_keepalive"):
            with patch("new_client.send_message"):
                for _ in range(6):
                    c.handle_message(self._make_json_msg(MessageType.KEEP_ALIVE))
        # 7th should be rate-limited
        c.handle_message(self._make_json_msg(MessageType.KEEP_ALIVE))
        c.ui.display_error_message.assert_called()
    
    def test_bypass_rate_limits_skips_check(self) -> None:
        c = _make_client()
        # bypass_rate_limits is True when file_transfer_active is True (pending_file_transfers non-empty)
        c.pending_file_transfers["dummy"] = object()
        with patch.object(c, "handle_keepalive") as mock_ka:
            with patch("new_client.send_message"):
                for _ in range(10):
                    c.handle_message(self._make_json_msg(MessageType.KEEP_ALIVE))
        assert mock_ka.call_count == 10


# ---------------------------------------------------------------------------
# handle_encrypted_message
# ---------------------------------------------------------------------------


class TestHandleEncryptedMessage:
    def _setup_pair(self) -> tuple[SecureChatProtocol, SecureChatClient]:
        """Return (sender_protocol, receiver_client) with shared keys."""
        proto_a, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_b)
        return proto_a, c
    
    def test_decrypts_text_message_and_displays(self) -> None:
        proto_a, c = self._setup_pair()
        inner = json.dumps({"type": int(MessageType.TEXT_MESSAGE), "text": "hello"})
        ct = proto_a.encrypt_message(inner)
        c.handle_encrypted_message(ct)
        c.ui.display_regular_message.assert_called_once()
        args = c.ui.display_regular_message.call_args[0]
        assert "hello" in args[0]
    
    def test_decrypts_dummy_message_silently(self) -> None:
        proto_a, c = self._setup_pair()
        inner = json.dumps({"type": int(MessageType.DUMMY_MESSAGE), "data": "x"})
        ct = proto_a.encrypt_message(inner)
        c.handle_encrypted_message(ct)
        c.ui.display_regular_message.assert_not_called()
    
    def test_bad_ciphertext_shows_error(self) -> None:
        _, c = self._setup_pair()
        c.handle_encrypted_message(b"not valid ciphertext at all")
        c.ui.display_error_message.assert_called()
    
    def test_delivery_confirmation_calls_ui(self) -> None:
        proto_a, c = self._setup_pair()
        inner = json.dumps({
            "type":              int(MessageType.DELIVERY_CONFIRMATION),
            "confirmed_counter": 5,
        })
        ct = proto_a.encrypt_message(inner)
        c.handle_encrypted_message(ct)
        c.ui.on_delivery_confirmation.assert_called_once_with(5)
    
    def test_nickname_change_updates_peer_nickname(self) -> None:
        proto_a, c = self._setup_pair()
        inner = json.dumps({
            "type":     int(MessageType.NICKNAME_CHANGE),
            "nickname": "Bob",
        })
        ct = proto_a.encrypt_message(inner)
        c.handle_encrypted_message(ct)
        assert c.peer_nickname == "Bob"
    
    def test_unverified_peer_unexpected_inner_field_drops(self) -> None:
        proto_a, c = self._setup_pair()
        c._peer_key_verified = False
        inner = json.dumps({
            "type": int(MessageType.TEXT_MESSAGE),
            "text": "hi",
            "evil": "bad",
        })
        ct = proto_a.encrypt_message(inner)
        c.handle_encrypted_message(ct)
        c.ui.display_error_message.assert_called()
        c.ui.display_regular_message.assert_not_called()
    
    # ---------------------------------------------------------------------------


# handle_message_types
# ---------------------------------------------------------------------------

class TestHandleMessageTypes:
    def _make_client_with_proto(self) -> tuple[SecureChatProtocol, SecureChatClient]:
        proto_a, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_b)
        return proto_a, c
    
    def test_text_message_displays(self) -> None:
        _, c = self._make_client_with_proto()
        c.handle_message_types(
                MessageType.TEXT_MESSAGE,
                {"type": int(MessageType.TEXT_MESSAGE), "text": "hi there"},
                1,
        )
        c.ui.display_regular_message.assert_called_once()
    
    def test_dummy_message_no_display(self) -> None:
        _, c = self._make_client_with_proto()
        c.handle_message_types(
                MessageType.DUMMY_MESSAGE,
                {"type": int(MessageType.DUMMY_MESSAGE)},
                1,
        )
        c.ui.display_regular_message.assert_not_called()
    
    def test_delivery_confirmation_calls_ui(self) -> None:
        _, c = self._make_client_with_proto()
        c.handle_message_types(
                MessageType.DELIVERY_CONFIRMATION,
                {"type": int(MessageType.DELIVERY_CONFIRMATION), "confirmed_counter": 3},
                1,
        )
        c.ui.on_delivery_confirmation.assert_called_once_with(3)
    
    def test_unknown_inner_type_returns_false(self) -> None:
        _, c = self._make_client_with_proto()
        result = c.handle_message_types(
                MessageType.NONE,
                {"type": int(MessageType.NONE)},
                1,
        )
        assert result is False
    
    def test_emergency_close_calls_handler(self) -> None:
        _, c = self._make_client_with_proto()
        with patch.object(c, "handle_emergency_close") as mock_ec:
            c.handle_message_types(
                    MessageType.EMERGENCY_CLOSE,
                    {"type": int(MessageType.EMERGENCY_CLOSE)},
                    1,
            )
        mock_ec.assert_called_once()


# ---------------------------------------------------------------------------
# handle_keepalive
# ---------------------------------------------------------------------------


class TestHandleKeepalive:
    def test_keepalive_sends_response(self) -> None:
        c = _make_client()
        with patch("new_client.send_message") as mock_send:
            c.handle_keepalive()
        mock_send.assert_called_once()
        sent_data = mock_send.call_args[0][1]
        msg = json.loads(sent_data)
        assert msg["type"] == int(MessageType.KEEP_ALIVE_RESPONSE)


# ---------------------------------------------------------------------------
# handle_delivery_confirmation
# ---------------------------------------------------------------------------


class TestHandleDeliveryConfirmation:
    def test_calls_ui_on_delivery_confirmation(self) -> None:
        c = _make_client()
        c.handle_delivery_confirmation({"confirmed_counter": 7})
        c.ui.on_delivery_confirmation.assert_called_once_with(7)
    
    def test_missing_counter_does_not_crash(self) -> None:
        c = _make_client()
        c.handle_delivery_confirmation({})  # no confirmed_counter key
        c.ui.on_delivery_confirmation.assert_not_called()
    
    # ---------------------------------------------------------------------------


# handle_key_exchange_reset
# ---------------------------------------------------------------------------


class TestHandleKeyExchangeReset:
    def test_resets_protocol_state(self) -> None:
        c = _make_client()
        proto_a, _ = _full_ke_protocol_pair()
        _inject_ready_protocol(c, proto_a)
        assert c._protocol.shared_key is True
        
        reset_msg = json.dumps({
            "type":    int(MessageType.KEY_EXCHANGE_RESET),
            "message": "reset",
        }).encode()
        c.handle_key_exchange_reset(reset_msg)
        assert c._key_exchange_complete is False
    
    def test_shows_system_message(self) -> None:
        c = _make_client()
        reset_msg = json.dumps({
            "type":    int(MessageType.KEY_EXCHANGE_RESET),
            "message": "reset",
        }).encode()
        c.handle_key_exchange_reset(reset_msg)
        c.ui.display_system_message.assert_called()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# handle_emergency_close
# ---------------------------------------------------------------------------


class TestHandleEmergencyClose:
    def test_sets_connected_false(self) -> None:
        c = _make_client()
        c._connected = True
        c.handle_emergency_close()
        assert c._connected is False
    
    def test_calls_ui_on_emergency_close(self) -> None:
        c = _make_client()
        c.handle_emergency_close()
        c.ui.on_emergency_close.assert_called()
    
    def test_resets_key_exchange_complete(self) -> None:
        c = _make_client()
        c._key_exchange_complete = True
        c.handle_emergency_close()
        assert c._key_exchange_complete is False


# ---------------------------------------------------------------------------
# handle_maybe_binary_chunk
# ---------------------------------------------------------------------------


class TestHandleMaybeBinaryChunk:
    def test_too_short_returns_false(self) -> None:
        c = _make_client()
        assert c.handle_maybe_binary_chunk(b"\x00" * 10) is False
    
    def test_unknown_magic_returns_false(self) -> None:
        c = _make_client()
        data = b"\xAB" + b"\x00" * 60
        assert c.handle_maybe_binary_chunk(data) is False
    
    def test_file_transfer_magic_decrypts_and_handles(self) -> None:
        proto_a, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_b)
        
        chunk_data = os.urandom(128)
        frame = proto_a.encrypt_file_chunk("tid-1", 0, chunk_data)
        
        with patch.object(c, "handle_file_chunk_binary") as mock_fch:
            result = c.handle_maybe_binary_chunk(frame)
        assert result is True
        mock_fch.assert_called_once()
        call_arg = mock_fch.call_args[0][0]
        assert call_arg["chunk_data"] == chunk_data
    
    def test_file_transfer_magic_bad_data_returns_false(self) -> None:
        _, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_b)
        # Valid magic but garbage payload
        bad_frame = MAGIC_NUMBER_FILE_TRANSFER + b"\x00" * 60
        result = c.handle_maybe_binary_chunk(bad_frame)
        assert result is False


# ---------------------------------------------------------------------------
# handle_rekey
# ---------------------------------------------------------------------------


class TestHandleRekey:
    def test_rekey_dsa_random_sets_rekey_in_progress(self) -> None:
        """Receiving a dsa_random from peer starts B's rekey."""
        proto_a, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_b)
        
        dsa_random_msg = proto_a.create_rekey_dsa_random(is_initiator=True)
        
        with patch.object(c._protocol, "queue_json"):
            c.handle_rekey(dsa_random_msg)
        assert c._protocol.rekey_in_progress is True
    
    def test_rekey_verification_activates_keys(self) -> None:
        """Receiving a valid verification message on A's side activates pending keys."""
        proto_a, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_a)
        
        # Drive the rekey up to B having pending keys and verification ready
        msg1 = proto_a.create_rekey_dsa_random(is_initiator=True)
        msg2 = proto_b.process_rekey_dsa_random(msg1)
        msg3 = proto_a.process_rekey_dsa_random(msg2)
        msg4 = proto_b.process_rekey_mlkem_pubkey(msg3)
        proto_a.process_rekey_mlkem_ct_keys(msg4)  # sets pending keys on proto_a
        # (skip sending x25519_hqc_ct to proto_b for this test — we just need pending keys on proto_a)
        
        # Manually set pending keys on proto_b to create a valid verification
        msg5 = proto_a.process_rekey_mlkem_ct_keys(msg4) if not proto_a._pending_send_chain_key else None
        # At this point proto_a has pending keys. Fabricate a matching verification from proto_b.
        # We do this by copying proto_a's pending material to proto_b so it produces the same proof.
        proto_b._pending_key_verification_material = proto_a._pending_key_verification_material
        
        b_verif = proto_b.create_rekey_verification()
        with patch.object(c._protocol, "queue_json"):
            c.handle_rekey(b_verif)
        assert c._protocol.rekey_in_progress is False


# ---------------------------------------------------------------------------
# handle_ke_dsa_random (step logic)
# ---------------------------------------------------------------------------


class TestHandleKeDsaRandom:
    def test_client_b_responds_with_dsa_random(self) -> None:
        c = _make_client()
        # Client B: ke_step == 0
        assert c._protocol.ke_step == 0
        
        # Build a valid KE_DSA_RANDOM from a fresh protocol
        sender = SecureChatProtocol()
        sender.set_server_identifier("test")
        msg = sender.create_ke_dsa_random()
        
        with patch("new_client.send_message") as mock_send:
            c.handle_ke_dsa_random(msg)
        
        # Client B should have sent its own DSA random
        mock_send.assert_called_once()
        assert c._protocol.ke_step == 2
    
    def test_client_a_sends_mlkem_pubkey(self) -> None:
        c = _make_client()
        # Client A must have already generated DSA keys (done during initiate_key_exchange)
        with patch("new_client.send_message"):
            c.initiate_key_exchange()
        assert c._protocol.ke_step == 1
        
        sender = SecureChatProtocol()
        sender.set_server_identifier("test")
        msg = sender.create_ke_dsa_random()
        
        with patch("new_client.send_message") as mock_send:
            c.handle_ke_dsa_random(msg)
        
        mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# handle_key_verification_message
# ---------------------------------------------------------------------------


class TestHandleKeyVerificationMessage:
    def test_peer_verified_true_updates_flag(self) -> None:
        c = _make_client()
        msg = SecureChatProtocol.create_key_verification_message(True)
        c.handle_key_verification_message(msg)
        assert c._peer_verified_own_key is True
    
    def test_peer_verified_false_updates_flag(self) -> None:
        c = _make_client()
        msg = SecureChatProtocol.create_key_verification_message(False)
        c.handle_key_verification_message(msg)
        assert c._peer_verified_own_key is False


# ---------------------------------------------------------------------------
# reject_file_transfer
# ---------------------------------------------------------------------------


class TestRejectFileTransfer:
    def test_queues_file_reject_message(self) -> None:
        proto_a, proto_b = _full_ke_protocol_pair()
        c = _make_client()
        _inject_ready_protocol(c, proto_b)
        
        c.reject_file_transfer("transfer-xyz")
        # Should have queued an encrypt_json tuple
        assert len(c._protocol._message_queue) >= 1
        item = c._protocol._message_queue[-1]
        assert isinstance(item, tuple)
        assert item[0].value == "encrypt_json"
        assert item[1]["type"] == MessageType.FILE_REJECT
    
    def test_removes_from_active_metadata(self) -> None:
        c = _make_client()
        c.active_file_metadata["tid"] = {}
        c.reject_file_transfer("tid")
        assert "tid" not in c.active_file_metadata


# ---------------------------------------------------------------------------
# End-to-end: two clients exchange keys and messages via in-memory bytes
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """
    Simulate two clients performing a full key exchange and messaging
    without real sockets, by directly calling handle_message on each side
    with the bytes the other side would have sent.
    """
    
    def _make_pair(self) -> tuple[SecureChatClient, SecureChatClient]:
        ui_a = _make_ui()
        ui_b = _make_ui()
        alice = SecureChatClient(ui_a)
        bob = SecureChatClient(ui_b)
        alice._protocol.set_server_identifier("e2e-test")
        bob._protocol.set_server_identifier("e2e-test")
        return alice, bob
    
    def _do_ke(self, alice: SecureChatClient, bob: SecureChatClient):
        """Drive the full key exchange by intercepting send_message calls.

        Uses a shared queue per side. A single global patch captures all
        send_message calls (including those from confirm_key_verification).
        """
        sent_by_alice: list[bytes] = []
        sent_by_bob: list[bytes] = []
        _current_sender: list = [None]  # mutable cell
        
        def _send(sock: object, data: object) -> None:
            if _current_sender[0] == "alice":
                sent_by_alice.append(data)
            else:
                sent_by_bob.append(data)
        
        with patch("new_client.send_message", side_effect=_send):
            # Step 3: Alice initiates
            _current_sender[0] = "alice"
            alice.initiate_key_exchange()
            
            # Step 6: Bob receives Alice's DSA random, sends his own
            _current_sender[0] = "bob"
            bob.handle_message(sent_by_alice.pop(0))
            
            # Step 8: Alice receives Bob's DSA random, sends ML-KEM pubkey
            _current_sender[0] = "alice"
            alice.handle_message(sent_by_bob.pop(0))
            
            # Step 10: Bob receives ML-KEM pubkey, sends CT+keys
            _current_sender[0] = "bob"
            bob.handle_message(sent_by_alice.pop(0))
            
            # Step 13: Alice receives CT+keys, sends X25519+HQC CT
            _current_sender[0] = "alice"
            alice.handle_message(sent_by_bob.pop(0))
            
            # Step 15: Bob receives X25519+HQC CT, sends verification
            # (Bob also calls confirm_key_verification → more sends captured)
            _current_sender[0] = "bob"
            bob.handle_message(sent_by_alice.pop(0))
            
            # Step 16: Alice receives Bob's verification, sends her own
            # (Alice also calls confirm_key_verification → more sends captured)
            _current_sender[0] = "alice"
            alice.handle_message(sent_by_bob.pop(0))
            
            # Bob receives Alice's verification (KEY_VERIFICATION message)
            _current_sender[0] = "bob"
            bob.handle_message(sent_by_alice.pop(0))
        
        return alice, bob
    
    def test_ke_completes_both_sides(self) -> None:
        alice, bob = self._make_pair()
        alice, bob = self._do_ke(alice, bob)
        assert alice.key_exchange_complete is True
        assert bob.key_exchange_complete is True
    
    def test_message_delivered_after_ke(self) -> None:
        alice, bob = self._make_pair()
        alice, bob = self._do_ke(alice, bob)
        
        # Alice sends a text message
        alice._peer_key_verified = True
        alice.send_message("Hello Bob!")
        
        # Drain Alice's queue to find the encrypt_text item
        ct = self._drain_encrypt_text(alice._protocol, "Hello Bob!")
        
        bob._peer_key_verified = True
        bob.handle_encrypted_message(ct)
        bob.ui.display_regular_message.assert_called_once()
        args = bob.ui.display_regular_message.call_args[0]
        assert "Hello Bob!" in args[0]
    
    def _drain_encrypt_text(self, proto: SecureChatProtocol, text: str) -> bytes:
        """Pop items from the queue until we find the encrypt_text tuple for `text`."""
        queue = proto._message_queue
        while queue:
            item = queue.popleft()
            if isinstance(item, tuple) and item[0].value == "encrypt_text" and item[1] == text:
                assert isinstance(item[1], str)
                return proto._encrypt_text_message(item[1])
        raise AssertionError(f"encrypt_text item for {text!r} not found in queue")
    
    def test_bidirectional_messages_after_ke(self) -> None:
        alice, bob = self._make_pair()
        alice, bob = self._do_ke(alice, bob)
        alice._peer_key_verified = True
        bob._peer_key_verified = True
        
        # Alice → Bob
        alice.send_message("ping")
        ct_a = self._drain_encrypt_text(alice._protocol, "ping")
        bob.handle_encrypted_message(ct_a)
        bob.ui.display_regular_message.assert_called()
        
        # Bob → Alice
        bob.send_message("pong")
        ct_b = self._drain_encrypt_text(bob._protocol, "pong")
        alice.handle_encrypted_message(ct_b)
        alice.ui.display_regular_message.assert_called()
    
    def test_ke_shared_keys_match(self) -> None:
        alice, bob = self._make_pair()
        alice, bob = self._do_ke(alice, bob)
        # Both sides derive the same verification material (order-independent)
        assert alice._protocol._key_verification_material == bob._protocol._key_verification_material
        # Both sides have shared_key set
        assert alice._protocol.shared_key is True
        assert bob._protocol.shared_key is True
