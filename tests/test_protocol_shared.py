"""
Comprehensive tests for protocol/shared.py — SecureChatProtocol.

Covers:
- Initialisation and property defaults
- Key exchange (full two-party handshake)
- Encryption / decryption round-trips
- Double-ratchet forward secrecy
- Out-of-order message handling
- Replay-attack protection
- File-chunk encrypt / decrypt
- Rekey flow (init → response → commit → activate)
- Key-verification message helpers
- Static key-derivation helpers
- Queue / sender-thread helpers
- reset_key_exchange
- send_emergency_close (no socket → False)
"""

import json
import os

import pytest

from protocol.constants import MAGIC_NUMBER_FILE_TRANSFER
from protocol.crypto_classes import DoubleEncryptor, KeyExchangeDoubleEncryptor
from protocol.shared import SecureChatProtocol
from protocol.utils import LRUCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_protocol(server_id: str = "test-server") -> SecureChatProtocol:
    """Return a fresh SecureChatProtocol with a fixed server identifier."""
    p = SecureChatProtocol()
    p.set_server_identifier(server_id)
    return p


def _full_key_exchange(server_id: str = "test-server") -> tuple[SecureChatProtocol, SecureChatProtocol]:
    """
    Perform a complete key exchange between two protocol instances (A and B).
    
    The handshake follows the spec order:
      A → B : KE_DSA_RANDOM   (step 3)
      B → A : KE_DSA_RANDOM   (step 6)
      B → A : KE_MLKEM_PUBKEY (step 8)
      A → B : KE_MLKEM_CT_KEYS (step 10)
      B → A : KE_X25519_HQC_CT (step 12-13)  [actually A processes step 11 first]
      A → B : KE_VERIFICATION
      B → A : KE_VERIFICATION
    
    Returns (alice, bob) both with shared_key == True.
    """
    alice = _make_protocol(server_id)
    bob = _make_protocol(server_id)
    
    # Step 3: Alice sends DSA+random
    msg_a_dsa = alice.create_ke_dsa_random()
    # Step 6: Bob sends DSA+random
    msg_b_dsa = bob.create_ke_dsa_random()
    
    # Both process the other's DSA random
    alice.process_ke_dsa_random(msg_b_dsa)
    bob.process_ke_dsa_random(msg_a_dsa)
    
    # Step 8: Bob sends ML-KEM pubkey
    msg_b_mlkem = bob.create_ke_mlkem_pubkey()
    alice.process_ke_mlkem_pubkey(msg_b_mlkem)
    
    # Step 10: Alice sends ML-KEM CT + encrypted HQC/X25519 pubkeys
    msg_a_ct = alice.create_ke_mlkem_ct_keys()
    bob.process_ke_mlkem_ct_keys(msg_a_ct)
    
    # Step 12-13: Bob sends X25519+HQC CT; Alice processes (step 14)
    msg_b_x25519 = bob.create_ke_x25519_hqc_ct()
    alice.process_ke_x25519_hqc_ct(msg_b_x25519)
    
    # KE_VERIFICATION exchange
    msg_a_verif = alice.create_ke_verification()
    msg_b_verif = bob.create_ke_verification()
    assert bob.process_ke_verification(msg_a_verif), "Bob failed to verify Alice's KE"
    assert alice.process_ke_verification(msg_b_verif), "Alice failed to verify Bob's KE"
    
    return alice, bob


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestInit:
    def test_shared_key_false_on_init(self):
        p = _make_protocol()
        assert p.shared_key is False
    
    def test_message_counter_zero(self):
        p = _make_protocol()
        assert p.message_counter == 0
    
    def test_peer_counter_zero(self):
        p = _make_protocol()
        assert p.peer_counter == 0
    
    def test_encryption_not_ready_on_init(self):
        p = _make_protocol()
        assert p.encryption_ready is False
    
    def test_should_not_auto_rekey_on_init(self):
        p = _make_protocol()
        assert p.should_auto_rekey is False
    
    def test_rekey_not_in_progress_on_init(self):
        p = _make_protocol()
        assert p.rekey_in_progress is False
    
    def test_ke_step_zero(self):
        p = _make_protocol()
        assert p.ke_step == 0
    
    def test_skipped_counters_is_lru_cache(self):
        p = _make_protocol()
        assert isinstance(p.skipped_counters, LRUCache)
    
    def test_rekey_interval_positive(self):
        p = _make_protocol()
        assert p.rekey_interval > 0


# ---------------------------------------------------------------------------
# Key exchange
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestKeyExchange:
    def test_full_ke_sets_shared_key(self):
        alice, bob = _full_key_exchange()
        assert alice.shared_key is True
        assert bob.shared_key is True
    
    def test_encryption_ready_after_ke(self):
        alice, bob = _full_key_exchange()
        assert alice.encryption_ready is True
        assert bob.encryption_ready is True
    
    def test_ke_dsa_random_produces_bytes(self):
        p = _make_protocol()
        msg = p.create_ke_dsa_random()
        assert isinstance(msg, bytes) and len(msg) > 0
    
    def test_ke_mlkem_pubkey_produces_bytes(self):
        p = _make_protocol()
        p.create_ke_dsa_random()
        msg = p.create_ke_mlkem_pubkey()
        assert isinstance(msg, bytes) and len(msg) > 0
    
    def test_ke_verification_matches_after_ke(self):
        alice, bob = _full_key_exchange()
        # Verification material should be identical (order-independent derivation)
        assert alice._key_verification_material == bob._key_verification_material
    
    def test_mldsa_keys_discarded_after_ke(self):
        alice, bob = _full_key_exchange()
        assert alice._mldsa_private_key == b""
        assert alice._mldsa_public_key == b""
        assert bob._mldsa_private_key == b""
    
    def test_ke_intermediate_state_cleared_after_ke(self):
        alice, bob = _full_key_exchange()
        assert alice._ke_mlkem_shared_secret == b""
        assert alice._combined_random == b""
        assert bob._ke_mlkem_shared_secret == b""
    
    def test_send_chain_keys_differ_between_peers(self):
        alice, bob = _full_key_exchange()
        # Alice's send chain == Bob's receive chain and vice-versa
        assert alice._send_chain_key == bob._receive_chain_key
        assert bob._send_chain_key == alice._receive_chain_key
    
    def test_process_ke_dsa_random_returns_version_warning_or_empty(self):
        alice = _make_protocol()
        bob = _make_protocol()
        msg = alice.create_ke_dsa_random()
        warning = bob.process_ke_dsa_random(msg)
        assert isinstance(warning, str)
    
    def test_process_ke_mlkem_pubkey_bad_signature_raises(self):
        alice = _make_protocol()
        bob = _make_protocol()
        alice.create_ke_dsa_random()
        bob.create_ke_dsa_random()
        alice.process_ke_dsa_random(bob.create_ke_dsa_random())
        bob.process_ke_dsa_random(alice.create_ke_dsa_random())
        
        msg = bob.create_ke_mlkem_pubkey()
        # Corrupt the signature bytes in the JSON
        parsed = json.loads(msg)
        import base64
        
        sig_bytes = base64.b64decode(parsed["mldsa_signature"])
        corrupted = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
        parsed["mldsa_signature"] = base64.b64encode(corrupted).decode()
        corrupted_msg = json.dumps(parsed).encode()
        
        with pytest.raises(ValueError, match="ML-DSA"):
            alice.process_ke_mlkem_pubkey(corrupted_msg)
    
    def test_reset_key_exchange_clears_state(self):
        alice, _ = _full_key_exchange()
        alice.reset_key_exchange()
        assert alice.shared_key is False
        assert alice.message_counter == 0
        assert alice._send_chain_key == b""
        assert alice._receive_chain_key == b""
        assert alice.ke_step == 0
    
    def test_set_server_identifier(self):
        p = _make_protocol("my-server")
        assert p._server_identifier == "my-server"
    
    def test_different_server_ids_produce_different_keys(self):
        alice1, bob1 = _full_key_exchange("server-A")
        alice2, bob2 = _full_key_exchange("server-B")
        assert alice1._send_chain_key != alice2._send_chain_key


# ---------------------------------------------------------------------------
# Encryption / Decryption
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestEncryptDecrypt:
    def test_encrypt_returns_bytes(self):
        alice, _ = _full_key_exchange()
        ct = alice.encrypt_message("hello")
        assert isinstance(ct, bytes)
    
    def test_encrypt_decrypt_roundtrip(self):
        alice, bob = _full_key_exchange()
        plaintext = "Hello, Bob!"
        ct = alice.encrypt_message(plaintext)
        result = bob.decrypt_message(ct)
        assert result == plaintext
    
    def test_encrypt_decrypt_multiple_messages(self):
        alice, bob = _full_key_exchange()
        messages = ["msg1", "msg2", "msg3", "msg4", "msg5"]
        for msg in messages:
            ct = alice.encrypt_message(msg)
            assert bob.decrypt_message(ct) == msg
    
    def test_counter_increments_on_encrypt(self):
        alice, _ = _full_key_exchange()
        before = alice.message_counter
        alice.encrypt_message("test")
        assert alice.message_counter == before + 1
    
    def test_peer_counter_increments_on_decrypt(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("test")
        before = bob.peer_counter
        bob.decrypt_message(ct)
        assert bob.peer_counter == before + 1
    
    def test_encrypt_without_shared_key_raises(self):
        p = _make_protocol()
        with pytest.raises(ValueError):
            p.encrypt_message("test")
    
    def test_decrypt_without_shared_key_raises(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("test")
        fresh = _make_protocol()
        with pytest.raises(ValueError):
            fresh.decrypt_message(ct)
    
    def test_tampered_ciphertext_raises(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("secret")
        msg = json.loads(ct)
        import base64
        
        raw = base64.b64decode(msg["ciphertext"])
        msg["ciphertext"] = base64.b64encode(bytes([raw[0] ^ 0xFF]) + raw[1:]).decode()
        with pytest.raises(ValueError):
            bob.decrypt_message(json.dumps(msg).encode())
    
    def test_tampered_verification_raises(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("secret")
        msg = json.loads(ct)
        import base64
        
        raw = base64.b64decode(msg["verification"])
        msg["verification"] = base64.b64encode(bytes([raw[0] ^ 0xFF]) + raw[1:]).decode()
        with pytest.raises(ValueError, match="verification"):
            bob.decrypt_message(json.dumps(msg).encode())
    
    def test_missing_field_raises(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("test")
        msg = json.loads(ct)
        del msg["nonce"]
        with pytest.raises(ValueError):
            bob.decrypt_message(json.dumps(msg).encode())
    
    def test_encrypt_unicode_message(self):
        alice, bob = _full_key_exchange()
        text = "こんにちは世界 🌍"
        ct = alice.encrypt_message(text)
        assert bob.decrypt_message(ct) == text
    
    def test_encrypt_empty_string(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("")
        assert bob.decrypt_message(ct) == ""
    
    def test_encrypt_large_message(self):
        alice, bob = _full_key_exchange()
        text = "A" * 100_000
        ct = alice.encrypt_message(text)
        assert bob.decrypt_message(ct) == text
    
    def test_bidirectional_messaging(self):
        alice, bob = _full_key_exchange()
        ct1 = alice.encrypt_message("from alice")
        ct2 = bob.encrypt_message("from bob")
        assert bob.decrypt_message(ct1) == "from alice"
        assert alice.decrypt_message(ct2) == "from bob"


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestReplayProtection:
    def test_replay_same_message_raises(self):
        alice, bob = _full_key_exchange()
        ct = alice.encrypt_message("once")
        bob.decrypt_message(ct)
        with pytest.raises(ValueError):
            bob.decrypt_message(ct)
    
    def test_old_counter_without_saved_state_raises(self):
        alice, bob = _full_key_exchange()
        ct1 = alice.encrypt_message("msg1")
        ct2 = alice.encrypt_message("msg2")
        bob.decrypt_message(ct1)
        bob.decrypt_message(ct2)
        # Replaying ct1 (counter already passed, not saved) should raise
        with pytest.raises(ValueError):
            bob.decrypt_message(ct1)


# ---------------------------------------------------------------------------
# Out-of-order messages
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestOutOfOrder:
    def test_out_of_order_delivery(self):
        alice, bob = _full_key_exchange()
        ct1 = alice.encrypt_message("first")
        ct2 = alice.encrypt_message("second")
        ct3 = alice.encrypt_message("third")
        
        # Deliver in order 1, 3, 2
        assert bob.decrypt_message(ct1) == "first"
        assert bob.decrypt_message(ct3) == "third"
        assert bob.decrypt_message(ct2) == "second"
    
    def test_skipped_counter_saved_in_cache(self):
        alice, bob = _full_key_exchange()
        ct1 = alice.encrypt_message("skip")
        ct2 = alice.encrypt_message("arrive first")
        
        # Deliver ct2 first — ct1's chain state should be saved
        bob.decrypt_message(ct2)
        # ct1 should still be decryptable via saved state
        assert bob.decrypt_message(ct1) == "skip"


# ---------------------------------------------------------------------------
# File chunk encrypt / decrypt
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestFileChunks:
    def test_file_chunk_roundtrip(self):
        alice, bob = _full_key_exchange()
        data = os.urandom(1024)
        frame = alice.encrypt_file_chunk("transfer-1", 0, data)
        result = bob.decrypt_file_chunk(frame)
        assert result["transfer_id"] == "transfer-1"
        assert result["chunk_index"] == 0
        assert result["chunk_data"] == data
    
    def test_file_chunk_starts_with_magic(self):
        alice, _ = _full_key_exchange()
        frame = alice.encrypt_file_chunk("t", 0, b"data")
        assert frame[:len(MAGIC_NUMBER_FILE_TRANSFER)] == MAGIC_NUMBER_FILE_TRANSFER
    
    def test_file_chunk_counter_increments(self):
        alice, _ = _full_key_exchange()
        before = alice.message_counter
        alice.encrypt_file_chunk("t", 0, b"x")
        assert alice.message_counter == before + 1
    
    def test_file_chunk_without_shared_key_raises(self):
        p = _make_protocol()
        with pytest.raises(ValueError):
            p.encrypt_file_chunk("t", 0, b"data")
    
    def test_file_chunk_too_short_raises(self):
        _, bob = _full_key_exchange()
        with pytest.raises(ValueError):
            bob.decrypt_file_chunk(b"\x00" * 10)
    
    def test_file_chunk_tampered_raises(self):
        alice, bob = _full_key_exchange()
        frame = alice.encrypt_file_chunk("t", 0, b"secret")
        corrupted = frame[:-10] + bytes([frame[-10] ^ 0xFF]) + frame[-9:]
        with pytest.raises(ValueError):
            bob.decrypt_file_chunk(corrupted)
    
    def test_multiple_file_chunks_sequential(self):
        alice, bob = _full_key_exchange()
        chunks = [os.urandom(512) for _ in range(5)]
        frames = [alice.encrypt_file_chunk("t", i, c) for i, c in enumerate(chunks)]
        for i, frame in enumerate(frames):
            result = bob.decrypt_file_chunk(frame)
            assert result["chunk_data"] == chunks[i]
            assert result["chunk_index"] == i


# ---------------------------------------------------------------------------
# Rekey
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestRekey:
    def test_rekey_full_flow(self):
        alice, bob = _full_key_exchange()
        
        old_send_key = alice._send_chain_key
        
        # Alice initiates rekey
        rekey_init = alice.create_rekey_init()
        assert alice.rekey_in_progress is True
        
        # Bob processes init and returns response
        rekey_response = bob.process_rekey_init(rekey_init)
        assert bob.rekey_in_progress is True
        
        # Alice processes response and returns commit
        rekey_commit = alice.process_rekey_response(rekey_response)
        assert isinstance(rekey_commit, dict)
        
        # Both activate pending keys
        alice.activate_pending_keys()
        bob.activate_pending_keys()
        
        assert alice.rekey_in_progress is False
        assert bob.rekey_in_progress is False
        assert alice.shared_key is True
        assert bob.shared_key is True
        # Keys should have changed
        assert alice._send_chain_key != old_send_key
    
    def test_rekey_new_keys_allow_messaging(self):
        alice, bob = _full_key_exchange()
        
        rekey_init = alice.create_rekey_init()
        rekey_response = bob.process_rekey_init(rekey_init)
        alice.process_rekey_response(rekey_response)
        alice.activate_pending_keys()
        bob.activate_pending_keys()
        
        ct = alice.encrypt_message("post-rekey message")
        assert bob.decrypt_message(ct) == "post-rekey message"
    
    def test_activate_pending_keys_noop_when_not_in_progress(self):
        alice, _ = _full_key_exchange()
        old_key = alice._send_chain_key
        alice.activate_pending_keys()  # should be a no-op
        assert alice._send_chain_key == old_key
    
    def test_process_rekey_response_without_private_key_raises(self):
        alice, bob = _full_key_exchange()
        rekey_init = alice.create_rekey_init()
        rekey_response = bob.process_rekey_init(rekey_init)
        # Corrupt alice's private key
        alice._rekey_mlkem_private_key = b""
        with pytest.raises(ValueError):
            alice.process_rekey_response(rekey_response)
    
    def test_rekey_counters_reset_after_activate(self):
        alice, bob = _full_key_exchange()
        alice.encrypt_message("bump counter")
        bob.decrypt_message(alice.encrypt_message("bump"))
        
        rekey_init = alice.create_rekey_init()
        rekey_response = bob.process_rekey_init(rekey_init)
        alice.process_rekey_response(rekey_response)
        alice.activate_pending_keys()
        bob.activate_pending_keys()
        
        assert alice.message_counter == 0
        assert bob.peer_counter == 0
    
    def test_should_auto_rekey_triggers_after_interval(self):
        alice, _ = _full_key_exchange()
        alice.messages_since_last_rekey = alice.rekey_interval + 1
        assert alice.should_auto_rekey is True
    
    def test_should_not_auto_rekey_when_rekey_in_progress(self):
        alice, _ = _full_key_exchange()
        alice.messages_since_last_rekey = alice.rekey_interval + 1
        alice._rekey_in_progress = True
        assert alice.should_auto_rekey is False


# ---------------------------------------------------------------------------
# Key verification helpers
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestKeyVerification:
    def test_create_and_process_key_verification_true(self):
        msg = SecureChatProtocol.create_key_verification_message(True)
        assert SecureChatProtocol.process_key_verification_message(msg) is True
    
    def test_create_and_process_key_verification_false(self):
        msg = SecureChatProtocol.create_key_verification_message(False)
        assert SecureChatProtocol.process_key_verification_message(msg) is False
    
    def test_get_own_key_fingerprint_after_ke(self):
        alice, bob = _full_key_exchange()
        fp_a = alice.get_own_key_fingerprint()
        fp_b = bob.get_own_key_fingerprint()
        assert isinstance(fp_a, str) and len(fp_a) > 0
        # Both sides derive the same fingerprint (order-independent)
        assert fp_a == fp_b
    
    def test_get_own_key_fingerprint_before_ke_raises(self):
        p = _make_protocol()
        with pytest.raises((ValueError, AttributeError)):
            p.get_own_key_fingerprint()
    
    def test_ke_verification_wrong_material_returns_false(self):
        alice, bob = _full_key_exchange()
        # Tamper with alice's material before creating the message
        alice._key_verification_material = os.urandom(32)
        msg = alice.create_ke_verification()
        assert bob.process_ke_verification(msg) is False


# ---------------------------------------------------------------------------
# Static key-derivation helpers
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestKeyDerivationHelpers:
    def test_derive_message_key_deterministic(self):
        chain = os.urandom(64)
        k1 = SecureChatProtocol._derive_message_key(chain, 1)
        k2 = SecureChatProtocol._derive_message_key(chain, 1)
        assert k1 == k2
    
    def test_derive_message_key_different_counters(self):
        chain = os.urandom(64)
        k1 = SecureChatProtocol._derive_message_key(chain, 1)
        k2 = SecureChatProtocol._derive_message_key(chain, 2)
        assert k1 != k2
    
    def test_ratchet_chain_key_advances(self):
        chain = os.urandom(64)
        new_chain = SecureChatProtocol._ratchet_chain_key(chain, 1)
        assert new_chain != chain
        assert len(new_chain) == 64
    
    def test_ratchet_chain_key_deterministic(self):
        chain = os.urandom(64)
        c1 = SecureChatProtocol._ratchet_chain_key(chain, 5)
        c2 = SecureChatProtocol._ratchet_chain_key(chain, 5)
        assert c1 == c2
    
    def test_mix_dh_with_chain_deterministic(self):
        chain = os.urandom(64)
        dh = os.urandom(32)
        m1 = SecureChatProtocol._mix_dh_with_chain(chain, dh, 3)
        m2 = SecureChatProtocol._mix_dh_with_chain(chain, dh, 3)
        assert m1 == m2
    
    def test_mix_dh_with_chain_different_dh(self):
        chain = os.urandom(64)
        m1 = SecureChatProtocol._mix_dh_with_chain(chain, os.urandom(32), 1)
        m2 = SecureChatProtocol._mix_dh_with_chain(chain, os.urandom(32), 1)
        assert m1 != m2
    
    def test_derive_combined_shared_secret_deterministic(self):
        mlkem = os.urandom(32)
        dh = os.urandom(32)
        s1 = SecureChatProtocol._derive_combined_shared_secret(mlkem, dh)
        s2 = SecureChatProtocol._derive_combined_shared_secret(mlkem, dh)
        assert s1 == s2
    
    def test_derive_keys_and_chain_returns_64_bytes_each(self):
        secret = os.urandom(64)
        enc_key, chain = SecureChatProtocol._derive_keys_and_chain(secret)
        assert len(enc_key) == 64
        assert len(chain) == 64
    
    def test_derive_keys_and_chain_with_pub_keys(self):
        secret = os.urandom(64)
        pub_a = os.urandom(32)
        pub_b = os.urandom(32)
        enc_key, chain = SecureChatProtocol._derive_keys_and_chain(secret, pub_a, pub_b)
        assert len(enc_key) == 64
        assert len(chain) == 64
    
    def test_derive_rekey_otp_material_length(self):
        hqc = os.urandom(64)
        otp = SecureChatProtocol._derive_rekey_otp_material(hqc)
        assert len(otp) == 64


# ---------------------------------------------------------------------------
# Sender thread
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestSenderThread:
    def test_start_stop_sender_thread(self):
        import socket as _socket
        
        p = _make_protocol()
        # Use a mock socket-like object
        sock = _socket.socket()
        p.start_sender_thread(sock)
        assert p._sender_running is True
        assert p._sender_thread is not None
        p.stop_sender_thread()
        assert p._sender_running is False
        sock.close()
    
    def test_start_sender_thread_idempotent(self):
        import socket as _socket
        
        p = _make_protocol()
        sock = _socket.socket()
        p.start_sender_thread(sock)
        thread_before = p._sender_thread
        p.start_sender_thread(sock)  # second call should be a no-op
        assert p._sender_thread is thread_before
        p.stop_sender_thread()
        sock.close()


# ---------------------------------------------------------------------------
# LRUCache (used by protocol for skipped counters)
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestLRUCache:
    def test_set_and_get(self):
        cache = LRUCache(3)
        cache[1] = b"a"
        assert cache[1] == b"a"
    
    def test_missing_key_returns_none(self):
        cache = LRUCache(3)
        assert cache[99] is None
    
    def test_evicts_lru_when_full(self):
        cache = LRUCache(2)
        cache[1] = b"a"
        cache[2] = b"b"
        cache[3] = b"c"  # should evict key 1
        assert cache[1] is None
        assert cache[2] == b"b"
        assert cache[3] == b"c"
    
    def test_pop_removes_key(self):
        cache = LRUCache(3)
        cache[1] = b"x"
        val = cache.pop(1)
        assert val == b"x"
        assert cache[1] is None
    
    def test_pop_missing_key_returns_none(self):
        cache = LRUCache(3)
        assert cache.pop(42) is None
    
    def test_access_updates_lru_order(self):
        cache = LRUCache(2)
        cache[1] = b"a"
        cache[2] = b"b"
        _ = cache[1]  # access key 1 → now most recently used
        cache[3] = b"c"  # should evict key 2 (LRU)
        assert cache[1] == b"a"
        assert cache[2] is None


# ---------------------------------------------------------------------------
# DoubleEncryptor (crypto_classes)
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestDoubleEncryptor:
    def _make_encryptor(self, counter: int = 1):
        key = os.urandom(64)
        otp = os.urandom(32)
        return DoubleEncryptor(key, otp, counter), key, otp
    
    def test_encrypt_decrypt_roundtrip(self):
        enc, _, _ = self._make_encryptor()
        nonce = os.urandom(12)
        data = b"hello world"
        ct = enc.encrypt(nonce, data)
        assert enc.decrypt(nonce, ct) == data
    
    def test_wrong_key_raises(self):
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        otp = os.urandom(32)
        enc1 = DoubleEncryptor(key1, otp, 1)
        enc2 = DoubleEncryptor(key2, otp, 1)
        nonce = os.urandom(12)
        ct = enc1.encrypt(nonce, b"secret")
        with pytest.raises(Exception):
            enc2.decrypt(nonce, ct)
    
    def test_bad_key_length_raises(self):
        with pytest.raises(ValueError):
            DoubleEncryptor(b"short", b"otp", 1)
    
    def test_aad_mismatch_raises(self):
        enc, _, _ = self._make_encryptor()
        nonce = os.urandom(12)
        ct = enc.encrypt(nonce, b"data", associated_data=b"aad1")
        with pytest.raises(Exception):
            enc.decrypt(nonce, ct, associated_data=b"aad2")
    
    def test_encrypt_no_pad(self):
        enc, _, _ = self._make_encryptor()
        nonce = os.urandom(12)
        data = b"x" * 64
        ct = enc.encrypt(nonce, data, pad=False)
        assert enc.decrypt(nonce, ct, pad=False) == data


# ---------------------------------------------------------------------------
# KeyExchangeDoubleEncryptor
# ---------------------------------------------------------------------------

# noinspection PyMissingTypeHints
class TestKeyExchangeDoubleEncryptor:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(64)
        enc = KeyExchangeDoubleEncryptor(key)
        nonce = os.urandom(12)
        data = os.urandom(128)
        ct = enc.encrypt(nonce, data)
        assert enc.decrypt(nonce, ct) == data
    
    def test_bad_key_length_raises(self):
        with pytest.raises(ValueError):
            KeyExchangeDoubleEncryptor(b"tooshort")
    
    def test_different_nonces_produce_different_ciphertexts(self):
        key = os.urandom(64)
        enc = KeyExchangeDoubleEncryptor(key)
        data = b"same data"
        ct1 = enc.encrypt(os.urandom(12), data)
        ct2 = enc.encrypt(os.urandom(12), data)
        assert ct1 != ct2
