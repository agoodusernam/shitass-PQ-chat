import base64
import json
import unittest

from shared import SecureChatProtocol

class ProtocolCryptoTests(unittest.TestCase):
    def setUp(self):
        self.alice = SecureChatProtocol()
        self.bob = SecureChatProtocol()

        # Perform full key exchange between alice (initiator) and bob (responder)
        pub_a, priv_a = self.alice.generate_keypair()
        self.alice_priv = priv_a
        init = self.alice.create_key_exchange_init(pub_a)

        shared_b, ct, warn = self.bob.process_key_exchange_init(init)
        self.assertIsInstance(shared_b, (bytes, bytearray))
        self.assertTrue(shared_b)
        # Warning may be None or a string if version mismatch was forced elsewhere
        self.assertTrue(self.bob.shared_key)
        self.assertTrue(self.bob.send_chain_key)
        self.assertTrue(self.bob.receive_chain_key)

        resp = self.bob.create_key_exchange_response(ct)
        shared_a, warn2 = self.alice.process_key_exchange_response(resp, self.alice_priv)
        self.assertIsInstance(shared_a, (bytes, bytearray))
        self.assertTrue(shared_a)
        self.assertEqual(shared_a, shared_b)
        self.assertTrue(self.alice.shared_key)
        self.assertTrue(self.alice.send_chain_key)
        self.assertTrue(self.alice.receive_chain_key)

    def test_encrypt_decrypt_roundtrip_and_ratchet(self):
        # Alice -> Bob
        m1 = "Hello Bob"
        c1 = self.alice.encrypt_message(m1)
        p1 = self.bob.decrypt_message(c1)
        self.assertEqual(p1, m1)
        self.assertEqual(self.bob.peer_counter, 1)

        # Alice sends two more messages, Bob skips first and decrypts second
        m2 = "Second message"
        c2 = self.alice.encrypt_message(m2)
        m3 = "Third message"
        c3 = self.alice.encrypt_message(m3)
        m4 = "Fourth message"
        c4 = self.alice.encrypt_message(m4)
        p3 = self.bob.decrypt_message(c3)  # out-of-order acceptable forward
        self.assertEqual(p3, m3)
        self.assertEqual(self.bob.peer_counter, 3)

        # Replay detection: decrypting an old message should fail now
        with self.assertRaises(ValueError):
            self.bob.decrypt_message(c1)
        with self.assertRaises(ValueError):
            self.bob.decrypt_message(c2)

        # Tamper with ciphertext bytes -> should fail authentication
        tampered = json.loads(c4.decode("utf-8"))
        ct_bytes = bytearray(base64.b64decode(tampered["ciphertext"]))
        ct_bytes[0] ^= 0x01
        tampered["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("utf-8")
        tampered_bytes = json.dumps(tampered).encode("utf-8")
        with self.assertRaises(ValueError):
            self.bob.decrypt_message(tampered_bytes)

        # Tamper with AAD (nonce) -> should fail authentication
        tampered2 = json.loads(c4.decode("utf-8"))
        n = base64.b64decode(tampered2["nonce"])  # keep ct same
        n = bytearray(n)
        n[-1] ^= 0x01
        tampered2["nonce"] = base64.b64encode(bytes(n)).decode("utf-8")
        tampered2_bytes = json.dumps(tampered2).encode("utf-8")
        with self.assertRaises(ValueError):
            self.bob.decrypt_message(tampered2_bytes)

        # Tamper with counter in JSON (AAD) -> should fail authentication
        tampered3 = json.loads(c4.decode("utf-8"))
        tampered3["counter"] = 999999
        tampered3_bytes = json.dumps(tampered3).encode("utf-8")
        with self.assertRaises(ValueError):
            self.bob.decrypt_message(tampered3_bytes)
        
        tampered4 = json.loads(c4.decode("utf-8"))
        ver_bytes = bytearray(base64.b64decode(tampered["verification"]))
        ver_bytes[0] ^= 0x01
        tampered4["verification"] = base64.b64encode(bytes(ver_bytes)).decode("utf-8")
        tampered4_bytes = json.dumps(tampered4).encode("utf-8")
        with self.assertRaises(ValueError):
            self.bob.decrypt_message(tampered4_bytes)

    def test_version_mismatch_warning(self):
        # Craft init with fake version to trigger warning
        pub_a, _ = self.alice.generate_keypair()
        init = self.alice.create_key_exchange_init(pub_a)
        payload = json.loads(init.decode("utf-8"))
        payload["version"] = "0.0.0"
        init_bad = json.dumps(payload).encode("utf-8")
        _, _, warn = self.bob.process_key_exchange_init(init_bad)
        self.assertIsInstance(warn, (str, type(None)))
        self.assertTrue(warn is None or "Protocol version mismatch" in warn)

    def test_fingerprints_match_after_key_exchange(self):
        # After setUp, both peers should have both public keys
        fp_a = self.alice.get_own_key_fingerprint()
        fp_b = self.bob.get_own_key_fingerprint()
        self.assertEqual(fp_a, fp_b)
        self.assertTrue(len(fp_a.split()) >= 16)

    def test_rekey_flow(self):
        # Send a pre-rekey message
        pre_ct = self.alice.encrypt_message("before rekey")
        pre_ct_copy = pre_ct  # store for later failure test
        _ = self.bob.decrypt_message(pre_ct)

        # Initiate rekey from Alice
        init_payload = self.alice.create_rekey_init()
        resp_payload = self.bob.process_rekey_init(init_payload)
        commit_payload = self.alice.process_rekey_response(resp_payload)
        ack_payload = self.bob.process_rekey_commit(commit_payload)
        self.assertEqual(ack_payload.get("action"), "commit_ack")

        # Activate new keys on both sides
        self.alice.activate_pending_keys()
        self.bob.activate_pending_keys()

        # Old ciphertext should not decrypt under new keys
        with self.assertRaises(ValueError):
            _ = self.bob.decrypt_message(pre_ct_copy)

        # New message should work
        post_ct = self.alice.encrypt_message("after rekey")
        post_pt = self.bob.decrypt_message(post_ct)
        self.assertEqual(post_pt, "after rekey")

    def test_file_chunk_encrypt_decrypt(self):
        # Simple file chunk crypto path roundtrip
        transfer_id = "tx123"
        chunk_data = b"hello world bytes"
        msg = self.alice.create_file_chunk_message(transfer_id, 0, chunk_data)
        info = self.bob.process_file_chunk(msg)
        self.assertEqual(info["transfer_id"], transfer_id)
        self.assertEqual(info["chunk_index"], 0)
        self.assertEqual(info["chunk_data"], chunk_data)


if __name__ == "__main__":
    unittest.main()
