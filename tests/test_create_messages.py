"""Tests for ``protocol.create_messages``."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from protocol import create_messages
from protocol.constants import ML_DSA_CONTEXT, MessageType


class TestPlainMessages:
    def test_error_message(self) -> None:
        m = json.loads(create_messages.create_error_message("boom"))
        assert m == {"type": MessageType.ERROR, "error": "boom"}
    
    def test_reset_message(self) -> None:
        m = json.loads(create_messages.create_reset_message())
        assert m["type"] == MessageType.KEY_EXCHANGE_RESET
        assert "message" in m
    
    @pytest.mark.parametrize("verified", [True, False])
    def test_key_verification(self, verified: bool) -> None:
        m = json.loads(create_messages.create_key_verification_message(verified))
        assert m == {"type": MessageType.KEY_VERIFICATION, "verified": verified}


class TestKEMessages:
    def test_dsa_random_encodes_inputs(self) -> None:
        m = json.loads(create_messages.create_ke_dsa_random(b"\x01" * 32, b"\x02" * 32))
        assert m["type"] == MessageType.KE_DSA_RANDOM
        assert base64.b64decode(m["mldsa_public_key"]) == b"\x01" * 32
        assert base64.b64decode(m["client_random"]) == b"\x02" * 32
    
    def test_mlkem_pubkey_signature_verifies(self) -> None:
        priv = MLDSA87PrivateKey.generate()
        pubkey = b"\xaa" * 1568
        m = json.loads(create_messages.create_ke_mlkem_pubkey(pubkey, priv))
        sig = base64.b64decode(m["mldsa_signature"])
        priv.public_key().verify(sig, pubkey, context=ML_DSA_CONTEXT)
    
    def test_mlkem_ct_keys_signature_verifies(self) -> None:
        priv = MLDSA87PrivateKey.generate()
        ct, hqc, x, n1, n2 = b"a", b"b", b"c", b"\x00" * 12, b"\x01" * 12
        m = json.loads(create_messages.create_ke_mlkem_ct_keys(ct, hqc, x, n1, n2, priv))
        sig = base64.b64decode(m["mldsa_signature"])
        priv.public_key().verify(sig, ct + hqc + x + n1 + n2, context=ML_DSA_CONTEXT)
    
    def test_x25519_hqc_ct_signature_verifies(self) -> None:
        priv = MLDSA87PrivateKey.generate()
        x, hqc, n1, n2 = b"x", b"h", b"\x00" * 12, b"\x01" * 12
        m = json.loads(create_messages.create_ke_x25519_hqc_ct(x, hqc, n1, n2, priv))
        sig = base64.b64decode(m["mldsa_signature"])
        priv.public_key().verify(sig, x + hqc + n1 + n2, context=ML_DSA_CONTEXT)
    
    def test_verification_proof_is_sha3_512(self) -> None:
        m = json.loads(create_messages.create_ke_verification(b"\xab" * 32))
        assert m["type"] == MessageType.KE_VERIFICATION
        assert len(base64.b64decode(m["verification_key"])) == 64


class TestFileMessages:
    def test_file_accept(self) -> None:
        a = create_messages.create_file_accept_message("tid123")
        assert a == {"type": MessageType.FILE_ACCEPT, "transfer_id": "tid123"}
    
    def test_file_reject_custom_reason(self) -> None:
        r = create_messages.create_file_reject_message("tid", "nah")
        assert r == {"type": MessageType.FILE_REJECT, "transfer_id": "tid", "reason": "nah"}
    
    def test_file_reject_default_reason(self) -> None:
        assert create_messages.create_file_reject_message("tid")["reason"] == "User declined"


class TestFileMetadata:
    def test_uncompressed_incompressible_extension(self, tmp_path: Path) -> None:
        data = b"hello world" * 100
        p = tmp_path / "data.bin"  # .bin -> compression forced off
        p.write_bytes(data)
        meta = create_messages.create_file_metadata_message(p, compress=True, chunk_size=512)
        assert meta["filename"] == "data.bin"
        assert meta["file_size"] == len(data)
        assert meta["compressed"] is False
        assert meta["total_chunks"] >= 1
        assert len(meta["transfer_id"]) > 0
    
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            create_messages.create_file_metadata_message(tmp_path / "missing.txt")
