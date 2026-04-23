"""Property-based fuzzing tests for protocol/parse_messages.py.

Two kinds of properties:
    1. Roundtrip: create_*(inputs) -> parse_*(...) returns inputs.
    2. Robustness: parse_*(arbitrary bytes) raises only declared exceptions
       (DecodeError for parse_ke_*, KeyError for process_file_metadata).
"""
from __future__ import annotations

import base64
import json
import os

import pytest
from hypothesis import given, strategies as st
from pqcrypto.sign import ml_dsa_87  # type: ignore[import-untyped]

from protocol import create_messages as cm
from protocol import parse_messages as pm
from protocol.constants import PROTOCOL_VERSION
from protocol.types import DecodeError


# ---------------------------------------------------------------------------
# Shared fixtures — expensive crypto material generated once per session.
# ---------------------------------------------------------------------------
_MLDSA_PUB, _MLDSA_PRIV = ml_dsa_87.generate_keypair()


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
blob = st.binary(min_size=0, max_size=2048)
small_blob = st.binary(min_size=0, max_size=256)
nonce12 = st.binary(min_size=12, max_size=12)
client_random = st.binary(min_size=32, max_size=32)

# JSON-ish garbage: bytes that may or may not parse as JSON.
garbage_bytes = st.one_of(
    st.binary(min_size=0, max_size=4096),
    st.text(max_size=512).map(lambda s: s.encode("utf-8", errors="replace")),
    st.dictionaries(st.text(max_size=16), st.text(max_size=64), max_size=8)
        .map(lambda d: json.dumps(d).encode("utf-8")),
)

# Dicts that decode as JSON but have the wrong shape for the target parser.
malformed_json_dicts = st.dictionaries(
    st.text(min_size=0, max_size=20),
    st.one_of(
        st.text(max_size=64),
        st.integers(),
        st.booleans(),
        st.none(),
        st.binary(max_size=64).map(lambda b: base64.b64encode(b).decode()),
    ),
    max_size=10,
).map(lambda d: json.dumps(d).encode("utf-8"))


# ---------------------------------------------------------------------------
# Roundtrip tests
# ---------------------------------------------------------------------------
@given(mldsa_pub=small_blob, cr=client_random)
def test_roundtrip_ke_dsa_random(mldsa_pub: bytes, cr: bytes) -> None:
    wire = cm.create_ke_dsa_random(mldsa_pub, cr)
    out = pm.parse_ke_dsa_random(wire)
    assert out["mldsa_public_key"] == mldsa_pub
    assert out["client_random"] == cr
    # Current version encoded → no warning.
    assert out["version_warning"] == ""


@given(pub=small_blob)
def test_roundtrip_ke_mlkem_pubkey(pub: bytes) -> None:
    wire = cm.create_ke_mlkem_pubkey(pub, _MLDSA_PRIV)
    out = pm.parse_ke_mlkem_pubkey(wire)
    assert out["mlkem_public_key"] == pub
    # Signature must verify against the signed payload.
    assert ml_dsa_87.verify(_MLDSA_PUB, pub, out["mldsa_signature"])


@given(ct=small_blob, hqc=small_blob, x=small_blob, n1=nonce12, n2=nonce12)
def test_roundtrip_ke_mlkem_ct_keys(ct: bytes, hqc: bytes, x: bytes, n1: bytes, n2: bytes) -> None:
    wire = cm.create_ke_mlkem_ct_keys(ct, hqc, x, n1, n2, _MLDSA_PRIV)
    out = pm.parse_ke_mlkem_ct_keys(wire)
    assert out["mlkem_ciphertext"] == ct
    assert out["encrypted_hqc_pubkey"] == hqc
    assert out["encrypted_x25519_pubkey"] == x
    assert out["nonce1"] == n1
    assert out["nonce2"] == n2
    assert out["signed_payload"] == ct + hqc + x + n1 + n2
    assert ml_dsa_87.verify(_MLDSA_PUB, out["signed_payload"], out["mldsa_signature"])


@given(x=small_blob, hqc_ct=small_blob, n1=nonce12, n2=nonce12)
def test_roundtrip_ke_x25519_hqc_ct(x: bytes, hqc_ct: bytes, n1: bytes, n2: bytes) -> None:
    wire = cm.create_ke_x25519_hqc_ct(x, hqc_ct, n1, n2, _MLDSA_PRIV)
    out = pm.parse_ke_x25519_hqc_ct(wire)
    assert out["encrypted_x25519_pubkey"] == x
    assert out["encrypted_hqc_ciphertext"] == hqc_ct
    assert out["nonce1"] == n1
    assert out["nonce2"] == n2
    assert out["signed_payload"] == x + hqc_ct + n1 + n2
    assert ml_dsa_87.verify(_MLDSA_PUB, out["signed_payload"], out["mldsa_signature"])


@given(verification_key=st.binary(min_size=16, max_size=128))
def test_roundtrip_ke_verification_match(verification_key: bytes) -> None:
    """Peer sends HMAC(key, label); parse with same key returns non-empty expected proof."""
    wire = cm.create_ke_verification(verification_key)
    out = pm.parse_ke_verification(wire, local_verification_key=verification_key)
    assert out["verification_key"] != b""
    # Without a local key, parse returns the raw peer proof.
    out_raw = pm.parse_ke_verification(wire, local_verification_key=None)
    assert len(out_raw["verification_key"]) == 64  # SHA3-512 output


@given(key_a=st.binary(min_size=16, max_size=64), key_b=st.binary(min_size=16, max_size=64))
def test_roundtrip_ke_verification_mismatch(key_a: bytes, key_b: bytes) -> None:
    """Different keys → parse returns empty bytes (constant-time mismatch signal)."""
    if key_a == key_b:
        return
    wire = cm.create_ke_verification(key_a)
    out = pm.parse_ke_verification(wire, local_verification_key=key_b)
    assert out["verification_key"] == b""


@given(verified=st.booleans())
def test_roundtrip_key_verification_message(verified: bool) -> None:
    wire = cm.create_key_verification_message(verified)
    assert pm.process_key_verification_message(wire) is verified


@given(
    transfer_id=st.text(min_size=1, max_size=32),
    filename=st.text(min_size=1, max_size=64).filter(lambda s: "\x00" not in s and "/" not in s and s not in (".", "..")),
    file_size=st.integers(min_value=0, max_value=2**40),
    file_hash=st.text(alphabet="0123456789abcdef", min_size=1, max_size=128),
    total_chunks=st.integers(min_value=0, max_value=2**32),
    compressed=st.booleans(),
    compressed_size=st.integers(min_value=0, max_value=2**40),
)
def test_roundtrip_file_metadata(
    transfer_id: str,
    filename: str,
    file_size: int,
    file_hash: str,
    total_chunks: int,
    compressed: bool,
    compressed_size: int,
) -> None:
    msg = {
        "transfer_id": transfer_id,
        "filename": filename,
        "file_size": file_size,
        "file_hash": file_hash,
        "total_chunks": total_chunks,
        "compressed": compressed,
        "compressed_size": compressed_size,
    }
    out = pm.process_file_metadata(msg)
    # filename is sanitised to a basename — compare against basename.
    assert out["filename"] == os.path.basename(filename) or out["filename"] == filename
    assert out["transfer_id"] == transfer_id
    assert out["file_size"] == file_size
    assert out["file_hash"] == file_hash
    assert out["total_chunks"] == total_chunks
    assert out["compressed"] == compressed
    assert out["compressed_size"] == compressed_size


def test_file_metadata_compressed_size_defaults_to_file_size() -> None:
    msg = {
        "transfer_id": "abc",
        "filename": "x.bin",
        "file_size": 123,
        "file_hash": "deadbeef",
        "total_chunks": 1,
    }
    out = pm.process_file_metadata(msg)
    assert out["compressed"] is False
    assert out["compressed_size"] == 123


# ---------------------------------------------------------------------------
# Version warning behaviour
# ---------------------------------------------------------------------------
@given(peer_version=st.text(min_size=1, max_size=16).filter(lambda s: s != PROTOCOL_VERSION))
def test_ke_dsa_random_emits_version_warning(peer_version: str) -> None:
    payload = {
        "type": 1,
        "version": peer_version,
        "mldsa_public_key": base64.b64encode(b"x").decode(),
        "client_random": base64.b64encode(b"y").decode(),
    }
    out = pm.parse_ke_dsa_random(json.dumps(payload).encode("utf-8"))
    assert "WARNING" in out["version_warning"]
    assert peer_version in out["version_warning"]


# ---------------------------------------------------------------------------
# Robustness / fuzz: parse_* must raise only DecodeError on garbage.
# ---------------------------------------------------------------------------
PARSE_BYTES_FUNCS = [
    pm.parse_ke_dsa_random,
    pm.parse_ke_mlkem_pubkey,
    pm.parse_ke_mlkem_ct_keys,
    pm.parse_ke_x25519_hqc_ct,
    lambda data: pm.parse_ke_verification(data, local_verification_key=None),
    lambda data: pm.parse_ke_verification(data, local_verification_key=b"\x00" * 32),
]


@pytest.mark.parametrize("parser", PARSE_BYTES_FUNCS)
@given(data=garbage_bytes)
def test_parse_ke_raises_only_decode_error(parser, data: bytes) -> None:
    try:
        parser(data)
    except DecodeError:
        pass  # expected
    except Exception as exc:  # noqa: BLE001 — we are asserting the *type*
        pytest.fail(f"{parser} raised unexpected {type(exc).__name__}: {exc!r} on {data!r}")


@pytest.mark.parametrize("parser", PARSE_BYTES_FUNCS)
@given(data=malformed_json_dicts)
def test_parse_ke_malformed_json_raises_decode_error(parser, data: bytes) -> None:
    """Valid JSON object with wrong/missing fields must still only raise DecodeError."""
    try:
        parser(data)
    except DecodeError:
        pass
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{parser} raised unexpected {type(exc).__name__}: {exc!r} on {data!r}")


@given(data=garbage_bytes)
def test_process_key_verification_robustness(data: bytes) -> None:
    """Must either return a bool or raise DecodeError — nothing else."""
    try:
        result = pm.process_key_verification_message(data)
    except DecodeError:
        return
    assert isinstance(result, bool)


@given(
    msg=st.dictionaries(
        st.text(max_size=16),
        st.one_of(st.text(max_size=32), st.integers(), st.booleans(), st.none()),
        max_size=10,
    )
)
def test_process_file_metadata_missing_fields_raise_keyerror(msg: dict) -> None:
    required = {"transfer_id", "filename", "file_size", "file_hash", "total_chunks"}
    if required.issubset(msg.keys()):
        # All required present: should not raise KeyError.
        pm.process_file_metadata(msg)
        return
    with pytest.raises(KeyError):
        pm.process_file_metadata(msg)


# ---------------------------------------------------------------------------
# Extra: base64 field mutation — parse must reject non-base64 blobs cleanly.
# ---------------------------------------------------------------------------
@given(
    bad=st.text(
        alphabet=st.characters(blacklist_categories=["Cs"]),
        min_size=1,
        max_size=64,
    ).filter(lambda s: not all(c.isalnum() or c in "+/=" for c in s)),
)
def test_ke_dsa_random_rejects_non_base64(bad: str) -> None:
    payload = {
        "type": 1,
        "mldsa_public_key": bad,
        "client_random": base64.b64encode(b"y" * 32).decode(),
    }
    with pytest.raises(DecodeError):
        pm.parse_ke_dsa_random(json.dumps(payload).encode("utf-8"))
