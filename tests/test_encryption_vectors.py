"""Known-answer tests for encryption classes against `tests/encryption_vectors.json`.

Vectors are `{"inputs": {...}, "output": ...}`. `bytes` values are base64-encoded;
`int`/`bool` values stored as-is. `associated_data` is `null` when absent.

Guards against silent regressions in AEAD layering, OTP keystream derivation,
nonce mixing, or padding for DoubleEncryptor / ChunkIndependentDoubleEncryptor /
KeyExchangeDoubleEncryptor.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from protocol.crypto_classes import (
    ChunkIndependentDoubleEncryptor,
    DoubleEncryptor,
    KeyExchangeDoubleEncryptor,
)

_VECTORS_PATH = Path(__file__).parent / "encryption_vectors.json"


def _b(s: str) -> bytes:
    return base64.b64decode(s)


def _maybe_b(s: str | None) -> bytes | None:
    return None if s is None else base64.b64decode(s)


@pytest.fixture(scope="module")
def vectors() -> dict[str, list[dict[str, Any]]]:
    with _VECTORS_PATH.open("rb") as f:
        return json.load(f)


def _run(vectors: dict, cls_name: str, fn) -> None:
    cases = vectors[cls_name]
    assert cases, f"no vectors for {cls_name}"
    for i, case in enumerate(cases):
        try:
            got = fn(case["inputs"])
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"{cls_name}[{i}] raised {type(exc).__name__}: {exc!r}")
        expected = case["output"]
        assert got == expected, f"{cls_name}[{i}] ciphertext mismatch"


# ---------------------------------------------------------------------------
# Encrypt-direction KAT: vector output must match current impl byte-for-byte.
# ---------------------------------------------------------------------------
def test_double_encryptor(vectors) -> None:
    def fn(inp: dict) -> str:
        enc = DoubleEncryptor(
            key=_b(inp["key"]),
            OTP_secret=_b(inp["OTP_secret"]),
            message_counter=inp["message_counter"],
        )
        ct = enc.encrypt(
            nonce=_b(inp["nonce"]),
            data=_b(inp["plaintext"]),
            associated_data=_maybe_b(inp["associated_data"]),
            pad=inp["pad"],
        )
        return base64.b64encode(ct).decode()
    _run(vectors, "DoubleEncryptor", fn)


def test_chunk_independent_double_encryptor(vectors) -> None:
    def fn(inp: dict) -> str:
        enc = ChunkIndependentDoubleEncryptor(key=_b(inp["key"]))
        ct = enc.encrypt(nonce=_b(inp["nonce"]), data=_b(inp["plaintext"]))
        return base64.b64encode(ct).decode()
    _run(vectors, "ChunkIndependentDoubleEncryptor", fn)


def test_key_exchange_double_encryptor(vectors) -> None:
    def fn(inp: dict) -> str:
        enc = KeyExchangeDoubleEncryptor(key=_b(inp["key"]))
        ct = enc.encrypt(nonce=_b(inp["nonce"]), data=_b(inp["plaintext"]))
        return base64.b64encode(ct).decode()
    _run(vectors, "KeyExchangeDoubleEncryptor", fn)


# ---------------------------------------------------------------------------
# Decrypt-direction: ciphertext from vectors must roundtrip back to plaintext.
# Cheap extra assurance that the recorded output is internally consistent.
# ---------------------------------------------------------------------------
def test_double_encryptor_decrypt_roundtrip(vectors) -> None:
    for i, case in enumerate(vectors["DoubleEncryptor"]):
        inp = case["inputs"]
        dec = DoubleEncryptor(
            key=_b(inp["key"]),
            OTP_secret=_b(inp["OTP_secret"]),
            message_counter=inp["message_counter"],
        )
        pt = dec.decrypt(
            nonce=_b(inp["nonce"]),
            data=_b(case["output"]),
            associated_data=_maybe_b(inp["associated_data"]),
            pad=inp["pad"],
        )
        assert pt == _b(inp["plaintext"]), f"DoubleEncryptor[{i}] decrypt mismatch"


def test_chunk_independent_decrypt_roundtrip(vectors) -> None:
    for i, case in enumerate(vectors["ChunkIndependentDoubleEncryptor"]):
        inp = case["inputs"]
        dec = ChunkIndependentDoubleEncryptor(key=_b(inp["key"]))
        pt = dec.decrypt(nonce=_b(inp["nonce"]), data=_b(case["output"]))
        assert pt == _b(inp["plaintext"]), f"ChunkIndependentDoubleEncryptor[{i}] decrypt mismatch"


def test_key_exchange_decrypt_roundtrip(vectors) -> None:
    for i, case in enumerate(vectors["KeyExchangeDoubleEncryptor"]):
        inp = case["inputs"]
        dec = KeyExchangeDoubleEncryptor(key=_b(inp["key"]))
        pt = dec.decrypt(nonce=_b(inp["nonce"]), data=_b(case["output"]))
        assert pt == _b(inp["plaintext"]), f"KeyExchangeDoubleEncryptor[{i}] decrypt mismatch"


# ---------------------------------------------------------------------------
# Meta: vector file shape.
# ---------------------------------------------------------------------------
def test_vector_file_has_all_classes(vectors) -> None:
    assert set(vectors) == {
        "DoubleEncryptor",
        "ChunkIndependentDoubleEncryptor",
        "KeyExchangeDoubleEncryptor",
    }