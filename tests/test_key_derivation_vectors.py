"""Known-answer tests for `_KeyDerivation` against `tests/key_derivation_vectors.json`.

Each method has 256 vectors (512 for rekey-aware methods: 256 each for rekey=False/True).
Vectors are `{"inputs": {...}, "output": ...}`. `bytes` values are base64-encoded;
`int`/`bool` values are stored as-is.

Guards against silent regressions in any HKDF / hash domain separator, output length,
or input-ordering logic (e.g. `derive_combined_random` sorts the pair before HKDF).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from protocol.crypto_classes import _KeyDerivation

_VECTORS_PATH = Path(__file__).parent / "key_derivation_vectors.json"


def _b(s: str) -> bytes:
    return base64.b64decode(s)


@pytest.fixture(scope="module")
def vectors() -> dict[str, list[dict[str, Any]]]:
    with _VECTORS_PATH.open("rb") as f:
        return json.load(f)


def _run(vectors: dict, method: str, fn) -> None:
    cases = vectors[method]
    assert cases, f"no vectors for {method}"
    for i, case in enumerate(cases):
        try:
            got = fn(case["inputs"])
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"{method}[{i}] raised {type(exc).__name__}: {exc!r}")
        expected = case["output"]
        assert got == expected, f"{method}[{i}] mismatch"


# ---------------------------------------------------------------------------
# Session-level derivations (rekey-aware)
# ---------------------------------------------------------------------------
def test_derive_combined_random(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.derive_combined_random(
            own_random=_b(inp["own_random"]),
            peer_random=_b(inp["peer_random"]),
            server_id=_b(inp["server_id"]),
            rekey=inp["rekey"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "derive_combined_random", fn)


def test_derive_intermediary_key_1(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.derive_intermediary_key_1(
            mlkem_secret=_b(inp["mlkem_secret"]),
            combined_random=_b(inp["combined_random"]),
            server_id=_b(inp["server_id"]),
            rekey=inp["rekey"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "derive_intermediary_key_1", fn)


def test_derive_intermediary_key_2(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.derive_intermediary_key_2(
            int_key_1=_b(inp["int_key_1"]),
            dh_secret=_b(inp["dh_secret"]),
            server_id=_b(inp["server_id"]),
            rekey=inp["rekey"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "derive_intermediary_key_2", fn)


def test_derive_otp_material(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.derive_otp_material(
            hqc_secret=_b(inp["hqc_secret"]),
            combined_random=_b(inp["combined_random"]),
            server_id=_b(inp["server_id"]),
            rekey=inp["rekey"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "derive_otp_material", fn)


def test_derive_chain_key_root(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.derive_chain_key_root(
            mlkem_secret=_b(inp["mlkem_secret"]),
            dh_secret=_b(inp["dh_secret"]),
            client_random=_b(inp["client_random"]),
            server_id=_b(inp["server_id"]),
            rekey=inp["rekey"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "derive_chain_key_root", fn)


# ---------------------------------------------------------------------------
# Verification pair — tuple output, dict in vectors.
# ---------------------------------------------------------------------------
def test_compute_verification_pair(vectors) -> None:
    def fn(inp: dict) -> dict:
        vk, kvm = _KeyDerivation.compute_verification_pair(
            otp=_b(inp["otp"]),
            own_chain_root=_b(inp["own_chain_root"]),
            peer_chain_root=_b(inp["peer_chain_root"]),
            combined_random=_b(inp["combined_random"]),
        )
        return {
            "verification_key":         base64.b64encode(vk).decode(),
            "key_verification_material": base64.b64encode(kvm).decode(),
        }
    _run(vectors, "compute_verification_pair", fn)


# ---------------------------------------------------------------------------
# Per-message derivations (counter-driven).
# ---------------------------------------------------------------------------
def test_derive_message_key(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.derive_message_key(
            chain_key=_b(inp["chain_key"]),
            counter=inp["counter"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "derive_message_key", fn)


def test_ratchet_chain_key(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.ratchet_chain_key(
            chain_key=_b(inp["chain_key"]),
            counter=inp["counter"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "ratchet_chain_key", fn)


def test_mix_dh_with_chain(vectors) -> None:
    def fn(inp: dict) -> str:
        out = _KeyDerivation.mix_dh_with_chain(
            chain_key=_b(inp["chain_key"]),
            dh_shared=_b(inp["dh_shared"]),
            counter=inp["counter"],
        )
        return base64.b64encode(out).decode()
    _run(vectors, "mix_dh_with_chain", fn)


# ---------------------------------------------------------------------------
# Meta: confirm vector file structure matches docs (9 methods, rekey=True/False
# split for rekey-aware methods).
# ---------------------------------------------------------------------------
_REKEY_AWARE = {
    "derive_combined_random",
    "derive_intermediary_key_1",
    "derive_intermediary_key_2",
    "derive_otp_material",
    "derive_chain_key_root",
}


def test_vector_file_has_all_methods(vectors) -> None:
    expected = _REKEY_AWARE | {
        "compute_verification_pair",
        "derive_message_key",
        "ratchet_chain_key",
        "mix_dh_with_chain",
    }
    assert set(vectors) == expected


def test_rekey_aware_methods_have_both_flag_values(vectors) -> None:
    for method in _REKEY_AWARE:
        flags = {case["inputs"]["rekey"] for case in vectors[method]}
        assert flags == {False, True}, f"{method} missing rekey=True or False"