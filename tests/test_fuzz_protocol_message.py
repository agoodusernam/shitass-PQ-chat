"""Property-based fuzzing for SecureChatProtocol.encrypt_message / decrypt_message.

Roundtrip:
    - arbitrary plaintext (str or bytes) → encrypt_message → decrypt_message → original.
    - out-of-order delivery across a batch of N messages.
    - replay (same frame twice) must raise.
    - bit-flip anywhere in the wire frame must raise ValueError (verification / AEAD / padding).

Robustness:
    - decrypt_message on arbitrary bytes / malformed JSON must raise only ValueError.
"""
from __future__ import annotations

import base64
import json
import random

import pytest
from hypothesis import given, strategies as st

from tests.test_protocol_shared import _full_key_exchange


@pytest.fixture(scope="module")
def pair():
    return _full_key_exchange("fuzz-server")


# ---------------------------------------------------------------------------
# Roundtrip
# ---------------------------------------------------------------------------
@given(msg=st.text(min_size=0, max_size=2048))
def test_encrypt_decrypt_roundtrip_text(pair, msg: str) -> None:
    a, b = pair
    wire = a.encrypt_message(msg)
    out = b.decrypt_message(wire)
    assert out == msg


@given(msg=st.binary(min_size=0, max_size=2048).filter(lambda b: _valid_utf8(b)))
def test_encrypt_decrypt_roundtrip_bytes(pair, msg: bytes) -> None:
    a, b = pair
    wire = a.encrypt_message(msg)
    out = b.decrypt_message(wire)
    assert out == msg.decode("utf-8")


def _valid_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# ---------------------------------------------------------------------------
# Out-of-order delivery (double ratchet skipped-key buffer)
# ---------------------------------------------------------------------------
@given(messages=st.lists(st.text(min_size=1, max_size=64), min_size=2, max_size=10),
       seed=st.integers(min_value=0, max_value=2**32 - 1))
def test_out_of_order_delivery(messages: list[str], seed: int) -> None:
    a, b = _full_key_exchange(f"ooo-{seed}")
    wires = [a.encrypt_message(m) for m in messages]
    order = list(range(len(wires)))
    random.Random(seed).shuffle(order)
    recovered = [None] * len(wires)
    for i in order:
        recovered[i] = b.decrypt_message(wires[i])
    assert recovered == messages


# ---------------------------------------------------------------------------
# Replay detection
# ---------------------------------------------------------------------------
def test_replay_same_frame_rejected() -> None:
    a, b = _full_key_exchange("replay")
    wire = a.encrypt_message("hello")
    assert b.decrypt_message(wire) == "hello"
    with pytest.raises(ValueError):
        b.decrypt_message(wire)


# ---------------------------------------------------------------------------
# Bit-flip tamper detection
# ---------------------------------------------------------------------------
@given(flip_byte_index=st.integers(min_value=0, max_value=4095),
       flip_bit=st.integers(min_value=0, max_value=7),
       msg=st.text(min_size=1, max_size=128))
def test_bitflip_detected(flip_byte_index: int, flip_bit: int, msg: str) -> None:
    a, b = _full_key_exchange(f"flip-{flip_byte_index}-{flip_bit}")
    wire = a.encrypt_message(msg)
    # Parse, mutate one base64 field, repack.
    parsed = json.loads(wire)
    field = ["ciphertext", "nonce", "dh_public_key", "verification"][flip_byte_index % 4]
    raw = bytearray(base64.b64decode(parsed[field]))
    if not raw:
        return
    idx = flip_byte_index % len(raw)
    raw[idx] ^= 1 << flip_bit
    parsed[field] = base64.b64encode(bytes(raw)).decode()
    tampered = json.dumps(parsed).encode()
    with pytest.raises(ValueError):
        b.decrypt_message(tampered)


# ---------------------------------------------------------------------------
# Robustness: garbage input must raise only ValueError.
# ---------------------------------------------------------------------------
garbage = st.one_of(
    st.binary(min_size=0, max_size=4096),
    st.text(max_size=512).map(lambda s: s.encode("utf-8", errors="replace")),
    st.dictionaries(
        st.text(max_size=16),
        st.one_of(st.text(max_size=64), st.integers(), st.booleans(), st.none()),
        max_size=10,
    ).map(lambda d: json.dumps(d).encode("utf-8")),
)


@given(data=garbage)
def test_decrypt_message_garbage_only_valueerror(data: bytes) -> None:
    a, _ = _full_key_exchange("garbage")
    try:
        a.decrypt_message(data)
    except ValueError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"decrypt_message raised unexpected {type(exc).__name__}: {exc!r}")