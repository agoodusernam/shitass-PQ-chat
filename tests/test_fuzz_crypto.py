"""Property-based fuzzing for protocol/crypto_classes.py.

Covers:
    - ISO/IEC 7816-4 pad/unpad invariants and malformed-padding rejection.
    - DoubleEncryptor roundtrip + AEAD tamper detection.
    - ChunkIndependentDoubleEncryptor roundtrip.
    - KeyExchangeDoubleEncryptor roundtrip + AEAD tamper detection.
"""
from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given, strategies as st

from protocol.constants import DOUBLE_KEY_SIZE, NONCE_SIZE, PAD_SIZE, CTR_NONCE_SIZE
from protocol.crypto_classes import (
    ChunkIndependentDoubleEncryptor,
    DoubleEncryptor,
    KeyExchangeDoubleEncryptor,
    _iso7816_pad,
    _iso7816_unpad,
)


key64 = st.binary(min_size=DOUBLE_KEY_SIZE, max_size=DOUBLE_KEY_SIZE)
nonce_aead = st.binary(min_size=NONCE_SIZE, max_size=NONCE_SIZE)
nonce_ctr = st.binary(min_size=CTR_NONCE_SIZE, max_size=CTR_NONCE_SIZE)
otp = st.binary(min_size=32, max_size=128)
plaintext = st.binary(min_size=32, max_size=4096)
aad = st.one_of(st.none(), st.binary(min_size=0, max_size=256))
counter = st.integers(min_value=0, max_value=2**63 - 1)


# ---------------------------------------------------------------------------
# ISO 7816-4 padding
# ---------------------------------------------------------------------------
@given(data=st.binary(max_size=8192), block_size=st.sampled_from([16, 64, 256, 512, 1024]))
def test_iso7816_roundtrip(data: bytes, block_size: int) -> None:
    padded = _iso7816_pad(data, block_size)
    assert len(padded) % block_size == 0
    assert len(padded) > len(data)  # always adds at least one byte
    assert _iso7816_unpad(padded) == data


@given(data=st.binary(max_size=2048))
def test_iso7816_pad_always_appends_0x80(data: bytes) -> None:
    padded = _iso7816_pad(data, PAD_SIZE)
    # The 0x80 marker sits right after the original data.
    assert padded[len(data)] == 0x80
    assert padded[len(data) + 1:] == b"\x00" * (len(padded) - len(data) - 1)


@given(data=st.binary(min_size=0, max_size=2048))
def test_iso7816_unpad_rejects_no_marker(data: bytes) -> None:
    # All-zero input has no 0x80 → invalid.
    with pytest.raises(ValueError):
        _iso7816_unpad(b"\x00" * max(1, len(data)))


@given(data=st.binary(min_size=1, max_size=2048).filter(lambda b: b[-1] != 0x00 and b[-1] != 0x80))
def test_iso7816_unpad_rejects_trailing_non_padding(data: bytes) -> None:
    with pytest.raises(ValueError):
        _iso7816_unpad(data)


# ---------------------------------------------------------------------------
# DoubleEncryptor
# ---------------------------------------------------------------------------
@given(key=key64, nonce=nonce_aead, data=plaintext, otp_secret=otp,
       ctr=counter, ad=aad, pad=st.booleans())
def test_double_encryptor_roundtrip(key, nonce, data, otp_secret, ctr, ad, pad) -> None:
    enc = DoubleEncryptor(key, otp_secret, ctr)
    ct = enc.encrypt(nonce, data, ad, pad=pad)
    dec = DoubleEncryptor(key, otp_secret, ctr)
    assert dec.decrypt(nonce, ct, ad, pad=pad) == data


@given(key=key64, nonce=nonce_aead, data=st.binary(min_size=1, max_size=512),
       otp_secret=otp, ctr=counter,
       flip_index=st.integers(min_value=0, max_value=2047))
def test_double_encryptor_rejects_tampered(key, nonce, data, otp_secret, ctr, flip_index) -> None:
    enc = DoubleEncryptor(key, otp_secret, ctr)
    ct = enc.encrypt(nonce, data, None)
    idx = flip_index % len(ct)
    tampered = ct[:idx] + bytes([ct[idx] ^ 0x01]) + ct[idx + 1:]
    dec = DoubleEncryptor(key, otp_secret, ctr)
    with pytest.raises(InvalidTag):
        dec.decrypt(nonce, tampered, None)


@given(key=key64, nonce=nonce_aead, data=plaintext, otp_secret=otp, ctr=counter,
       ad_a=st.binary(min_size=0, max_size=64),
       ad_b=st.binary(min_size=0, max_size=64))
def test_double_encryptor_aad_binding(key, nonce, data, otp_secret, ctr, ad_a, ad_b) -> None:
    if ad_a == ad_b:
        return
    enc = DoubleEncryptor(key, otp_secret, ctr)
    ct = enc.encrypt(nonce, data, ad_a)
    dec = DoubleEncryptor(key, otp_secret, ctr)
    with pytest.raises(InvalidTag):
        dec.decrypt(nonce, ct, ad_b)


@given(key=key64, nonce=nonce_aead, data=plaintext, otp_secret=otp,
       ctr_enc=counter, ctr_dec=counter, ad=aad)
def test_double_encryptor_counter_mismatch_corrupts(key, nonce, data, otp_secret,
                                                    ctr_enc, ctr_dec, ad) -> None:
    """Counter is mixed into OTP keystream only, not AEAD AAD. Wrong counter = wrong OTP mask.
    AEAD still verifies (inner ciphertext unchanged), but decrypted plaintext is scrambled
    and, if padded, the padding check fails."""
    if ctr_enc == ctr_dec:
        return
    enc = DoubleEncryptor(key, otp_secret, ctr_enc)
    ct = enc.encrypt(nonce, data, ad, pad=True)
    dec = DoubleEncryptor(key, otp_secret, ctr_dec)
    try:
        recovered = dec.decrypt(nonce, ct, ad, pad=True)
    except ValueError:
        return  # Padding check caught it — good.
    # On the rare occasion padding happens to be valid, plaintext must not equal original.
    assert recovered != data or data == b""


def test_double_encryptor_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError):
        DoubleEncryptor(b"\x00" * (DOUBLE_KEY_SIZE - 1), b"otp", 0)


# ---------------------------------------------------------------------------
# ChunkIndependentDoubleEncryptor
# ---------------------------------------------------------------------------
@given(key=key64, nonce=nonce_ctr, data=plaintext)
def test_chunk_independent_roundtrip(key, nonce, data) -> None:
    enc = ChunkIndependentDoubleEncryptor(key)
    ct = enc.encrypt(nonce, data)
    assert len(ct) == len(data)  # stream cipher: no length expansion
    assert enc.decrypt(nonce, ct) == data


@given(key=key64,
       nonce_a=nonce_ctr, nonce_b=nonce_ctr,
       data=st.binary(min_size=16, max_size=512))
def test_chunk_independent_different_nonces_diverge(key, nonce_a, nonce_b, data) -> None:
    if nonce_a == nonce_b:
        return
    enc = ChunkIndependentDoubleEncryptor(key)
    ct_a = enc.encrypt(nonce_a, data)
    ct_b = enc.encrypt(nonce_b, data)
    assert ct_a != ct_b


def test_chunk_independent_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError):
        ChunkIndependentDoubleEncryptor(b"\x00" * (DOUBLE_KEY_SIZE + 1))


# ---------------------------------------------------------------------------
# KeyExchangeDoubleEncryptor
# ---------------------------------------------------------------------------
@given(key=key64, nonce=nonce_aead, data=plaintext)
def test_ke_double_encryptor_roundtrip(key, nonce, data) -> None:
    enc = KeyExchangeDoubleEncryptor(key)
    ct = enc.encrypt(nonce, data)
    assert enc.decrypt(nonce, ct) == data


@given(key=key64, nonce=nonce_aead, data=st.binary(min_size=1, max_size=512),
       flip_index=st.integers(min_value=0, max_value=2047))
def test_ke_double_encryptor_rejects_tampered(key, nonce, data, flip_index) -> None:
    enc = KeyExchangeDoubleEncryptor(key)
    ct = enc.encrypt(nonce, data)
    idx = flip_index % len(ct)
    tampered = ct[:idx] + bytes([ct[idx] ^ 0x80]) + ct[idx + 1:]
    with pytest.raises(InvalidTag):
        enc.decrypt(nonce, tampered)