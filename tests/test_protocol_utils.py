"""Tests for ``protocol.utils``."""
from __future__ import annotations

import gzip
import os
from pathlib import Path

import pytest

from protocol.constants import FINGERPRINT_WORD_COUNT, MAX_SANITIZED_STR_LENGTH
from protocol.utils import (
    LRUCache,
    StreamingGzipCompressor,
    bytes_to_human_readable,
    chunk_file,
    decide_compression,
    generate_key_fingerprint,
    hash_to_words,
    load_wordlist,
    sanitize_str,
    xor_bytes,
)


class TestLRUCache:
    def test_eviction_order(self) -> None:
        c = LRUCache(2)
        c[1] = b"a";
        c[2] = b"b"
        assert c[1] == b"a"  # touch
        c[3] = b"c"  # evicts 2
        assert c[2] is None
        assert c[3] == b"c"
    
    def test_pop_present_and_missing(self) -> None:
        c = LRUCache(4)
        c[5] = b"v"
        assert c.pop(5) == b"v"
        assert c.pop(5) is None
    
    def test_missing_key_returns_none(self) -> None:
        assert LRUCache(2)[999] is None


class TestStreamingGzip:
    def test_compress_roundtrip(self) -> None:
        comp = StreamingGzipCompressor()
        data = b"data" * 4096
        out = comp.compress_chunk(data) + comp.finalise()
        assert gzip.decompress(out) == data
    
    def test_finalize_is_alias_of_finalise(self) -> None:
        comp = StreamingGzipCompressor()
        comp.compress_chunk(b"x")
        assert comp.finalize.__func__ is comp.finalise.__func__


class TestDecideCompression:
    def test_user_pref_off(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt";
        f.touch()
        assert decide_compression(f, user_pref=False) is False
    
    def test_incompressible_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "a.zip";
        f.touch()
        assert decide_compression(f, user_pref=True) is False
    
    def test_text_compresses(self, tmp_path: Path) -> None:
        f = tmp_path / "a.txt";
        f.touch()
        assert decide_compression(f, user_pref=True) is True


class TestBytesHumanReadable:
    @pytest.mark.parametrize("size,expected", [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1024 * 1024, "1.0 MiB"),
        (1024 ** 3, "1.00 GiB"),
        (5 * 1024 ** 3, "5.00 GiB"),
    ])
    def test_format(self, size: int, expected: str) -> None:
        assert bytes_to_human_readable(size) == expected


class TestXorBytes:
    @pytest.mark.parametrize("a,b", [
        (b"\x00\xff", b"\xff\x00"),
        (b"abc", b"abc"),
        (os.urandom(64), os.urandom(64)),
        (os.urandom(1024), os.urandom(1024)),  # numpy path
    ])
    def test_self_inverse(self, a: bytes, b: bytes) -> None:
        assert xor_bytes(xor_bytes(a, b), b) == a
    
    def test_unequal_lengths_numpy_path(self) -> None:
        a = b"\xff" * 800
        b = b"\x0f" * 700
        out = xor_bytes(a, b)
        assert len(out) == 800
    
    def test_unequal_lengths_int_path(self) -> None:
        a, b = b"\xff", b"\x0f\x00"
        expected = bytes(x ^ y for x, y in zip(b"\xff\x00", b"\x0f\x00"))
        assert xor_bytes(a, b) == expected


class TestSanitizeStr:
    def test_strips_non_ascii_and_truncates(self) -> None:
        s = "a" * (MAX_SANITIZED_STR_LENGTH + 50) + "🦀non-ascii"
        out = sanitize_str(s)
        assert out == "a" * MAX_SANITIZED_STR_LENGTH
    
    def test_empty_fallback(self) -> None:
        assert sanitize_str("🦀🦀🦀") == "?"


class TestWordlist:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_wordlist(tmp_path / "nope.txt")
    
    def test_strips_blank_lines(self, tmp_path: Path) -> None:
        p = tmp_path / "w.txt"
        p.write_text("alpha\n\n  beta  \n\ngamma\n", encoding="utf-8")
        assert load_wordlist(p) == ["alpha", "beta", "gamma"]
    
    def test_hash_to_words_deterministic(self) -> None:
        wl = [f"w{i}" for i in range(64)]
        h = b"\x01" * 16
        a = hash_to_words(h, wl, num_words=4)
        assert a == hash_to_words(h, wl, num_words=4)
        assert len(a) == 4
        assert all(w in wl for w in a)
    
    def test_generate_fingerprint_word_count(self) -> None:
        wl_path = Path("resources/wordlist.txt")
        if not wl_path.exists():
            pytest.skip("wordlist missing")
        fp = generate_key_fingerprint(b"\x00" * 32, wl_path)
        assert len(fp.split(" ")) == FINGERPRINT_WORD_COUNT


class TestChunkFile:
    def test_uncompressed_concatenates_to_source(self, tmp_path: Path) -> None:
        data = os.urandom(4096 * 3 + 17)
        p = tmp_path / "f.bin"
        p.write_bytes(data)
        chunks = list(chunk_file(p, compress=False, chunk_size=4096))
        assert b"".join(chunks) == data
        assert all(len(c) <= 4096 for c in chunks)
    
    def test_compressed_chunks_decompress_to_source(self, tmp_path: Path) -> None:
        data = b"abcdefg" * 1000
        p = tmp_path / "f.txt"
        p.write_bytes(data)
        chunks = list(chunk_file(p, compress=True, chunk_size=1024))
        assert gzip.decompress(b"".join(chunks)) == data
    
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises((OSError, IOError)):
            list(chunk_file(tmp_path / "missing.bin", compress=False))
