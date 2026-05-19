"""Tests for ``utils.file_utils``."""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

from utils.file_utils import (
    cleanup_paths,
    decompress_gzip_file,
    hash_file_hexdigest,
    safe_remove,
)


class TestSafeRemove:
    def test_removes_existing_file(self, tmp_path: Path) -> None:
        p = tmp_path / "x"
        p.write_bytes(b"hello")
        assert safe_remove(p) is True
        assert not p.exists()
    
    def test_missing_returns_true(self, tmp_path: Path) -> None:
        assert safe_remove(tmp_path / "nope") is True


class TestCleanupPaths:
    def test_counts_all_removed(self, tmp_path: Path) -> None:
        a = tmp_path / "a";
        a.write_bytes(b"1")
        b = tmp_path / "b";
        b.write_bytes(b"2")
        missing = tmp_path / "c"
        assert cleanup_paths([a, b, missing]) == 3
        assert not a.exists() and not b.exists()


class TestHashFile:
    def test_matches_hashlib(self, tmp_path: Path) -> None:
        data = b"the quick brown fox" * 1024
        p = tmp_path / "f.bin"
        p.write_bytes(data)
        expected = hashlib.blake2b(data, digest_size=32).hexdigest()
        assert hash_file_hexdigest(p) == expected


class TestDecompressGzip:
    def test_roundtrip(self, tmp_path: Path) -> None:
        payload = b"compress me" * 5000
        src = tmp_path / "src.gz"
        with gzip.open(src, "wb") as f:
            f.write(payload)
        out = decompress_gzip_file(src)
        assert out.read_bytes() == payload
        out.unlink()
