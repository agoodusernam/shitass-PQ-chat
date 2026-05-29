"""Tests for ``protocol.file_handler.ProtocolFileHandler``."""
from __future__ import annotations

import gzip
import hashlib
import os
from pathlib import Path

import pytest
from protocol.errors import ErrorCode, ChatError

from protocol.file_handler import ProtocolFileHandler


class TestInitialState:
    def test_empty(self) -> None:
        h = ProtocolFileHandler()
        assert not h.has_active_file_transfers
        assert h.received_chunks == {}
        assert h.open_file_handles == {}


class TestAddChunkValidation:
    def test_negative_index(self) -> None:
        h = ProtocolFileHandler()
        with pytest.raises(ChatError):
            h.add_file_chunk("abc", -1, b"x", 5)
    
    def test_index_at_total(self) -> None:
        h = ProtocolFileHandler()
        with pytest.raises(ChatError):
            h.add_file_chunk("abc", 5, b"x", 5)
    
    def test_non_alphanumeric_transfer_id(self) -> None:
        h = ProtocolFileHandler()
        with pytest.raises(ChatError):
            h.add_file_chunk("not-alnum!", 0, b"x", 1)
    
    def test_too_long_transfer_id(self) -> None:
        h = ProtocolFileHandler()
        with pytest.raises(ChatError):
            h.add_file_chunk("a" * 65, 0, b"x", 1)


class TestReassemble:
    def test_uncompressed_full_roundtrip(self, tmp_path: Path) -> None:
        h = ProtocolFileHandler()
        chunk_size = 16
        data = os.urandom(chunk_size * 4 + 5)
        total = (len(data) + chunk_size - 1) // chunk_size
        tid = "abc123"
        
        for i in range(total):
            payload = data[i * chunk_size:(i + 1) * chunk_size]
            done = h.add_file_chunk(tid, i, payload, total, chunk_size=chunk_size)
            assert done == (i == total - 1)
        
        expected = hashlib.blake2b(data, digest_size=32).hexdigest()
        out = tmp_path / "out.bin"
        assert h.reassemble_file(tid, str(out), expected, compressed=False) is True
        assert out.read_bytes() == data
        assert tid not in h.received_chunks
        assert tid not in h.temp_file_paths
    
    def test_unknown_transfer_raises(self, tmp_path: Path) -> None:
        h = ProtocolFileHandler()
        with pytest.raises(ChatError):
            h.reassemble_file("missing", str(tmp_path / "x"), "0" * 64, compressed=False)
    
    def test_hash_mismatch_raises(self, tmp_path: Path) -> None:
        h = ProtocolFileHandler()
        tid = "tid1"
        h.add_file_chunk(tid, 0, b"hello", 1, chunk_size=16)
        with pytest.raises(ChatError):
            h.reassemble_file(tid, str(tmp_path / "x"), "0" * 64, compressed=False)
    
    def test_gzip_decompression(self, tmp_path: Path) -> None:
        h = ProtocolFileHandler()
        payload = b"compressed payload" * 200
        gz = gzip.compress(payload)
        tid = "gz1"
        h.add_file_chunk(tid, 0, gz, 1, chunk_size=max(len(gz), 16))
        expected = hashlib.blake2b(payload, digest_size=32).hexdigest()
        out = tmp_path / "out.txt"
        assert h.reassemble_file(tid, str(out), expected, compressed=True)
        assert out.read_bytes() == payload


class TestStateManagement:
    def test_clear_closes_handles(self) -> None:
        h = ProtocolFileHandler()
        h.add_file_chunk("tid", 0, b"x", 2, chunk_size=16)
        assert "tid" in h.open_file_handles
        h.clear()
        assert h.open_file_handles == {}
        assert h.received_chunks == {}
        assert h.temp_file_paths == {}
    
    def test_stop_sending_transfer_idempotent(self) -> None:
        h = ProtocolFileHandler()
        h.sending_transfers["tid"] = {"transfer_id": "tid"}  # type: ignore[typeddict-item]
        h.stop_sending_transfer("tid")
        assert "tid" not in h.sending_transfers
        h.stop_sending_transfer("tid")  # no-op
    
    def test_clear_orphan_handles_keeps_active_sends(self) -> None:
        h = ProtocolFileHandler()
        h.add_file_chunk("tidA", 0, b"x", 2, chunk_size=16)
        h.add_file_chunk("tidB", 0, b"y", 2, chunk_size=16)
        h.sending_transfers["tidA"] = {"transfer_id": "tidA"}  # type: ignore[typeddict-item]
        h.clear_orphan_handles()
        assert "tidA" in h.open_file_handles
        assert "tidB" not in h.open_file_handles
        h.clear()
