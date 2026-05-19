"""Tests for ``client.file_transfer_manager.FileTransferManager``."""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from new_client import SecureChatClient
from protocol.constants import MessageType


def _make_ui(prompt_result: bool | None = True) -> MagicMock:
    ui = MagicMock()
    ui.has_capability = MagicMock(return_value=False)
    ui.prompt_file_transfer = MagicMock(return_value=prompt_result)
    return ui


def _make_client(prompt_result: bool | None = True) -> SecureChatClient:
    c = SecureChatClient(_make_ui(prompt_result))
    c._protocol = MagicMock()
    c._protocol.send_dummy_messages = True
    return c


class TestActiveAndClear:
    def test_initially_inactive(self) -> None:
        c = _make_client()
        assert c._file_transfer.active is False
    
    def test_clear_resets_state(self) -> None:
        c = _make_client()
        c._file_transfer.pending_file_transfers["tid"] = {"metadata": {"filename": "x"}}  # type: ignore[typeddict-item]
        c._file_transfer.active_file_metadata["tid2"] = {"filename": "y"}  # type: ignore[typeddict-item]
        c._file_transfer._last_progress_shown["tid"] = 50
        assert c._file_transfer.active
        c._file_transfer.clear()
        assert not c._file_transfer.active
        assert c._file_transfer._last_progress_shown == {}


class TestSend:
    def test_blocks_without_verification(self) -> None:
        c = _make_client()
        c._verification_complete = False
        c._file_transfer.send("/no/such/file")
        c.ui.display_error_message.assert_called_once()
        c._protocol.queue_json.assert_not_called()
    
    def test_missing_file_reports_error(self, tmp_path: Path) -> None:
        c = _make_client()
        c._verification_complete = True
        c._peer_key_verified = True
        c._file_transfer.send(tmp_path / "missing.txt")
        c.ui.display_error_message.assert_called_once()
    
    def test_happy_path_queues_metadata_and_tracks(self, tmp_path: Path) -> None:
        c = _make_client()
        c._verification_complete = True
        c._peer_key_verified = True
        p = tmp_path / "data.bin"
        p.write_bytes(b"x" * 4096)
        c._file_transfer.send(p)
        # metadata frame queued
        c._protocol.queue_json.assert_called_once()
        msg = c._protocol.queue_json.call_args.args[0]
        assert msg["type"] == MessageType.FILE_METADATA
        tid = msg["transfer_id"]
        assert tid in c._file_transfer.pending_file_transfers


class TestReject:
    def test_queues_reject_and_drops_metadata(self) -> None:
        c = _make_client()
        c._file_transfer.active_file_metadata["tid"] = {"filename": "x"}  # type: ignore[typeddict-item]
        c._file_transfer.reject("tid")
        msg = c._protocol.queue_json.call_args.args[0]
        assert msg["type"] == MessageType.FILE_REJECT
        assert msg["transfer_id"] == "tid"
        assert "tid" not in c._file_transfer.active_file_metadata


def _good_metadata(file_size: int = 100, total_chunks: int = 1) -> dict:
    return {
        "type":            MessageType.FILE_METADATA,
        "transfer_id":     "tid",
        "filename":        "out.bin",
        "file_size":       file_size,
        "file_hash":       "deadbeef",
        "total_chunks":    total_chunks,
        "compressed":      False,
        "compressed_size": file_size,
    }


class TestHandleMetadata:
    def test_disabled_auto_rejects(self) -> None:
        c = _make_client()
        c.allow_file_transfers = False
        c._file_transfer.handle_metadata(_good_metadata())
        msg = c._protocol.queue_json.call_args.args[0]
        assert msg["type"] == MessageType.FILE_REJECT
    
    def test_user_decline_sends_reject(self) -> None:
        c = _make_client(prompt_result=False)
        c._peer_key_verified = True
        c._file_transfer.handle_metadata(_good_metadata())
        msg = c._protocol.queue_json.call_args.args[0]
        assert msg["type"] == MessageType.FILE_REJECT
        assert "tid" not in c._file_transfer.active_file_metadata
    
    def test_user_accept_records_metadata(self) -> None:
        c = _make_client(prompt_result=True)
        c._peer_key_verified = True
        c._file_transfer.handle_metadata(_good_metadata())
        msg = c._protocol.queue_json.call_args.args[0]
        assert msg["type"] == MessageType.FILE_ACCEPT
        assert "tid" in c._file_transfer.active_file_metadata
        assert c._protocol.send_dummy_messages is False
    
    def test_malformed_metadata_errors(self) -> None:
        c = _make_client()
        c._file_transfer.handle_metadata({"type": MessageType.FILE_METADATA})  # missing fields
        c.ui.display_error_message.assert_called_once()


class TestHandleAcceptReject:
    def test_accept_unknown_id(self) -> None:
        c = _make_client()
        c._file_transfer.handle_accept({"transfer_id": "nope"})
        c.ui.display_system_message.assert_called_once()
        assert c._protocol.send_dummy_messages is True
    
    def test_accept_missing_id(self) -> None:
        c = _make_client()
        c._file_transfer.handle_accept({})
        c.ui.display_error_message.assert_called_once()
    
    def test_accept_starts_sender_thread(self, tmp_path: Path, monkeypatch) -> None:
        c = _make_client()
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        c._file_transfer.pending_file_transfers["tid"] = {
            "file_path": p,
            "metadata":  {"filename": "a.bin", "total_chunks": 1},
            "compress":  False,
        }  # type: ignore[typeddict-item]
        started: list[bool] = []
        
        class FakeThread:
            def __init__(self, target, args, daemon):
                self._target = target
                self._args = args
            
            def start(self) -> None:
                started.append(True)
        
        monkeypatch.setattr(threading, "Thread", FakeThread)
        c._file_transfer.handle_accept({"transfer_id": "tid"})
        assert started == [True]
        assert "tid" in c.file_handler.sending_transfers
    
    def test_reject_known_drops(self) -> None:
        c = _make_client()
        c._file_transfer.pending_file_transfers["tid"] = {
            "file_path": Path("x"),
            "metadata":  {"filename": "a.bin"},
            "compress":  False,
        }  # type: ignore[typeddict-item]
        c._file_transfer.handle_reject({"transfer_id": "tid", "reason": "no"})
        assert "tid" not in c._file_transfer.pending_file_transfers
    
    def test_reject_unknown_errors(self) -> None:
        c = _make_client()
        c._file_transfer.handle_reject({"transfer_id": "unknown"})
        c.ui.display_error_message.assert_called_once()
    
    def test_reject_missing_id(self) -> None:
        c = _make_client()
        c._file_transfer.handle_reject({})
        c.ui.display_error_message.assert_called_once()


class TestHandleComplete:
    def test_known_id_drops(self) -> None:
        c = _make_client()
        c._file_transfer.pending_file_transfers["tid"] = {
            "file_path": Path("x"),
            "metadata":  {"filename": "a.bin"},
            "compress":  False,
        }  # type: ignore[typeddict-item]
        c._protocol.send_dummy_messages = False
        c._file_transfer.handle_complete({"transfer_id": "tid"})
        assert "tid" not in c._file_transfer.pending_file_transfers
        assert c._protocol.send_dummy_messages is True
    
    def test_unknown_id_errors(self) -> None:
        c = _make_client()
        c._file_transfer.handle_complete({"transfer_id": "x"})
        c.ui.display_error_message.assert_called_once()
    
    def test_missing_id_errors(self) -> None:
        c = _make_client()
        c._file_transfer.handle_complete({})
        c.ui.display_error_message.assert_called_once()


class TestHandleChunkBinary:
    def test_unknown_transfer_errors(self) -> None:
        c = _make_client()
        c._file_transfer.handle_chunk_binary({
            "transfer_id": "missing", "chunk_index": 0, "chunk_data": b"x",
        })
        c.ui.display_error_message.assert_called_once()
    
    def test_single_chunk_reassembles_and_sends_complete(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        c = _make_client()
        payload = b"hello chunk" * 10
        file_hash = hashlib.blake2b(payload, digest_size=32).hexdigest()
        meta = {
            "filename":        "got.bin",
            "file_size":       len(payload),
            "file_hash":       file_hash,
            "total_chunks":    1,
            "compressed":      False,
            "compressed_size": len(payload),
        }
        c._file_transfer.active_file_metadata["tid"] = meta  # type: ignore[typeddict-item]
        c._file_transfer.handle_chunk_binary({
            "transfer_id": "tid", "chunk_index": 0, "chunk_data": payload,
        })
        out_path = tmp_path / "got.bin"
        assert out_path.exists()
        assert out_path.read_bytes() == payload
        # FILE_COMPLETE queued
        completes = [
            call.args[0] for call in c._protocol.queue_json.call_args_list
            if call.args and call.args[0].get("type") == MessageType.FILE_COMPLETE
        ]
        assert completes and completes[0]["transfer_id"] == "tid"
