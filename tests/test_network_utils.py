"""Tests for ``utils.network_utils``."""
from __future__ import annotations

import json
import socket
import struct
from unittest.mock import MagicMock

import pytest

from protocol.constants import MAX_MESSAGE_SIZE
from utils.network_utils import encode_send_message, receive_message, send_message


class _FakeSock:
    def __init__(self, incoming: bytes = b"") -> None:
        self.sent = b""
        self._buf = incoming
    
    def sendall(self, data: bytes) -> None:
        self.sent += data
    
    def recv(self, n: int) -> bytes:
        chunk = self._buf[:n]
        self._buf = self._buf[n:]
        return chunk


class TestSendMessage:
    def test_prefixes_length(self) -> None:
        sock = _FakeSock()
        assert send_message(sock, b"abc") is None
        assert sock.sent == struct.pack("!I", 3) + b"abc"
    
    def test_socket_error_returned(self) -> None:
        sock = MagicMock()
        sock.sendall.side_effect = socket.error("boom")
        assert send_message(sock, b"x") == "boom"


class TestEncodeSendMessage:
    def test_serializes_json(self) -> None:
        sock = _FakeSock()
        assert encode_send_message(sock, {"k": 1}) is None
        length = struct.unpack("!I", sock.sent[:4])[0]
        assert json.loads(sock.sent[4:4 + length]) == {"k": 1}


class TestReceiveMessage:
    def test_roundtrip(self) -> None:
        payload = b"hello world"
        sock = _FakeSock(struct.pack("!I", len(payload)) + payload)
        assert receive_message(sock) == payload
    
    def test_too_large_raises(self) -> None:
        sock = _FakeSock(struct.pack("!I", MAX_MESSAGE_SIZE + 1))
        with pytest.raises(ValueError):
            receive_message(sock)
    
    def test_closed_in_length(self) -> None:
        with pytest.raises(ConnectionError):
            receive_message(_FakeSock(b""))
    
    def test_closed_mid_payload(self) -> None:
        sock = _FakeSock(struct.pack("!I", 10) + b"only5")
        with pytest.raises(ConnectionError):
            receive_message(sock)
