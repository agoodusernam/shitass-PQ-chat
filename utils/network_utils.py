import json
import socket
import struct
from typing import Any


def encode_send_message(sock: socket.socket, data: Any) -> str | None:
    encoded: bytes = json.dumps(data).encode('utf-8')
    return send_message(sock, encoded)


def send_message(sock: socket.socket, data: bytes) -> str | None:
    """Send a length-prefixed message over a socket."""
    try:
        length = struct.pack('!I', len(data))
        sock.sendall(length + data)
        return None
    except socket.error as e:
        return str(e)


def receive_message(sock: Any) -> bytes:
    """Receive a length-prefixed message from a socket."""
    # First, receive the length
    length_data = b''
    while len(length_data) < 4:
        chunk = sock.recv(4 - len(length_data))
        if not chunk:
            raise ConnectionError("Connection closed")
        length_data += chunk
    
    length = struct.unpack('!I', length_data)[0]
    
    # Then receive the message
    message_data = b''
    while len(message_data) < length:
        chunk = sock.recv(length - len(message_data))
        if not chunk:
            raise ConnectionError("Connection closed")
        message_data += chunk
    
    return message_data
