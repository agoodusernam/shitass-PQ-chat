# shared.py - Shared cryptographic utilities and protocol definitions
# pylint: disable=trailing-whitespace, line-too-long
import base64
import os
import json
import secrets
import socket
import struct
import hashlib
import shutil
import gzip
import io
import tempfile
import threading
import time
import typing
import warnings
from collections import deque
from enum import IntEnum, unique
from typing import Final, Any, SupportsIndex, SupportsBytes, TypedDict, NotRequired
from collections.abc import Generator, Buffer
from collections import OrderedDict
import binascii

import config_handler
import config_manager
import configs
assert config_manager  # silence unused import warning


try:
    from pqcrypto.kem import ml_kem_1024, hqc_256 # type: ignore # Still not a production ready, but better than before
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCMSIV
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher, CipherContext

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hmac import HMAC
    
    from cryptography.hazmat.primitives.constant_time import bytes_eq
    
    from cryptography.exceptions import InvalidTag
except ImportError as exc_:
    print("Required cryptographic libraries not found.")
    raise ImportError("Please install the required libraries with pip install -r requirements.txt") from exc_

# Protocol constants
PROTOCOL_VERSION: Final[str] = "7.1.1"
# Protocol compatibility is denoted by version number
# Breaking.Minor.Patch - only Breaking versions are checked for compatibility.
# Breaking version changes introduce breaking changes that are not compatible with previous versions of the same major version.
# Minor version changes may add features but remain compatible with previous minor versions of the same major version.
# Patch versions are for bug fixes and minor improvements that do not affect compatibility.

# File transfer constants
SEND_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB chunks for sending

# Incompressible file types where compression is wasteful
INCOMPRESSIBLE_EXTENSIONS: Final[set[str]] = {
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".lz4", ".7z", ".rar", ".hc", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".svgz",
    ".mp3", ".ogg", ".flac", ".aac", ".wav",
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mpeg", ".mpg",
    ".pdf", ".dmg", ".apk", ".jar"
}

class DoubleEncryptor:
    """
    Provides an authenticated two-AEAD encryption scheme with an additional OTP-like keystream pre-mask.

    Components:
        - OTP-like pre-mask: Before AEAD, the PKCS7-padded plaintext is XORed with a keystream derived
          from `OTP_secret`, the per-message counter, and the payload length. The keystream is produced
          via KDF/HMAC primitives and is deterministic per message/length. This is not an
          information-theoretic OTP, but a KDF-based stream that adds defence in depth.
        - Double AEAD: The masked payload is then encrypted with AES-GCM-SIV and ChaCha20-Poly1305.
          Nonces for each layer are derived by XORing the caller-provided 12-byte nonce with halves of
          the 64-byte key to reduce nonce misuse risk (even if the provided nonce repeats).

    Key material:
        - Requires a 64-byte key: first 32 bytes for AES-GCM-SIV, last 32 bytes for ChaCha20-Poly1305.
        - `OTP_secret` is a separate secret (e.g. from HQC) used solely for keystream derivation.
    
    Padding:
        - Payloads are PKCS7-padded to 512 bytes to hinder message size analysis.
    
    Associated Data (AAD):
        - The same AAD is authenticated by both AEAD layers to protect metadata.
    
    Security notes:
        - Keystream uniqueness relies on the tuple (`OTP_secret`, `message_counter`, payload length).
          Do not reuse counters with the same `OTP_secret`.
        - As long as one of these algorithms stay secure, the scheme remains secure. Any two can be broken
          and any data is still unreadable without the key
    """
    def __init__(self, key: bytes, OTP_secret: bytes, message_counter: int):
        """
        Args:
            key: 64 bytes. First 32 bytes for AES-GCM-SIV, last 32 bytes for ChaCha20-Poly1305.
            OTP_secret: Secret seed used to derive the OTP-like keystream that pre-masks the padded data.
            message_counter: Monotonically increasing counter mixed into the keystream to ensure per-message
                             uniqueness.
        """
        self._key: bytes = key
        self._aes: AESGCMSIV = AESGCMSIV(key[:32])
        self._chacha: ChaCha20Poly1305 = ChaCha20Poly1305(key[32:])
        self._OTP_secret: bytes = OTP_secret
        self.message_counter: int = message_counter
        
    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = True) -> bytes:
        if pad:
            padder = PKCS7(512).padder()
            new_data = padder.update(data) + padder.finalize()
        else:
            new_data = data
        
        aes_nonce = xor_bytes(nonce, self._key[:12])
        chacha_nonce = xor_bytes(nonce, self._key[-12:])
        
        layer0 = xor_bytes(new_data, self._derive_OTP_keystream(len(new_data), aes_nonce + chacha_nonce))
        layer1 = self._aes.encrypt(aes_nonce, layer0, associated_data)
        layer2 = self._chacha.encrypt(chacha_nonce, layer1, associated_data)
        return layer2
    
    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = True) -> bytes:
        aes_nonce = xor_bytes(nonce, self._key[:12])
        chacha_nonce = xor_bytes(nonce, self._key[-12:])
        
        layer2 = self._chacha.decrypt(chacha_nonce, data, associated_data)
        layer1 = self._aes.decrypt(aes_nonce, layer2, associated_data)
        layer0 = xor_bytes(layer1, self._derive_OTP_keystream(len(layer1), aes_nonce + chacha_nonce))

        if pad:
            unpadder = PKCS7(512).unpadder()
            return unpadder.update(layer0) + unpadder.finalize()
        return layer0
    
    def _derive_OTP_keystream(self, length: int, additional_salt: bytes) -> bytes:
        """Generate keystream from HQC shared secret using message counter."""
        
        # Mix: HQC secret + message counter
        hasher = hashlib.shake_256()
        hasher.update(self._OTP_secret)
        hasher.update(additional_salt)
        hasher.update(self.message_counter.to_bytes(8, byteorder="little"))
        return hasher.digest(length)

    def __del__(self):
        # This is not particularly secure, but it's better than nothing
        self._key = b"\x00" * 32
        del self._key
        
        del self._aes
        del self._chacha

class StreamingDoubleEncryptor:
    """
    Similar to DoubleEncryptor except not authenticated.
    This is for the DeadDrop feature in which chunks are not always
    guaranteed to be decrypted in the same size as encrypted.

    Conforms to DoubleEncryptor interface.
    """
    def __init__(self, key: bytes, OTP_secret: bytes | None = None, message_counter: int | None = None):
        self._key = key
        _ = OTP_secret
        _ = message_counter

    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = False) -> bytes:
        if associated_data is not None:
            warnings.warn("StreamingDoubleEncryptor does not support associated data and is NOT authenticated.",
                          RuntimeWarning)

        if pad:
            warnings.warn("StreamingDoubleEncryptor does not support padding.", RuntimeWarning)

        chacha_encryptor: CipherContext = Cipher(algorithms.ChaCha20(self._key[32:], nonce), None).encryptor()
        aes_encryptor: CipherContext = Cipher(algorithms.AES(self._key[:32]), modes.CTR(nonce)).encryptor()
        layer1 = chacha_encryptor.update(data) + chacha_encryptor.finalize()
        layer2 = aes_encryptor.update(layer1) + aes_encryptor.finalize()
        return layer2

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = False) -> bytes:
        if associated_data is not None:
            warnings.warn("StreamingDoubleEncryptor does not support associated data and is NOT authenticated.",
                          RuntimeWarning)

        if pad:
            warnings.warn("StreamingDoubleEncryptor does not support padding.", RuntimeWarning)

        chacha_decryptor: CipherContext = Cipher(algorithms.ChaCha20(self._key[32:], nonce), None).decryptor()
        aes_decryptor: CipherContext = Cipher(algorithms.AES(self._key[:32]), modes.CTR(nonce)).decryptor()
        layer2 = aes_decryptor.update(data) + aes_decryptor.finalize()
        layer1 = chacha_decryptor.update(layer2) + chacha_decryptor.finalize()
        return layer1

@unique
class MessageType(IntEnum):
    NONE = -1
    # Key Exchange
    # Server to client
    INITIATE_KEY_EXCHANGE = 1
    KEY_EXCHANGE_COMPLETE = 2
    KEY_EXCHANGE_RESET = 3
    # Client to server
    KEY_EXCHANGE_RESPONSE = 4
    KEY_EXCHANGE_INIT = 5
    
    # Messaging
    ENCRYPTED_MESSAGE = 10
    DELIVERY_CONFIRMATION = 11
    DUMMY_MESSAGE = 12
    TEXT_MESSAGE = 13
    
    # File Transfer
    FILE_METADATA = 20
    FILE_ACCEPT = 21
    FILE_REJECT = 22
    FILE_CHUNK = 23
    FILE_COMPLETE = 24
    
    # Voice Call
    VOICE_CALL_INIT = 30
    VOICE_CALL_ACCEPT = 31
    VOICE_CALL_REJECT = 32
    VOICE_CALL_DATA = 33
    VOICE_CALL_END = 34
    
    # Server-to-Client Control
    SERVER_FULL = 40
    SERVER_VERSION_INFO = 41
    SERVER_DISCONNECT = 42
    ERROR = 43
    KEEP_ALIVE = 44
    
    # Client-to-Server Control
    CLIENT_DISCONNECT = 50
    KEEP_ALIVE_RESPONSE = 51
    
    # Client-to-Client Control
    EMERGENCY_CLOSE = 60
    EPHEMERAL_MODE_CHANGE = 61
    KEY_VERIFICATION = 62
    NICKNAME_CHANGE = 63
    REKEY = 64
    
    # Dead drop functionality
    DEADDROP_START = 70
    DEADDROP_KE_RESPONSE = 71
    
    DEADDROP_CHECK = 72
    DEADDROP_CHECK_RESPONSE = 73
    
    DEADDROP_UPLOAD = 74
    
    DEADDROP_DOWNLOAD = 75
    DEADDROP_REDOWNLOAD = 76
    
    DEADDROP_ACCEPT = 77
    DEADDROP_DENY = 78
    
    DEADDROP_DATA = 79
    DEADDROP_COMPLETE = 80
    DEADDROP_MESSAGE = 81
    DEADDROP_PROVE = 82
    
    
    @classmethod
    def _missing_(cls, value):
        return cls.NONE


class LRUCache:
    """
    Implements a Least Recently Used (LRU) Cache.

    This class provides a mechanism to store a fixed amount of key-value pairs
    with a limited capacity, evicting the least recently used items in order to
    maintain the constraint. The cache ensures that the most frequently accessed
    items are retained in memory, making it useful for scenarios where caching
    is needed and the data set exceeds available memory.

    :ivar cache: Stores the key-value pairs in an ordered manner, enabling quick
        access and management of least recently used items.
    :type cache: collections.OrderedDict[int, bytes]
    :ivar capacity: The maximum number of items that the cache can store at any
        given time.
    :type capacity: int
    """
    def __init__(self, capacity: int):
        self.cache: OrderedDict[int, bytes] = OrderedDict()
        self.capacity = capacity

    def __getitem__(self, key: int) -> bytes | None:
        if key not in self.cache:
            return None
        else:
            self.cache.move_to_end(key)
            return self.cache[key]

    def __setitem__(self, key: int, value: bytes) -> None:
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last = False)
            
    def pop(self, key: int) -> bytes | None:
        if key in self.cache:
            value = self.cache.pop(key)
            return value
        else:
            return None


class FileMetadata(TypedDict):
    """
    Typed dict describing metadata about a file transfer.
    This is used to track incoming/outgoing file transfers and is shared across
    client and GUI code. It intentionally excludes the "type" field which is
    part of the on-the-wire message envelope.
    """
    transfer_id: str
    filename: str
    file_size: int
    file_hash: str
    total_chunks: int
    compressed: bool
    processed_size: int
    # Optional fields used by UI layers
    save_path: NotRequired[str]

class FileTransfer(TypedDict):
    file_path: str
    metadata:  FileMetadata
    compress:  bool

class StreamingGzipCompressor:
    """
    A streaming gzip compressor that yields compressed chunks as they're ready.

    Takes no arguments.
    """
    
    def __init__(self) -> None:
        self.buffer: io.BytesIO = io.BytesIO()
        self.compressor: gzip.GzipFile = gzip.GzipFile(fileobj=self.buffer, mode='wb', compresslevel=9)
    
    def compress_chunk(self, data: bytes) -> bytes:
        """
        Compress a chunk of data and return any available compressed output.

        :param data: The data to compress.

        :return: A compressed chunk of data, or an empty bytes object if no data is available.
        """
        if data:
            self.compressor.write(data)
        
        self.buffer.seek(0)
        compressed_data = self.buffer.read()
        
        # Reset buffer for next chunk
        self.buffer.seek(0)
        self.buffer.truncate(0)
        
        return compressed_data
    
    def finalise(self) -> bytes:
        """Finalise compression and return any remaining compressed data."""
        self.compressor.close()
        
        # Get any remaining compressed data
        self.buffer.seek(0)
        final_data = self.buffer.read()
        self.buffer.close()
        
        return final_data


class DecodeError(Exception):
    pass

def decide_compression(file_path: str, user_pref: bool = True) -> bool:
    """
    Decide whether to compress a file before sending.
    Compression is enabled only if the user prefers it AND the file is not of a
    type that's typically incompressible.
    """
    if not user_pref:
        return False
    _, ext = os.path.splitext(file_path)
    return ext.lower() not in INCOMPRESSIBLE_EXTENSIONS



def bytes_to_human_readable(size: int) -> str:
    """
    Convert a byte count to a human-readable format with appropriate units.
    
    Args:
        size (int): The number of bytes to convert.
        
    Returns:
        str: A formatted string with the size and appropriate unit (B, KB, MB, or GB).
        
    """
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KiB"
    if size < 1024 ** 3:
        return f"{size / 1024 ** 2:.1f} MiB"
    
    return f"{size / 1024 ** 3:.2f} GiB"


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte objects
    """
    length = len(a) if len(a) > len(b) else len(b)
    int_a = int.from_bytes(a, byteorder="little")
    int_b = int.from_bytes(b, byteorder="little")
    
    xor_result = int_a ^ int_b
    return xor_result.to_bytes(length, byteorder="little")

def sanitize_str(field: str) -> str:
    """Return ASCII-only str truncated to 32 chars; fallback to '?' if empty."""
    s_ascii = field.encode('ascii', errors='ignore').decode('ascii', errors='ignore')
    if len(s_ascii) > 32:
        s_ascii = s_ascii[:32]
    return s_ascii or "?"


class SecureChatProtocol:
    """
    SecureChatProtocol - Implements the cryptographic protocol for secure chat using ML-KEM and AES-GCM.
    """
    
    def __init__(self) -> None:
        """
        Initialise the secure chat protocol with the default cryptographic state.
        
        Sets up all necessary state variables for the ML-KEM-1024 + X25519 key exchange,
        AES-GCM-SIV + ChaCha20Poly1305 encryption, perfect forward secrecy, replay protection, and
        file transfer functionality.
        
        A guaranteed attribute is an attribute that is guaranteed to exist and have a valid value.
        This means that the value of the attribute is always correct and can be safely used after initialisation.
        
        Guaranteed Attributes:
            config (ConfigHandler): The configuration handler instance.
            message_counter (int): The current message counter.
            peer_counter (int): The current peer counter.
            peer_key_verified (bool): Indicates whether the peer's public key has been verified.
            
            file_transfers (dict[str, dict]): A dictionary of file transfers in progress.
            received_chunks (dict[str, set[int]]): A dictionary of received chunks for file transfers.
            temp_file_paths (dict[str, str]): A dictionary of temporary file paths for file transfers.
            open_file_handles (dict[str, typing.IO]): A dictionary of open file handles for file transfers.
            sending_transfers (dict[str, FileMetadata]): A dictionary of file transfers in progress.
            
            message_queue (deque): A deque of messages to be sent over the socket.
            sender_running (bool): Indicates whether the sender thread is running.
            sender_lock (threading.Lock): A lock object to synchronise access to the message queue.
            
            send_dummy_messages (bool): Indicates whether dummy messages should be sent.
            
            skipped_counters: (LRUCache): A dictionary of skipped counters and their ratchet state.
            
            rekey_in_progress (bool): Indicates whether a rekey is in progress.
        
        Unsafe attributes are attributes that may not have a valid value.
        These may be None, empty, or have invalid values.
        They will default to whatever an "empty" value would be.
        
        Unsafe Attributes:
            peer_version (str): The version of the peer's SecureChat protocol.
            own_private_key (bytes): The private key of the local peer.
            encryption_key (bytes): The encryption key for the current session.
            shared_key (bytes): The shared key for the current session.
            peer_public_key (bytes): The public key of the peer.
            own_public_key (bytes): The public key of the local peer.
            send_chain_key (bytes): The chain key for the current session.
            receive_chain_key (bytes): The chain key for the current session.
            
            socket (socket.socket | None): The socket object used for communication.
            sender_thread (threading.Thread | None): The sender thread used for sending messages.
            
            pending_shared_key (bytes): The pending shared key for the current session.
            pending_encryption_key (bytes): The pending encryption key for the current session.
            pending_send_chain_key (bytes): The pending send chain key for the current session.
            pending_receive_chain_key (bytes): The pending receive chain key for the current session.
            rekey_private_key (bytes): The private key for the current rekey.
            
            dh_private_key (X25519PrivateKey | None): The private key for the X25519 DH exchange.
            dh_public_key_bytes (bytes): The public key bytes for the X25519 DH exchange.
            peer_dh_public_key_bytes (bytes): The public key bytes for the peer's X25519 DH exchange.
            msg_recv_private (X25519PrivateKey | None): The private key for the message-phase Double Ratchet.
            msg_peer_base_public (bytes): The base public key for the peer's message-phase Double Ratchet.
            
        """
        # Configuration + protocol
        self.config: config_handler.ConfigHandler = config_handler.ConfigHandler()
        self.peer_version: str = "0.0.0"
        
        # Transport + queuing
        self.message_queue: deque = deque()
        self.socket: socket.socket | None = None
        self.sender_thread: threading.Thread | None = None
        self.sender_running: bool = False
        self.sender_lock: threading.Lock = threading.Lock()
        self._send_dummy_messages: bool = configs.SEND_DUMMY_PACKETS
        
        # Cryptographic identity + peer info
        self.mlkem_public_key: bytes = bytes()
        self.mlkem_private_key: bytes = bytes()
        self.hqc_public_key: bytes = bytes()
        self.hqc_private_key: bytes = bytes()
        
        self.peer_mlkem_public_key: bytes = bytes()
        self.peer_hqc_public_key: bytes = bytes()
        self.peer_key_verified: bool = False
        
        # Session keys
        self.shared_key: bool = False
        self.verification_key: bytes = bytes()
        self._hqc_secret: bytes = bytes()
        
        # Ratchet state (symmetric)
        self.message_counter: int = 0
        self.peer_counter: int = 0
        self.send_chain_key: bytes = bytes()
        self.receive_chain_key: bytes = bytes()
        
        # X25519 ephemeral DH (session setup)
        self.dh_private_key: X25519PrivateKey | None = None
        self.dh_public_key_bytes: bytes = bytes()
        self.peer_dh_public_key_bytes: bytes = bytes()
        
        # Message-phase Double Ratchet
        self.msg_recv_private: X25519PrivateKey | None = None
        self.msg_peer_base_public: bytes = bytes()
        self.skipped_counters: LRUCache = LRUCache(1000)
        
        # Rekey state
        self.rekey_in_progress: bool = False
        self.pending_shared_key: bytes = bytes()
        self.pending_encryption_key: bytes = bytes()
        self.pending_send_chain_key: bytes = bytes()
        self.pending_receive_chain_key: bytes = bytes()
        self.pending_hqc_secret: bytes = bytes()
        self.pending_message_counter: int = 0
        self.pending_peer_counter: int = 0
        self.rekey_mlkem_private_key: bytes = bytes()
        self.rekey_hqc_private_key: bytes = bytes()
        self.rekey_dh_public: X25519PublicKey | None = None
        self.rekey_dh_public_bytes: bytes = bytes()
        self.rekey_dh_private: X25519PrivateKey | None = None
        
        # File transfer state
        self.received_chunks: dict[str, set[int]] = {}
        self.temp_file_paths: dict[str, str] = {}
        self.open_file_handles: dict[str, typing.IO] = {}
        self.sending_transfers: dict[str, FileMetadata] = {}
        
        # Automatic rekey tracking
        self.messages_since_last_rekey: int = 0
        # Randomize the rekey interval by ±20% of the base value
        base_interval = configs.REKEY_INTERVAL
        variation = int(base_interval * 0.2)
        self.rekey_interval: int = base_interval + (secrets.randbelow(variation + 1) - variation)
    
    @property
    def encryption_ready(self) -> bool:
        """Check if encryption is ready (shared key and chain keys established)."""
        return bool(self.shared_key and self.send_chain_key and self.receive_chain_key)
    
    def should_auto_rekey(self) -> bool:
        """Check if automatic rekey should be initiated based on message count."""
        return (self.messages_since_last_rekey >= self.rekey_interval and 
                not self.rekey_in_progress and 
                self.encryption_ready)
    
    @property
    def send_dummy_messages(self) -> bool:
        """Check if dummy messages should be sent."""
        return self._send_dummy_messages and not self.rekey_in_progress
    
    @send_dummy_messages.setter
    def send_dummy_messages(self, value: bool) -> None:
        """Set whether dummy messages should be sent."""
        self._send_dummy_messages = value
    
    def reset_key_exchange(self) -> None:
        """
        Reset all cryptographic state to initial values for key exchange restart.
        
        These values will be rewritten quickly, so it's not necessary to zero them manually.
        Even that likely wouldn't actually clear the data from RAM
        """
        # Stop sender thread if running
        self.stop_sender_thread()
        
        self.shared_key = False
        self.message_counter = 0
        self.peer_counter = 0
        self.peer_mlkem_public_key = bytes()
        self.peer_key_verified = False
        self.mlkem_public_key = bytes()
        self._hqc_secret = bytes()
        self.send_chain_key = bytes()
        self.receive_chain_key = bytes()
        # Reset DH ephemeral keys
        self.dh_private_key = None
        self.dh_public_key_bytes = bytes()
        self.peer_dh_public_key_bytes = bytes()
        # Reset message-phase Double Ratchet state
        self.msg_recv_private = None
        self.msg_peer_base_public = bytes()
        # Clear file transfer state as well
        self.received_chunks = {}
        
        # Clear message queue
        with self.sender_lock:
            self.message_queue.clear()
        
        # Close any open file handles
        for file_handle in self.open_file_handles.values():
            try:
                file_handle.close()
            except (OSError, ValueError):
                # Non-critical: file handle might already be closed or invalid
                pass
        self.open_file_handles = {}
        
        # Clean up any temporary files
        for temp_path in self.temp_file_paths.values():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except (OSError, PermissionError):
                # Non-critical: leftover temp file will be cleaned by OS eventually
                pass
        self.temp_file_paths = {}
        self.sending_transfers = {}
    
    
    def stop_sending_transfer(self, transfer_id: str) -> None:
        """Stop tracking a sending file transfer."""
        if transfer_id in self.sending_transfers:
            del self.sending_transfers[transfer_id]
    
    @property
    def has_active_file_transfers(self) -> bool:
        """Check if any file transfers (sending or receiving) are currently active."""
        if self.received_chunks or self.open_file_handles or self.sending_transfers:
            return True
        return False
    
    def start_sender_thread(self, sock: socket.socket) -> None:
        """Start the background sender thread for message queuing."""
        if self.sender_thread is not None and self.sender_thread.is_alive():
            return  # Thread already running
        
        self.socket = sock
        self.sender_running = True
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.sender_thread.start()
    
    def stop_sender_thread(self) -> None:
        """Stop the background sender thread."""
        self.sender_running = False
        if self.sender_thread is not None and self.sender_thread.is_alive():
            self.sender_thread.join(timeout=1.0)  # Wait up to 1 second for thread to stop
        self.sender_thread = None
        self.socket = None
    
    def queue_message(self, message: bytes | str | dict[Any, Any] | tuple[str, Any]) -> None:
        """
        Add a message to the send queue.
        
        The message can be one of the following:
        - bytes: already-prepared data to send as-is (control or pre-encrypted)
        - str: plaintext to be encrypted and sent
        - dict: JSON-serializable object to be encrypted and sent
        - tuple: instruction for the sender loop, supported forms:
            ("encrypt_text", str)
            ("encrypt_json", dict)
            ("encrypt_json_then_switch", dict)  # send encrypted under current keys, then activate pending keys
            ("file_chunk", transfer_id: str, chunk_index: int, chunk_data: bytes)
            ("plaintext", bytes)  # send as-is (control)
            ("encrypted", bytes)  # send as-is (already encrypted)
        """
        with self.sender_lock:
            self.message_queue.append(message)
    
    def send_emergency_close(self) -> bool:
        """
        Send an emergency close message immediately, bypassing the queue.
        
        Behavior:
            - If encryption is ready, encrypt immediately and send over the socket.
            - If encryption is not ready, send plaintext immediately.
        
        Returns:
            bool: True if the message was sent successfully, False otherwise.
        """
        if not self.socket:
            return False
        emergency_message = {"type": MessageType.EMERGENCY_CLOSE}
        if self.shared_key and self.send_chain_key:
            # Encrypt immediately using normal ratcheting
            encrypted = self.encrypt_message(json.dumps(emergency_message))
            send_message(self.socket, encrypted)
        
        else:
            # Fall back to plaintext immediate send
            send_message(self.socket, json.dumps(emergency_message).encode('utf-8'))
        
        return True
    
    def _generate_dummy_message(self) -> bytes:
        """Generate a dummy message with random data."""
        dummy_data = os.urandom(configs.MAX_DUMMY_PACKET_SIZE)
        
        dummy_message = {
            "type": MessageType.DUMMY_MESSAGE,
            "data": base64.b64encode(dummy_data).decode('utf-8')
        }
        return self.encrypt_message(json.dumps(dummy_message))
    
    def _sender_loop(self) -> None:
        """Background thread loop that sends messages every 250 ms.
        
        This loop is responsible for performing encryption for all queued
        non-control messages before sending them over the socket.
        Control messages (key exchange, explicit plaintext items) are sent as-is.
        """
        while self.sender_running:
            item = self._get_next_item()
            to_send, post_action = self._prepare_item_for_sending(item)
            
            if to_send is not None and self.socket is not None:
                self._send_prepared_item(to_send, post_action)
            
            time.sleep(0.25)
    
    def _get_next_item(self):
        """Get the next item from the queue or generate a dummy message."""
        with self.sender_lock:
            if self.message_queue:
                return self.message_queue.popleft()
        
        # Generate dummy message if appropriate
        if self.send_dummy_messages and not self.has_active_file_transfers:
            if self.encryption_ready and configs.SEND_DUMMY_PACKETS:
                return self._generate_dummy_message()
        
        return None
    
    def _prepare_item_for_sending(self, item) -> tuple[bytes | None, str | None]:
        """Convert a queue item into bytes ready for transmission."""
        if item is None:
            return None, None
        
        try:
            if isinstance(item, (bytes, bytearray)):
                return bytes(item), None
            
            if isinstance(item, (str, dict)):
                return self._encrypt_plaintext_item(item), None
            
            if isinstance(item, tuple) and item:
                return self._process_instruction_tuple(item)
            
            raise ValueError(f"Unsupported item type: {type(item)}")
        
        except (ValueError, TypeError) as e:
            print(f"Message preparation error (dropped): {e}")
            return None, None
        except Exception as e:
            print(f"Unexpected error preparing message (dropped): {e}")
            return None, None
    
    def _encrypt_plaintext_item(self, item) -> bytes:
        """Encrypt a string or dict item."""
        if isinstance(item, dict):
            item = json.dumps(item)
        
        if not (self.shared_key and self.send_chain_key):
            raise ValueError("Encryption keys not ready for plaintext item")
        
        return self.encrypt_message(item)
    
    def _process_instruction_tuple(self, item: tuple) -> tuple[bytes, str | None]:
        """Process instruction tuples like ('encrypt_text', data)."""
        kind = item[0]
        
        if kind == "encrypt_text" and len(item) >= 2:
            return self._encrypt_text_message(item[1]), None
        
        if kind == "encrypt_json" and len(item) >= 2:
            return self._encrypt_json_message(item[1]), None
        
        if kind == "encrypt_json_then_switch" and len(item) >= 2:
            return self._encrypt_json_message(item[1]), "switch_keys"
        
        if kind in ("plaintext", "encrypted") and len(item) >= 2:
            data = item[1]
            if isinstance(data, (SupportsIndex, SupportsBytes, Buffer)):
                return bytes(data), None
            raise TypeError("Provided data is not bytes-like for plaintext/encrypted send")
        
        raise ValueError(f"Unsupported instruction tuple: {kind}")
    
    def _encrypt_text_message(self, text: str) -> bytes:
        """Encrypt a text message."""
        if not isinstance(text, str) or not (self.shared_key and self.send_chain_key):
            raise ValueError("Invalid text encryption request or keys not ready")
        
        inner_obj = {"type": MessageType.TEXT_MESSAGE, "text": text}
        return self.encrypt_message(json.dumps(inner_obj))
    
    def _encrypt_json_message(self, obj: dict) -> bytes:
        """Encrypt a JSON message."""
        if not isinstance(obj, dict) or not (self.shared_key and self.send_chain_key):
            raise ValueError("Invalid JSON encryption request or keys not ready")
        
        return self.encrypt_message(json.dumps(obj))
    
    def _send_prepared_item(self, to_send: bytes, post_action: str | None) -> None:
        """Send prepared bytes and perform any post-send actions."""
        assert self.socket is not None
        success, err_msg = send_message(self.socket, to_send)
        if not success:
            print(f"Failed to send message: {err_msg}")
        
        if post_action == "switch_keys":
            self.activate_pending_keys()
    
    def generate_keys(self) -> bytes:
        """Generate ML-KEM keypair for key exchange."""
        self.mlkem_public_key, self.mlkem_private_key = ml_kem_1024.generate_keypair()
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key_bytes = self.dh_private_key.public_key().public_bytes_raw()
        self.hqc_public_key, self.hqc_private_key = hqc_256.generate_keypair()
        return self.mlkem_public_key
    
    def derive_keys(self, shared_secret: bytes) -> bytes:
        """Derive encryption and MAC keys from shared secret using HKDF."""
        # Sort public keys lexicographically for deterministic order
        keys = sorted([self.mlkem_public_key, self.peer_mlkem_public_key])
        combined_keys = keys[0] + keys[1]
        salt = hashlib.sha512(combined_keys + b"verification_key_salt").digest()[:32]
        
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=64,
                salt=salt,
                info=b"derive_root_mac_keys"
        )
        derived = hkdf.derive(shared_secret)
    
        # Initialize chain keys for perfect forward secrecy
        self._initialize_chain_keys(shared_secret)
    
        return derived

    def _initialize_chain_keys(self, shared_secret: bytes) -> None:
        """Initialize separate chain keys for sending and receiving."""
        # Sort public keys lexicographically for deterministic order
        keys = sorted([self.mlkem_public_key, self.peer_mlkem_public_key, self.dh_public_key_bytes,
                       self.peer_dh_public_key_bytes, self.hqc_public_key, self.peer_hqc_public_key])
        combined_keys = b''.join(keys)
        salt = hashlib.sha512(combined_keys + b"chain_key_salt").digest()
        
        # Derive a root chain key that both parties will use as the starting point
        chain_hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=salt,
                info=b"chain_key_root"
        )
    
        root_chain_key = chain_hkdf.derive(shared_secret)
    
        # Both send and receive chain keys start with the same value
        # They will diverge as messages are sent and received
        self.send_chain_key = root_chain_key
        self.receive_chain_key = root_chain_key
        return None
    
    @staticmethod
    def _derive_message_key(chain_key: bytes, counter: int) -> bytes:
        """Derive a message key from the chain key and counter."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=64,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"message_key_{counter}".encode()
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def _ratchet_chain_key(chain_key: bytes, counter: int) -> bytes:
        """Advance the chain key (ratchet forward)."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"chain_key_{counter}".encode("utf-8")
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def _mix_dh_with_chain(chain_key: bytes, dh_shared: bytes, counter: int) -> bytes:
        """Mix DH shared secret into the chain key using HKDF with the chain key as salt."""
        info = b"dr_mix" + b"_" + str(counter).encode('utf-8')
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=64,
                salt=chain_key,
                info=info
        )
        return hkdf.derive(dh_shared)
    
    @staticmethod
    def _derive_keys_and_chain(shared_secret: bytes, own_pub: bytes = b"", peer_pub: bytes = b"") -> tuple[bytes, bytes]:
        """Derive encryption key, MAC key, and root chain key from a shared secret without mutating state."""
        # Sort public keys lexicographically for deterministic order (if available)
        if own_pub and peer_pub:
            keys = sorted([own_pub, peer_pub])
            combined_keys = keys[0] + keys[1]
        else:
            combined_keys = b""
        
        enc_salt = hashlib.sha512(combined_keys + b"enc_key_salt").digest()[:32]
        chain_salt = hashlib.sha512(combined_keys + b"chain_salt").digest()[:32]
        
        # Derive encryption and MAC keys
        hkdf_keys = HKDF(
                algorithm=hashes.SHA3_512(),
                length=32,
                salt=enc_salt,
                info=b"key_derivation"
        )
        derived = hkdf_keys.derive(shared_secret)
        enc_key = derived
    
        # Derive root chain key
        hkdf_chain = HKDF(
                algorithm=hashes.SHA3_512(),
                length=64,
                salt=chain_salt,
                info=b"chain_key_root"
        )
        root_chain_key = hkdf_chain.derive(shared_secret)
        return enc_key, root_chain_key
    
    def generate_key_fingerprint(self, public_key: bytes) -> str:
        """Generate a human-readable word-based fingerprint for a public key."""
        # Create SHA-256 hash of the public key
        key_hash = hashlib.sha256(public_key).digest()
        
        # Load the wordlist
        wordlist = self._load_wordlist()
        
        # Convert hash to word-based fingerprint
        words = self._hash_to_words(key_hash, wordlist, num_words=8)
        # 8 words should give ~128 bits of security with a wordlist of ~65k words
        
        return " ".join(words)
    
    @staticmethod
    def _load_wordlist() -> list[str]:
        """Load the wordlist."""
        try:
            wordlist_path = os.path.join(os.path.dirname(__file__), configs.WORDLIST_FILE)
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback if wordlist file is not found
            raise FileNotFoundError(
                    f"{configs.WORDLIST_FILE} not found. Please ensure the wordlist file is in the same directory as "
                    "shared.py")
    
    @staticmethod
    def _hash_to_words(hash_bytes: bytes, wordlist: list[str], num_words: int = 16) -> list[str]:
        """Convert hash bytes to a list of words from the wordlist."""
        # Convert hash to integer for easier manipulation
        hash_int = int.from_bytes(hash_bytes, byteorder='big')
        
        words = []
        for i in range(num_words):
            index = (hash_int >> (i * 8)) % len(wordlist)
            words.append(wordlist[index])
        
        return words
    
    def get_own_key_fingerprint(self) -> str:
        """
        Generate a consistent fingerprint for the session that both users will see.
        Includes both ML-KEM public keys and the ephemeral X25519 DH public keys from the key exchange.
        """
        # Ensure we have all required key materials
        if not all([self.mlkem_public_key, self.peer_mlkem_public_key, self.dh_public_key_bytes,
                    self.peer_dh_public_key_bytes, self.hqc_public_key, self.peer_hqc_public_key]):
            if not self.mlkem_public_key:
                raise ValueError("Own ML-KEM public key not available")
            if not self.peer_mlkem_public_key:
                raise ValueError("Peer ML-KEM public key not available")
            if not self.dh_public_key_bytes:
                raise ValueError("Own DH public key bytes not available")
            if not self.peer_dh_public_key_bytes:
                raise ValueError("Peer DH public key bytes not available")
            if not self.hqc_public_key:
                raise ValueError("Own HQC public key not available")
            if not self.peer_hqc_public_key:
                raise ValueError("Peer HQC public key not available")
        
        # Build a deterministic, order-independent combination of all four keys
        components: list[bytes] = [
            self.mlkem_public_key,
            self.peer_mlkem_public_key,
            self.dh_public_key_bytes,
            self.peer_dh_public_key_bytes,
            self.hqc_public_key,
            self.peer_hqc_public_key,
        ]
        # Sort lexicographically to make result independent of initiator/responder roles
        components.sort()
        combined = b"".join(components)
        
        # Generate fingerprint from combined keys
        return self.generate_key_fingerprint(combined)
    
    @staticmethod
    def create_key_verification_message(verified: bool) -> bytes:
        """Create a key verification status message."""
        message = {
            "type":     MessageType.KEY_VERIFICATION,
            "verified": verified,
        }
        return json.dumps(message).encode('utf-8')
    
    @staticmethod
    def process_key_verification_message(data: bytes) -> bool:
        """Process a key verification message from peer."""
        try:
            message = json.loads(data)
            return message.get("verified", False)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DecodeError("Received invalid key verification message")
    
    def create_key_exchange_init(self, public_key: bytes) -> bytes:
        """Create initial key exchange message with X25519 DH public key."""
        message = {
            "version":       PROTOCOL_VERSION,
            "type":          MessageType.KEY_EXCHANGE_INIT,
            "mlkem_public_key":    base64.b64encode(public_key).decode('utf-8'),
            "dh_public_key": base64.b64encode(self.dh_public_key_bytes).decode('utf-8'),
            "hqc_public_key": base64.b64encode(self.hqc_public_key).decode('utf-8')
        }
        return json.dumps(message).encode('utf-8')
    
    def create_key_exchange_response(self, mlkem_ciphertext: bytes, hqc_ciphertext: bytes) -> bytes:
        """Create key exchange response message including our X25519 DH public key, mlkem and hqc ciphertext, and pk"""
        message = {
            "version":       PROTOCOL_VERSION,
            "type":          MessageType.KEY_EXCHANGE_RESPONSE,
            "mlkem_ciphertext":    base64.b64encode(mlkem_ciphertext).decode('utf-8'),
            "mlkem_public_key":    base64.b64encode(self.mlkem_public_key).decode('utf-8'),
            "hqc_ciphertext": base64.b64encode(hqc_ciphertext).decode('utf-8'),
            "hqc_public_key": base64.b64encode(self.hqc_public_key).decode('utf-8'),
            "dh_public_key": base64.b64encode(self.dh_public_key_bytes).decode('utf-8'),
        }
        return json.dumps(message).encode('utf-8')
    
    @staticmethod
    def derive_combined_shared_secret(kem_shared: bytes, dh_shared: bytes) -> bytes:
        return HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=kem_shared,
                info=b"hybrid kem+x25519"
        ).derive(dh_shared)
    
    def process_key_exchange_init(self, data: bytes) -> tuple[bytes, bytes, str]:
        """Process initial key exchange and return HQC ciphertext, KEM ciphertext, and version warning if any.
        
        Returns:
            tuple: (hqc_ciphertext, mlkem_ciphertext, warning_message)
                  warning_message is "" if protocol versions match
        """
        try:
            message = json.loads(data)
            peer_version = str(message["version"])
            self.peer_version = peer_version
            kem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
            peer_dh_pub_bytes = base64.b64decode(message["dh_public_key"], validate=True)
            hqc_public_key = base64.b64decode(message["hqc_public_key"], validate=True)
        except UnicodeDecodeError as e:
            raise ValueError("Key exchange init message contains invalid UTF-8 characters") from e
        except json.JSONDecodeError as e:
            raise ValueError("Key exchange init message could not be parsed") from e
        except KeyError as e:
            raise ValueError("Key exchange init message is missing required fields") from e
        except binascii.Error as e:
            raise ValueError("Key exchange init message contains invalid base64-encoded data") from e
        
        # Check protocol version
        version_warning = ""
        if peer_version != "" and peer_version != PROTOCOL_VERSION:
            version_warning = (
                f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: {peer_version}. " +
                "Communication may not work properly.")
        # Store peer's KEM public key for verification
        self.peer_mlkem_public_key = kem_public_key
        self.peer_hqc_public_key = hqc_public_key
        # Store peer's DH public key for fingerprinting/verification context
        self.peer_dh_public_key_bytes = peer_dh_pub_bytes
        
        # Generate our own KEM keypair if we don't have one yet (for verification purposes)
        if not self.mlkem_public_key or not self.hqc_public_key:
            self.generate_keys()
        
        # Generate our ephemeral X25519 keypair for DH and compute DH shared secret
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key_bytes = self.dh_private_key.public_key().public_bytes_raw()
        peer_dh_pub = X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)
        dh_shared_secret = self.dh_private_key.exchange(peer_dh_pub)
        
        # Perform KEM encapsulation to obtain KEM shared secret and ciphertext to send back
        mlkem_ciphertext, kem_shared_secret = ml_kem_1024.encrypt(kem_public_key)
        hqc_ciphertext, self._hqc_secret = hqc_256.encrypt(hqc_public_key)
        
        # Combine secrets
        combined_shared = self.derive_combined_shared_secret(kem_shared_secret, dh_shared_secret)
        
        # Derive keys from combined shared secret
        self.verification_key = self.derive_keys(combined_shared)
        self.shared_key = True
        
        # Initialise message-phase Double Ratchet baseline
        self.msg_recv_private = self.dh_private_key
        self.msg_peer_base_public = self.peer_dh_public_key_bytes
        
        return hqc_ciphertext, mlkem_ciphertext, version_warning
    
    def process_key_exchange_response(self, data: bytes) -> str | None:
        """Process key exchange response and derive combined shared key using KEM ⊕ X25519 DH.
        
        Returns:
            tuple: (combined_shared_secret, warning_message)
                  warning_message is None if protocol versions match
        
        Raises:
            DecodeError: Something was wrong with the received data
        """
        try:
            message = json.loads(data)
            mlkem_ciphertext = base64.b64decode(message["mlkem_ciphertext"], validate=True)
            self.peer_mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
            hqc_ciphertext = base64.b64decode(message["hqc_ciphertext"], validate=True)
            self.peer_hqc_public_key = base64.b64decode(message["hqc_public_key"], validate=True)
            peer_dh_pub_bytes = base64.b64decode(message["dh_public_key"], validate=True)
        except (UnicodeDecodeError, binascii.Error):
            raise DecodeError("Key exchange response decode error, UnicodeDecodeError")
        except json.JSONDecodeError:
            raise DecodeError("Key exchange response decode error, json.JSONDecodeError")
        except KeyError:
            raise DecodeError("Key exchange response decode error, KeyError")
            
        peer_version = message.get("version", None)
        
        version_warning = None
        if peer_version is not None and peer_version != PROTOCOL_VERSION:
            version_warning = (f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: " +
                               f"{peer_version}. Communication may not work properly.")
        
        
        # Store peer's DH public key for fingerprinting/verification context
        self.peer_dh_public_key_bytes = peer_dh_pub_bytes
        if not self.dh_private_key:
            raise ValueError("Local DH private key not initialized for key exchange response")
        peer_dh_pub = X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)
        dh_shared_secret = self.dh_private_key.exchange(peer_dh_pub)
        
        kem_shared_secret = ml_kem_1024.decrypt(self.mlkem_private_key, mlkem_ciphertext)
        combined_shared = self.derive_combined_shared_secret(kem_shared_secret, dh_shared_secret)
        self._hqc_secret = hqc_256.decrypt(self.hqc_private_key, hqc_ciphertext)
        
        # Derive keys from combined shared secret
        self.verification_key = self.derive_keys(combined_shared)
        self.shared_key = True
        
        # Initialize message-phase Double Ratchet baseline
        self.msg_recv_private = self.dh_private_key
        self.msg_peer_base_public = self.peer_dh_public_key_bytes
        
        return version_warning

    
    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Encrypt a message with authentication and replay protection using perfect forward secrecy.
        Integrates a Double Ratchet step using X25519 by including a fresh sender public key per message
        and mixing the DH shared secret into the chain key derivation.
        
        Additional MAC rationale:
            For authentication with AES or Poly1305, the message must be decrypted.
            To decrypt the message we need to derive the key.
            If there is no additional MAC, a bad actor could send a message with a very high counter,
            making the program essentially DoS itself.
            It also makes it possible to differentiate between forged messages and messages
            that have been corrupted or manipulated in flight
        
        :param plaintext: The plaintext message to encrypt.
        :return: The encrypted message as bytes, ready to send.
        :raises: ValueError: If no shared key or send chain key is established.
        """
        if not self.shared_key or not self.send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        self.message_counter += 1
        self.messages_since_last_rekey += 1
        
        # Generate ephemeral X25519 key for this message and compute DH with peer's static session public key
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
        peer_pub_bytes = self.peer_dh_public_key_bytes
        if not peer_pub_bytes:
            raise ValueError("Missing peer DH public key for encryption")
        dh_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
        
        # Mix DH into current send chain key to get a message-specific chain state
        mixed_chain_key = self._mix_dh_with_chain(self.send_chain_key, dh_shared, self.message_counter)
        
        # Derive unique message key for this message from the mixed chain
        message_key = self._derive_message_key(mixed_chain_key, self.message_counter)
        
        # Ratchet the send chain key forward for the next message (symmetric ratchet only)
        self.send_chain_key = self._ratchet_chain_key(self.send_chain_key, self.message_counter)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Create AAD from message metadata for authentication
        nonce = os.urandom(12)
        aad_data: dict[str, MessageType | int | str] = {
            "type":          MessageType.ENCRYPTED_MESSAGE,
            "counter":       self.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8')
        }
        aad: bytes = json.dumps(aad_data).encode('utf-8')
        encryptor = DoubleEncryptor(message_key, self._hqc_secret, message_counter=self.message_counter)
        # Encrypt with AES-GCM using the unique message key and AAD
        ciphertext = encryptor.encrypt(nonce, plaintext_bytes, aad)
        del encryptor
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Create authenticated message including our per-message DH public key
        encrypted_message: dict[str, MessageType | int | str] = {
            "type":          MessageType.ENCRYPTED_MESSAGE,
            "counter":       self.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "ciphertext":    base64.b64encode(ciphertext).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8')
        }
        
        verif_hasher = HMAC(self.verification_key, hashes.SHA512())
        # Include dh_public_key in verification to authenticate the ratchet key
        verif_hasher.update(json.dumps({
            "counter":       encrypted_message["counter"],
            "nonce":         encrypted_message["nonce"],
            "dh_public_key": encrypted_message["dh_public_key"],
        }).encode('utf-8'))
        
        encrypted_message["verification"] = base64.b64encode(verif_hasher.finalize()).decode('utf-8')
        
        return json.dumps(encrypted_message).encode('utf-8')
    
    def decrypt_message(self, data: bytes) -> str:
        """Decrypt and authenticate a message using perfect forward secrecy with proper state management.
        Incorporates Double Ratchet: mixes DH shared secret (from peer's included X25519 public key and our
        message-phase private key) into the chain before deriving the message key.
        
        Raises value error if message is invalid or verification fails.
        """
        if not self.shared_key or not self.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        try:
            message: dict[str, Any] = json.loads(data)
            nonce: bytes = base64.b64decode(message["nonce"])
            ciphertext: bytes = base64.b64decode(message["ciphertext"])
            counter: int = message["counter"]
            peer_dh_pub_b64: str = message["dh_public_key"]
            peer_dh_pub_bytes = base64.b64decode(peer_dh_pub_b64, validate=True)
            expected_verification: bytes = base64.b64decode(message["verification"], validate=True)
        except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as e:
            raise ValueError("Message decoding failed, message dropped") from e
        except KeyError as e:
            raise ValueError("Message missing field, message dropped") from e
        
        verif_hasher = HMAC(self.verification_key, hashes.SHA512())
        # Include dh_public_key in verification to authenticate the ratchet key
        verif_hasher.update(json.dumps({
            "counter":       counter,
            "nonce":         message["nonce"],
            "dh_public_key": peer_dh_pub_b64,
        }).encode('utf-8'))
        actual_verification = verif_hasher.finalize()
        if not bytes_eq(expected_verification, actual_verification):
            raise ValueError("Message verification failed, message dropped")
            
        
        # Determine if we have to use a previously saved ratchet step (out-of-order message)
        use_saved = False
        temp_chain_key: bytes
        new_chain_key: bytes = bytes()
        if counter <= self.peer_counter:
            # Try to use a saved pre-ratchet chain state for this counter
            saved = self.skipped_counters[counter]
            if saved is None:
                # As per current implementation, raise the same ValueError when not saved
                raise ValueError("Message is probably legitimate but counter has unexpected value: " +
                                 f"higher than {self.peer_counter} got {counter}")
            temp_chain_key = saved
            use_saved = True
        else:
            # We are moving forward; ratchet across gaps and save intermediate steps
            temp_chain_key = self.receive_chain_key
            for i in range(self.peer_counter + 1, counter):
                # Save the pre-ratchet chain state for counter i so we can later decrypt out-of-order
                if self.skipped_counters[i] is None:
                    self.skipped_counters[i] = temp_chain_key
                # Advance to the next chain state
                temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
        
        # Mix DH from peer's message into the temp chain key
        if not self.msg_recv_private:
            raise ValueError("Local DH private key not initialized for message ratchet")
        
        dh_shared = self.msg_recv_private.exchange(X25519PublicKey.from_public_bytes(peer_dh_pub_bytes))
        
        mixed_chain_key = self._mix_dh_with_chain(temp_chain_key, dh_shared, counter)
        
        # Derive the message key for the current message from the mixed chain
        message_key = self._derive_message_key(mixed_chain_key, counter)
        
        # Calculate what the new chain key state WOULD be (symmetric ratchet only)
        if not use_saved:
            new_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
        
        # Create AAD from message metadata for authentication verification
        aad_data = {
            "type":          MessageType.ENCRYPTED_MESSAGE,
            "counter":       counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(peer_dh_pub_bytes).decode('utf-8')
        }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Decrypt with the derived message key and verify AAD
        decryptor = DoubleEncryptor(message_key, self._hqc_secret, counter)
        try:
            decrypted_data = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            # May or may not actually remove it from memory but it's better than nothing
            message_key = b'\x00' * len(message_key)
            raise ValueError("Message is probably legitimate but failed to decrypt, InvalidTag")
            
        
        try:
            decrypted_data_str = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            # May or may not actually remove it from memory but it's better than nothing
            message_key = b'\x00' * len(message_key)
            raise ValueError("Message is probably legitimate but failed to decode, UnicodeDecodeError")
        
        # Update ratchet state: only when moving forward. For out-of-order (saved) do not change state.
        if use_saved:
            # Remove saved step after successful decryption
            try:
                self.skipped_counters.pop(counter)
            except KeyError:
                pass
        if not use_saved and new_chain_key:
            self.receive_chain_key = new_chain_key
            self.peer_counter = counter
            # Store peer's latest public key for our next send
            self.msg_peer_base_public = peer_dh_pub_bytes
            # Track message for automatic rekey
            self.messages_since_last_rekey += 1
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        return decrypted_data_str
    
    # Rekey methods
    def activate_pending_keys(self) -> None:
        """Atomically switch active session to the pending keys (if available)."""
        if not self.rekey_in_progress:
            return
        if not (self.pending_shared_key and self.pending_encryption_key and
                self.pending_send_chain_key and self.pending_receive_chain_key):
            # Incomplete pending state, do not switch
            return
        # Activate
        self.shared_key = True
        self.verification_key = self.pending_encryption_key
        self.send_chain_key = self.pending_send_chain_key
        self.receive_chain_key = self.pending_receive_chain_key
        self.message_counter = 0
        self.peer_counter = 0
        # Reset automatic rekey counter
        self.messages_since_last_rekey = 0
        # Activate HQC secret if present
        if self.pending_hqc_secret:
            self._hqc_secret = self.pending_hqc_secret
        # Clear pending state
        self.pending_shared_key = bytes()
        self.pending_encryption_key = bytes()
        self.pending_send_chain_key = bytes()
        self.pending_receive_chain_key = bytes()
        self.pending_hqc_secret = bytes()
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        # Clear rekey ephemeral keys
        self.rekey_mlkem_private_key = bytes()
        self.rekey_hqc_private_key = bytes()
        self.rekey_dh_private = None
        self.rekey_dh_public = None
        self.rekey_dh_public_bytes = bytes()
        self.rekey_in_progress = False
    
    def create_rekey_init(self) -> dict[str, str | int]:
        """Create a REKEY init payload to be sent inside an encrypted message using the old key."""
        # Generate ephemeral KEM keypair for this rekey only
        mlkem_public_key, mlkem_private_key = ml_kem_1024.generate_keypair()
        hqc_public_key, hqc_private_key = hqc_256.generate_keypair()
        dh_private = X25519PrivateKey.generate()
        dh_public = dh_private.public_key()
        
        self.rekey_mlkem_private_key = mlkem_private_key
        self.rekey_hqc_private_key = hqc_private_key
        self.rekey_dh_private = dh_private
        self.rekey_dh_public = dh_public
        self.rekey_dh_public_bytes = dh_public.public_bytes_raw()
        self.rekey_in_progress = True
        return {
            "type":       MessageType.REKEY,
            "action":     "init",
            "mlkem_public_key": base64.b64encode(mlkem_public_key).decode('utf-8'),
            "hqc_public_key":   base64.b64encode(hqc_public_key).decode('utf-8'),
            "dh_public_key":    base64.b64encode(dh_public.public_bytes_raw()).decode('utf-8')
        }
    
    def process_rekey_init(self, message: dict[Any, Any]) -> dict[str, int | str]:
        """Process a REKEY init payload; derive pending keys and return REKEY response payload.
        This must be called on the responder, and the response must be sent under the old key.
        """
        try:
            peer_mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
            peer_hqc_public_key = base64.b64decode(message["hqc_public_key"], validate=True)
            peer_dh_public_key_bytes = base64.b64decode(message["dh_public_key"], validate=True)
            peer_dh_public_key = X25519PublicKey.from_public_bytes(peer_dh_public_key_bytes)
        except (binascii.Error, KeyError):
            raise DecodeError("REKEY init decode error, binascii.Error")
        # Produce new shared secret and ciphertext for the initiator
        mlkem_ciphertext, mlkem_shared_secret = ml_kem_1024.encrypt(peer_mlkem_public_key)
        hqc_ciphertext, hqc_secret = hqc_256.encrypt(peer_hqc_public_key)
        self.rekey_dh_private = X25519PrivateKey.generate()
        dh_shared_secret = self.rekey_dh_private.exchange(peer_dh_public_key)
        # Combine ML-KEM and DH secrets (HQC stored separately like in initial key exchange)
        combined_shared = self.derive_combined_shared_secret(mlkem_shared_secret, dh_shared_secret)
        # Store pending derived keys without touching active ones
        enc_key, root_chain = self._derive_keys_and_chain(combined_shared)
        self.pending_shared_key = combined_shared
        self.pending_encryption_key = enc_key
        self.pending_send_chain_key = root_chain
        self.pending_receive_chain_key = root_chain
        self.pending_hqc_secret = hqc_secret
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        self.rekey_in_progress = True
        return {
            "type":       MessageType.REKEY,
            "action":     "response",
            "mlkem_ciphertext": base64.b64encode(mlkem_ciphertext).decode('utf-8'),
            "hqc_ciphertext":   base64.b64encode(hqc_ciphertext).decode('utf-8'),
            "dh_public_key":    base64.b64encode(self.rekey_dh_private.public_key().public_bytes_raw()).decode('utf-8'),
        }
    
    def process_rekey_response(self, message: dict) -> dict:
        """Process a REKEY response payload on the initiator; set pending keys and return commit payload."""
        if not self.rekey_mlkem_private_key:
            raise ValueError("No ephemeral ML-KEM private key for REKEY response")
        if not self.rekey_hqc_private_key:
            raise ValueError("No ephemeral HQC private key for REKEY response")
        if not self.rekey_dh_private:
            raise ValueError("No ephemeral DH private key for REKEY response")
        
        try:
            mlkem_ciphertext = base64.b64decode(message.get("mlkem_ciphertext", ""), validate=True)
            hqc_ciphertext = base64.b64decode(message.get("hqc_ciphertext", ""), validate=True)
            peer_dh_public_key_bytes = base64.b64decode(message.get("dh_public_key", ""), validate=True)
        except binascii.Error:
            raise DecodeError("REKEY response decode error, binascii.Error")
        
        if not mlkem_ciphertext:
            raise ValueError("Missing mlkem_ciphertext in REKEY response")
        if not hqc_ciphertext:
            raise ValueError("Missing hqc_ciphertext in REKEY response")
        if not peer_dh_public_key_bytes:
            raise ValueError("Missing dh_public_key in REKEY response")
        
        # Decrypt ML-KEM and HQC ciphertexts
        mlkem_shared_secret = ml_kem_1024.decrypt(self.rekey_mlkem_private_key, mlkem_ciphertext)
        hqc_secret = hqc_256.decrypt(self.rekey_hqc_private_key, hqc_ciphertext)
        
        # Compute DH shared secret
        peer_dh_public_key = X25519PublicKey.from_public_bytes(peer_dh_public_key_bytes)
        dh_shared_secret = self.rekey_dh_private.exchange(peer_dh_public_key)
        
        # Combine ML-KEM and DH secrets (HQC stored separately like in initial key exchange)
        combined_shared = self.derive_combined_shared_secret(mlkem_shared_secret, dh_shared_secret)
        
        # Derive keys and store pending state
        enc_key, root_chain = self._derive_keys_and_chain(combined_shared)
        self.pending_shared_key = combined_shared
        self.pending_encryption_key = enc_key
        self.pending_send_chain_key = root_chain
        self.pending_receive_chain_key = root_chain
        self.pending_hqc_secret = hqc_secret
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        self.rekey_in_progress = True
        return {
            "type":   MessageType.REKEY,
            "action": "commit",
        }
    
    
    # File transfer methods
    def create_file_metadata_message(self, file_path: str,
                                     compress: bool = True) -> FileMetadata:
        """Create a file metadata message for file transfer initiation.
        Automatically disables compression for known incompressible types.
        """
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Decide final compression setting based on user preference and file type
        effective_compress = decide_compression(file_path, user_pref=compress)
        
        file_size: int = os.path.getsize(file_path)
        file_name: str = os.path.basename(file_path)
        
        # Calculate file hash for integrity verification (of original uncompressed file)
        file_hash = hashlib.blake2b(digest_size=32)
        with open(file_path, 'rb') as f:
            while chunk := f.read(16384):
                file_hash.update(chunk)
        
        total_chunks: int = 0
        total_processed_size: int = 0
        
        try:
            for chunk in self.chunk_file(file_path, compress=effective_compress):
                total_chunks += 1
                total_processed_size += len(chunk)
        except (OSError, IOError) as e:
            print(f"Warning: I/O error during pre-chunking, using estimation: {e}")
            total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
            total_processed_size = file_size if not effective_compress else int(file_size * 0.85)
        except ValueError as e:
            print(f"Warning: Value error during pre-chunking, using estimation: {e}")
            total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
            total_processed_size = file_size if not effective_compress else int(file_size * 0.85)
        except Exception as e:
            print(f"Warning: Unexpected error during pre-chunking, using estimation: {e}")
            total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
            total_processed_size = file_size if not effective_compress else int(file_size * 0.85)
        
        # Generate unique transfer ID. It should be unique but does not have to be cryptographically secure.
        # SHA256 just happens to be fast, and its outputs are likely unique enough for this purpose.
        transfer_id: str = hashlib.sha256(f"{file_name}{file_size}{file_hash.hexdigest()}".encode(),
                                          usedforsecurity=False).hexdigest()[:32]
        
        metadata: FileMetadata = {
            "transfer_id":    transfer_id,
            "filename":       file_name,
            "file_size":      file_size,
            "file_hash":      file_hash.hexdigest(),
            "total_chunks":   total_chunks,
            "compressed":     effective_compress,
            "processed_size": total_processed_size
        }
        
        return metadata
    
    def create_file_accept_message(self, transfer_id: str) -> bytes:
        """Create a file acceptance message."""
        message = {
            "type":        MessageType.FILE_ACCEPT,
            "transfer_id": transfer_id
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_file_reject_message(self, transfer_id: str, reason: str = "User declined") -> bytes:
        """Create a file rejection message."""
        message = {
            "type":        MessageType.FILE_REJECT,
            "transfer_id": transfer_id,
            "reason":      reason
        }
        return self.encrypt_message(json.dumps(message))
    
    def create_file_chunk_message(self, transfer_id: str, chunk_index: int, chunk_data: bytes) -> bytes:
        """Create an optimized file chunk message with direct binary encryption and DH double ratchet.
        Frame layout: [4-byte counter][12-byte nonce][32-byte eph_pub][ciphertext]
        AAD covers type, counter, nonce, and dh_public_key.
        """
        if not self.shared_key or not self.send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        # Bump global message counter (shared with text messages) for unified ratchet state
        self.message_counter += 1
        
        # Generate ephemeral X25519 key for this chunk
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
        peer_pub_bytes = self.peer_dh_public_key_bytes
        if not peer_pub_bytes:
            raise ValueError("Missing peer DH public key for file chunk encryption")
        
        # Compute DH shared secret for this chunk and mix into send chain
        dh_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
        mixed_chain_key = self._mix_dh_with_chain(self.send_chain_key, dh_shared, self.message_counter)
        
        # Derive unique message key for this chunk
        message_key = self._derive_message_key(mixed_chain_key, self.message_counter)
        
        # Ratchet the send chain key forward for the next message
        self.send_chain_key = self._ratchet_chain_key(self.send_chain_key, self.message_counter)
        
        # Create compact header
        header = {
            "type":        MessageType.FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index
        }
        header_json = json.dumps(header).encode('utf-8')
        
        # Encrypt header and chunk data in one operation
        nonce = os.urandom(12)
        
        # Create AAD including eph pub to authenticate ratchet key
        aad_data = {
            "type":          MessageType.FILE_CHUNK,
            "counter":       self.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8'),
        }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Combine header length + header + chunk data for encryption
        header_len = struct.pack('!H', len(header_json))  # 2 bytes for header length
        plaintext = header_len + header_json + chunk_data
        encryptor = DoubleEncryptor(message_key, self._hqc_secret, self.message_counter)
        ciphertext = encryptor.encrypt(nonce, plaintext, aad)
        
        # This may or may not actually remove it from memory, but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Pack: counter (4 bytes) + nonce (12 bytes) + eph_pub (32 bytes) + ciphertext
        counter_bytes = struct.pack('!I', self.message_counter)
        return counter_bytes + nonce + eph_pub_bytes + ciphertext
    
    @staticmethod
    def chunk_file(file_path: str, compress: bool = True) -> Generator[bytes, None, None]:
        """Generate file chunks for transmission one at a time.

        This is a streaming generator function that optionally compresses and yields chunks
        without loading the entire file into memory. This approach is memory-efficient
        for large files and provides a steady stream of data for network transmission.
        
        Args:
            file_path: Path to the file to chunk
            compress: Whether to compress the chunks (default: True)
        """
        
        if compress:
            # Use streaming compression
            compressor: StreamingGzipCompressor = StreamingGzipCompressor()
            pending_data: bytes = b''
            
            try:
                with open(file_path, 'rb') as original_file:
                    while True:
                        # Read a chunk from the original file
                        file_chunk = original_file.read(SEND_CHUNK_SIZE)
                        
                        if not file_chunk:
                            # End of file - finalize compression
                            final_compressed = compressor.finalise()
                            if final_compressed:
                                pending_data += final_compressed
                            break
                        
                        # Compress this chunk
                        compressed_chunk = compressor.compress_chunk(file_chunk)
                        if compressed_chunk:
                            pending_data += compressed_chunk
                        
                        # Yield complete chunks when we have enough data
                        while len(pending_data) >= SEND_CHUNK_SIZE:
                            yield pending_data[:SEND_CHUNK_SIZE]
                            pending_data = pending_data[SEND_CHUNK_SIZE:]
                    
                    # Yield any remaining data
                    if pending_data:
                        yield pending_data
            
            except (OSError, IOError) as e:
                # Clean up on error
                try:
                    compressor.finalise()
                except Exception:  # ignore finalise issues because we're already failing
                    pass  # intentional: cleanup best-effort
                raise e
            except Exception as e:
                # Clean up on unexpected error
                try:
                    compressor.finalise()
                except Exception:
                    pass  # intentional: cleanup best-effort
                raise e
        else:
            # Send uncompressed chunks directly
            with open(file_path, 'rb') as original_file:
                while True:
                    # Read a chunk from the original file
                    file_chunk = original_file.read(SEND_CHUNK_SIZE)
                    if not file_chunk:
                        break
                    yield file_chunk
    
    @staticmethod
    def process_file_metadata(message: dict[Any, Any]) -> FileMetadata:
        """Process a file metadata message."""
        try:
            return {
                "transfer_id":    message["transfer_id"],
                "filename":       message["filename"],
                "file_size":      message["file_size"],
                "file_hash":      message["file_hash"],
                "total_chunks":   message["total_chunks"],
                "compressed":     message.get("compressed", False),
                "processed_size": message.get("processed_size", message["file_size"])
            }
        except KeyError:
            raise KeyError("Invalid file metadata message")
    
    def process_file_chunk(self, encrypted_data: bytes) -> dict[Any, Any]:
        """Process an optimised file chunk message with binary format and DH double ratchet.
        Expects frame: [4-byte counter][12-byte nonce][32-byte eph_pub][ciphertext].
        """
        if not self.shared_key or not self.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        if len(encrypted_data) < 4 + 12 + 32:
            raise ValueError("Invalid chunk message format")
        
        try:
            # Extract counter, nonce, peer ephemeral, and ciphertext from the message
            counter = int(struct.unpack('!I', encrypted_data[:4])[0])
        except struct.error:
            raise ValueError("Invalid chunk message format")
        except ValueError:
            raise ValueError("Invalid counter in chunk message")
        
        nonce = encrypted_data[4:16]
        peer_eph_pub = encrypted_data[16:48]
        ciphertext = encrypted_data[48:]
        
        # Check for replay attacks or very old messages
        if counter <= self.peer_counter:
            raise ValueError("Replay attack or out-of-order message detected. Expected > " +
                             f"{self.peer_counter}, got {counter}")
        
        # Advance the chain key to the correct state for this message (symmetric ratchet)
        temp_chain_key = self.receive_chain_key
        for i in range(self.peer_counter + 1, counter):
            temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
        
        # DH mix: use our receive private key for message-phase ratchet
        if not self.msg_recv_private:
            raise ValueError("Local DH private key not initialized for file chunk ratchet")
        dh_shared = self.msg_recv_private.exchange(X25519PublicKey.from_public_bytes(peer_eph_pub))
        mixed_chain_key = self._mix_dh_with_chain(temp_chain_key, dh_shared, counter)
        
        # Derive the message key for the current message
        message_key = self._derive_message_key(mixed_chain_key, counter)
        
        # Calculate what the new chain key state WOULD be (symmetric ratchet only)
        new_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
        
        # Create AAD including eph pub to authenticate ratchet key
        aad_data = {
            "type":          MessageType.FILE_CHUNK,
            "counter":       counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(peer_eph_pub).decode('utf-8'),
        }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Decrypt the chunk payload with AAD verification
        decryptor = DoubleEncryptor(message_key, self._hqc_secret, counter)
        try:
            plaintext = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            message_key = b'\x00' * len(message_key)
            raise ValueError("File chunk decryption failed: InvalidTag")
        
        # Parse the decrypted header and extract chunk data
        if len(plaintext) < 2:
            raise ValueError("Invalid decrypted data: too short")
        
        try:
            header_len = struct.unpack('!H', plaintext[:2])[0]
        except struct.error:
            raise ValueError("Invalid decrypted data: header length")
        
        if len(plaintext) < 2 + header_len:
            raise ValueError("Invalid decrypted data: header length mismatch")
        
        header_json = plaintext[2:2 + header_len]
        chunk_data = plaintext[2 + header_len:]
        try:
            header = json.loads(header_json)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid decrypted data: header JSON decode failed")
        
        if header["type"] != MessageType.FILE_CHUNK:
            raise ValueError("Invalid message type in decrypted chunk")
        
        # Decryption successful, update the state
        self.receive_chain_key = new_chain_key
        self.peer_counter = counter
        # Store peer's latest eph public key for completeness
        self.msg_peer_base_public = peer_eph_pub
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        return {
            "transfer_id": header["transfer_id"],
            "chunk_index": header["chunk_index"],
            "chunk_data":  chunk_data
        }
    
    def add_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes, total_chunks: int) -> bool:
        """
        Add a received file chunk and return True if file is complete.
        
        Instead of storing chunks in memory, this method writes them directly to a temporary file.
        It keeps track of which chunks have been received using a set of indices.
        Uses persistent file handles to avoid the performance overhead of opening/closing files for each chunk.
        """
        
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise ValueError(f"Invalid chunk index {chunk_index} for transfer with {total_chunks} chunks")
        
        if not transfer_id.isalnum():
            raise ValueError(f"Invalid transfer_id format: {transfer_id}")
        
        if len(transfer_id) > 64:
            raise ValueError(f"transfer_id too long: {len(transfer_id)} characters")
        
        # Initialise tracking structures if this is the first chunk for this transfer
        if transfer_id not in self.received_chunks:
            self.received_chunks[transfer_id] = set()
            
            # Create temp file with secure permissions (cross-platform)
            try:
                # Create a NamedTemporaryFile with delete=False so we can manage it
                # This automatically uses secure permissions on all platforms
                temp_file = tempfile.NamedTemporaryFile(
                        mode='w+b',
                        prefix=f'transfer_{transfer_id}_',
                        suffix='.tmp',
                        delete=False  # We'll manage deletion ourselves
                )
                temp_file_path = temp_file.name
                
                # Store the path and handle
                self.temp_file_paths[transfer_id] = temp_file_path
                self.open_file_handles[transfer_id] = temp_file
            
            except OSError as e:
                raise ValueError(f"Failed to create secure temporary file: {e}")
        
        # Get the open file handle
        file_handle = self.open_file_handles[transfer_id]
        
        # Write the chunk to the temporary file at the correct position
        # Calculate the position based on chunk index and send chunk size
        # Use explicit 64-bit integer calculation to handle large files
        position = int(chunk_index) * int(SEND_CHUNK_SIZE)
        
        try:
            # Seek to the correct position with error handling for large files
            file_handle.seek(position, 0)  # 0 = SEEK_SET (absolute positioning)
            
            # Verify we're at the correct position
            actual_position = file_handle.tell()
            if actual_position != position:
                raise ValueError(f"Failed to seek to position {position}, got {actual_position}")
            
            # Write the chunk data
            bytes_written = file_handle.write(chunk_data)
            if bytes_written != len(chunk_data):
                raise ValueError(f"Failed to write complete chunk: wrote {bytes_written} of {len(chunk_data)} bytes")
            
            # Flush to ensure data is written to disk
            file_handle.flush()
        
        except (OSError, IOError) as e:
            raise ValueError(f"Failed to write chunk {chunk_index} at position {position}: {e}")
        
        # Mark this chunk as received
        self.received_chunks[transfer_id].add(chunk_index)
        
        # Check if all chunks are received
        is_complete = len(self.received_chunks[transfer_id]) == total_chunks
        
        # If transfer is complete, close the file handle
        if is_complete:
            file_handle.close()
            del self.open_file_handles[transfer_id]
        
        return is_complete
    
    def reassemble_file(self, transfer_id: str, output_path: str, expected_hash: str, compressed: bool = True) -> bool:
        """
        Finalise file transfer, optionally decompress, and verify integrity.
        """
        temp_received_path = self._close_and_get_temp_path(transfer_id)
    
        final_file_path = temp_received_path
        # Always remove the received temp file on error; also remove decompressed temp if created
        cleanup_on_error: list[str] = [temp_received_path]
    
        try:
            if compressed:
                final_file_path = self._decompress_gzip_file(temp_received_path)
                cleanup_on_error.append(final_file_path)
    
            # Verify file integrity
            if self._hash_file_hexdigest(final_file_path) != expected_hash:
                raise ValueError("File integrity check failed")
    
            # Move the final file to the output path
            self._atomic_move_or_copy(final_file_path, output_path)
    
            # Clean up the original received file if it was a compressed container
            if compressed and os.path.exists(temp_received_path):
                self._safe_remove(temp_received_path)
    
        except Exception as e:
            self._cleanup_paths(cleanup_on_error)
            if isinstance(e, (OSError, IOError, gzip.BadGzipFile)):
                raise ValueError(f"File processing failed (I/O or gzip): {e}") from e
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"File processing failed (unexpected): {e}") from e
    
        # Clean up tracking data
        del self.received_chunks[transfer_id]
        del self.temp_file_paths[transfer_id]
    
        return True
    
    def _close_and_get_temp_path(self, transfer_id: str) -> str:
        """Ensure transfer exists, close any open handle, and return the temp file path."""
        if transfer_id not in self.received_chunks or transfer_id not in self.temp_file_paths:
            raise ValueError(f"No data found for transfer {transfer_id}")
    
        if transfer_id in self.open_file_handles:
            try:
                self.open_file_handles[transfer_id].close()
            except Exception:
                pass
            del self.open_file_handles[transfer_id]
    
        temp_received_path = self.temp_file_paths[transfer_id]
        if not os.path.exists(temp_received_path):
            raise ValueError(f"Temporary file not found: {temp_received_path}")
        return temp_received_path
    
    @staticmethod
    def _decompress_gzip_file(src: str) -> str:
        """Stream-decompress `src` gzip file to `src`.decompressed and return the new path."""
        dst = src + ".decompressed"
        with open(src, 'rb') as compressed_file:
            with gzip.GzipFile(fileobj=compressed_file, mode='rb') as gzip_file:
                with open(dst, 'wb') as decompressed_file:
                    while chunk := gzip_file.read(16384):
                        decompressed_file.write(chunk)
        return dst
    
    @staticmethod
    def _hash_file_hexdigest(path: str) -> str:
        """Return BLAKE2b(32) hex digest of the file at `path`."""
        file_hash = hashlib.blake2b(digest_size=32)
        with open(path, 'rb') as f:
            while chunk := f.read(16384):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    
    @staticmethod
    def _atomic_move_or_copy(src: str, dst: str) -> None:
        """Move `src` to `dst` or copy+remove on cross-device/permission issues."""
        try:
            if os.path.exists(dst):
                os.remove(dst)
            os.rename(src, dst)
        except (OSError, PermissionError) as e:
            try:
                shutil.copy2(src, dst)
                os.remove(src)
            except (OSError, PermissionError) as copy_error:
                raise ValueError(f"Failed to move file: {e}, copy error: {copy_error}") from e
    
    @staticmethod
    def _safe_remove(path: str) -> None:
        """Remove a file path, ignoring errors."""
        try:
            os.remove(path)
        except (FileNotFoundError, PermissionError, OSError):
            pass
    
    def _cleanup_paths(self, paths: list[str]) -> None:
        """Best-effort removal of a list of paths."""
        for p in paths:
            if p and os.path.exists(p):
                self._safe_remove(p)

def create_error_message(error_text: str) -> bytes:
    """Create an error message"""
    message = {
        "type":  MessageType.ERROR,
        "error": error_text
    }
    return json.dumps(message).encode('utf-8')


def create_reset_message() -> bytes:
    """Create a key exchange reset message."""
    message = {
        "type":    MessageType.KEY_EXCHANGE_RESET,
        "message": "Key exchange reset - other client disconnected"
    }
    return json.dumps(message).encode('utf-8')


def send_message(sock: socket.socket, data: bytes) -> tuple[bool, str]:
    """Send a length-prefixed message over a socket."""
    try:
        length = struct.pack('!I', len(data))
        sock.sendall(length + data)
        return True, ""
    except socket.error as e:
        return False, str(e)


def receive_message(sock) -> bytes:
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
