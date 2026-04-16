"""
Module for managing deaddrop files and implementing a secure chat server.

This module provides functionality for managing deaddrop files, including creating, appending,
removing, and checking the existence of files. Additionally, it contains a secure chat server
implementation that facilitates end-to-end encrypted communication between two clients.
The server handles client connections, key exchange initiation, message routing, and error handling.

Classes:
    DeadDropManager: Manages deaddrop files by handling their creation, storage, retrieval,
    and deletion.

    SecureChatServer: A threaded TCP server that supports secure communication between two
    clients, including key exchange and message routing.
"""
# pylint: disable=trailing-whitespace, broad-exception-caught, too-many-instance-attributes
import base64
import binascii
import datetime
import io
import json
import os
import os.path
import secrets
import socket
import socketserver
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pqcrypto.kem import ml_kem_1024  # type: ignore

from config import ServerConfigHandler
from protocol.constants import (
    DEADDROP_MAX_CHUNKS, DEADDROP_MIN_CHUNK_SIZE, MAGIC_NUMBER_DEADDROPS, MAGIC_NUMBER_FILE_TRANSFER, MISSING_CHUNKS_LIMIT, MessageType, PROTOCOL_VERSION,
    NONCE_SIZE, DEADDROP_KDF_KEY_LENGTH, DEADDROP_SALT_SIZE, DEADDROP_PBKDF2_ITERATIONS,
    SINGLE_KEY_SIZE,
    MAGIC_SIZE, DEADDROP_NONCE_OFFSET, DEADDROP_CIPHERTEXT_OFFSET,
    DEADDROP_LENGTH_PREFIX_SIZE,
)
from protocol.create_messages import create_reset_message
from utils.network_utils import encode_send_message, receive_message, send_message

_config = ServerConfigHandler()

SERVER_VERSION: Final[int] = 9


class DeadDropManager:
    """
    Manages deaddrop files.
    
    Handles retrieving, verifying, and storing deaddrop files.
    
    Attributes:
        deaddrop_files (dict[str, str]): A dictionary mapping deaddrop names to their file path.
    """
    
    def __init__(self) -> None:
        """
        Initialise the DeadDropManager.
        """
        self.deaddrop_files: dict[str, Path] = {}
        if not _config["deaddrop_enabled"]:
            return
        location: Path = _config["deaddrop_file_location"]
        if location.is_file():
            raise FileExistsError("Deaddrop folder location already exists as a file")
        if not location.exists():
            location.mkdir(mode=0o600, parents=True)
        files = _config["deaddrop_file_location"].iterdir()
        for file in files:
            if file.suffix == ".bin":
                name = file.stem
                self.deaddrop_files[name] = file.with_suffix("")
    
    def __getitem__(self, item: str) -> Path | None:
        """
        Get the path of a deaddrop file.
        :param item: The name of the deaddrop file.
        :return: The path of the deaddrop file as a string, or None if the deaddrop file does not exist.
        """
        if not _config["deaddrop_enabled"]:
            return None
        
        if not self.check_file(item):
            return None
        
        return self.deaddrop_files[item]
    
    def append(self, name: str, data: bytes) -> None:
        """
        Append data to a deaddrop file.
        :param name: The name of the deaddrop.
        :param data: The binary data to append.
        :return: None
        :raises FileNotFoundError: If the deaddrop file does not exist.
        :raises OSError: If the file cannot be appended to.
        """
        if not _config["deaddrop_enabled"]:
            return
        
        if name in self.deaddrop_files:
            with open(self.deaddrop_files[name].with_suffix(".bin"), "ab") as f:
                f.write(data)
        else:
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
    
    def add_file(self, name: str, password: str, file_hash: str, file_key_salt: str = "") -> None:
        """
        Create a new deaddrop file with name validation
        :param name: The name of the deaddrop file.
        :param password: The password to access the file.
        :param file_hash: The hash of the file.
        :param file_key_salt: Base64-encoded salt used for file key derivation.
        :return: None
        :raises ValueError: If the name is invalid.
        :raises FileExistsError: If the name is already in use.
        :raises OSError: If the file cannot be created.
        """
        if not _config["deaddrop_enabled"]:
            return
        
        if not name.isalnum():
            raise ValueError(f"Invalid deaddrop name '{name}'")
        
        path = _config["deaddrop_file_location"] / name
        bin_path = path.with_suffix(".bin")
        if bin_path.exists():
            raise FileExistsError(f"Deaddrop file '{name}' already exists")
        
        with open(bin_path, "wb"):
            pass
        os.chmod(bin_path, 0o600)
        
        with open(path.with_suffix(".metadata"), "w") as f:
            f.write(password + "\n")
            f.write(file_hash + "\n")
            f.write(file_key_salt)
        os.chmod(path.with_suffix(".metadata"), 0o600)
        
        self.deaddrop_files[name] = path
    
    def remove_file(self, name: str) -> None:
        """
        Remove a file from the deaddrop manager.
        :param name: The name of the deaddrop to remove.
        :return: None
        :raises FileNotFoundError: If the deaddrop file does not exist.
        :raises IsADirectoryError: If the deaddrop file is a directory.
        :raises OSError: If the file cannot be removed.
        """
        if not _config["deaddrop_enabled"]:
            return
        
        if name not in self.deaddrop_files:
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        if not os.path.exists(self.deaddrop_files[name]):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        if os.path.isdir(self.deaddrop_files[name]):
            raise IsADirectoryError(f"Deaddrop file '{name}' is a directory")
        
        # Remove main file
        os.remove(self.deaddrop_files[name].with_suffix(".bin"))
        os.remove(self.deaddrop_files[name].with_suffix(".metadata"))
        del self.deaddrop_files[name]
    
    def check_file(self, name: str) -> bool:
        return name in self.deaddrop_files.keys()
    
    def get_file(self, name: str) -> io.BufferedReader:
        if not self.check_file(name):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        return open(self.deaddrop_files[name].with_suffix('.bin'), "rb")
    
    def chunk_file(self, name: str) -> Generator[bytes, None, None]:
        with self.get_file(name) as f:
            while data := f.read(1024 * 1024):
                yield data
    
    def get_password_hash(self, name: str) -> str:
        if not self.check_file(name):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        with open(self.deaddrop_files[name].with_suffix(".metadata"), "r") as f:
            lines = f.readlines()
            if len(lines) < 2:
                raise ValueError(f"Deaddrop metadata for '{name}' is corrupted")
            return lines[0].strip()
    
    def get_file_hash(self, name: str) -> str:
        if not self.check_file(name):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        with open(self.deaddrop_files[name].with_suffix(".metadata"), "r") as f:
            lines = f.readlines()
            if len(lines) < 2:
                raise ValueError(f"Deaddrop metadata for '{name}' is corrupted")
            return lines[1].strip()
    
    def get_file_key_salt(self, name: str) -> str:
        if not self.check_file(name):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        with open(self.deaddrop_files[name].with_suffix(".metadata"), "r") as f:
            lines = f.readlines()
            if len(lines) < 3:
                return ""
            return lines[2].strip()


# noinspection PyBroadException
class SecureChatServer(socketserver.ThreadingTCPServer):
    """
    Secure chat server that handles two-client connections with end-to-end encryption.
    Allows only two clients to connect simultaneously and facilitates key exchange
    and encrypted message routing between them.
    
    Logging is intentionally very minimal since this is a security and privacy focused application.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 16384) -> None:
        """Initialise the secure chat server.
        
        Args:
            host (str, optional): The hostname or IP address to bind the server to.
                Defaults to 'localhost'.
            port (int, optional): The port number to listen on. Defaults to 16384.
        """
        self.clients: dict[str, 'SecureChatRequestHandler'] = {}
        self.clients_lock: threading.Lock = threading.Lock()
        self.running: bool = False
        self.client_counter: int = 0
        self.deaddrop_manager: DeadDropManager = DeadDropManager()
        self.server_identifier: str = ""
        # Deaddrop session exclusivity control
        self.deaddrop_busy: bool = False
        self.deaddrop_owner: str = ""
        
        super().__init__((host, port), SecureChatRequestHandler)
        
        # Load or create a persistent server identifier
        try:
            self.server_identifier = self._load_or_create_identifier()
        except Exception as e:
            # Fall back to empty identifier on failure; connection will still work
            print(f"Warning: Failed to load/create server identifier: {e}")
            self.server_identifier = ""
        
        print(f"Secure chat server started on {host}:{port}")
        print(f"Server identifier: {self.server_identifier}")
        print("Waiting for clients to connect...")
    
    # --- Identifier management ---
    @staticmethod
    def _get_identifier_path() -> Path:
        """Return path to identifier.txt in the project directory."""
        current_file = Path(__file__)
        return current_file.parent / "identifier.txt"
    
    @staticmethod
    def _get_wordlist_path() -> Path:
        current_file = Path(__file__)
        return current_file.parent / _config["wordlist_file"]
    
    def _load_or_create_identifier(self) -> str:
        """Load server identifier from file or create a new 4-word identifier.

        The identifier is stored in identifier.txt next to this file. If the file does not
        exist, it is created using 4 random words from the configured wordlist.
        """
        id_path = self._get_identifier_path()
        try:
            with open(id_path, 'r', encoding='utf-8') as f:
                ident = f.read().strip()
                if ident:
                    return ident
        except FileNotFoundError:
            pass
        
        # Create a new identifier
        words: list[str]
        wl_path = self._get_wordlist_path()
        with open(wl_path, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        if not words:
            raise ValueError("wordlist.txt is empty or not found")
        
        # Doesn't need to be cryptographically be secure, but we may as well do it anyway
        selected = [secrets.choice(words) for _ in range(4)]
        identifier = " ".join(selected)
        
        # Write atomically: write to temp then replace
        with open(id_path, 'w', encoding='utf-8') as f:
            f.write(identifier)
        return identifier
    
    def add_client(self, client_handler: 'SecureChatRequestHandler') -> bool:
        """Add a client to the server. Returns True if added, False if server rejects the client."""
        with self.clients_lock:
            # Enforce normal 2-client limit unless a deaddrop session is active
            if self.deaddrop_busy:
                # Only allow the deaddrop owner to remain connected; reject new clients
                if len(self.clients) >= 1:
                    return False
            if len(self.clients) >= 2:
                return False
            
            self.client_counter += 1
            client_id = f"client_{self.client_counter}"
            client_handler.client_id = client_id
            self.clients[client_id] = client_handler
            
            print(f"[{datetime.datetime.now().strftime('%d.%m.%Y, %H:%M:%S')}] Client {client_id} " +
                  f"connected from {client_handler.client_address}")
        
        # If we now have exactly 2 clients, start key exchange
        if len(self.clients) == 2:
            print("Two clients connected. Starting key exchange...")
            self.initiate_key_exchange()
        
        return True
    
    def remove_client(self, client_id: str) -> None:
        """Remove a client from the server."""
        with self.clients_lock:
            if client_id in self.clients:
                del self.clients[client_id]
                
                # Notify remaining client to reset key exchange
                if self.clients:
                    remaining_client = list(self.clients.values())[0]
                    # Send key exchange reset message
                    reset_msg = create_reset_message()
                    send_message(remaining_client.request, reset_msg)
                    remaining_client.key_exchange_complete = False
                else:
                    self.client_counter = 0
    
    def initiate_key_exchange(self) -> None:
        """Initiate the key exchange process between two connected clients."""
        with self.clients_lock:
            if len(self.clients) != 2:
                return
            
            client_handlers = list(self.clients.values())
            client1 = client_handlers[0]
            
            # Tell first client to start key exchange
            initiate_message = {"type": MessageType.INITIATE_KEY_EXCHANGE}
            message_data = json.dumps(initiate_message).encode('utf-8')
            send_message(client1.request, message_data)
    
    def route_message(self, sender_id: str, message_data: bytes) -> bool:
        """Route encrypted message from sender to the other client."""
        attempts: list[str | None] = []
        with self.clients_lock:
            for client_id, client_handler in self.clients.items():
                if client_id != sender_id and client_handler.is_connected():
                    attempts.append(send_message(client_handler.request, message_data))
        
        all_sent = True
        for success in attempts:
            if success is not None:
                print(f"Failed to route message to {sender_id}: {success}")
                all_sent = False
        return all_sent
    
    def broadcast_error(self, error_text: str) -> None:
        """Broadcast an error message to all connected clients."""
        error_msg = json.dumps({"type": MessageType.ERROR, "error": error_text}).encode('utf-8')
        with self.clients_lock:
            for client_handler in self.clients.values():
                send_message(client_handler.request, error_msg)
    
    def start_server(self) -> None:
        """Start the server and serve forever."""
        self.running = True
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("Server interrupted by user")
        finally:
            self.stop_server()
    
    def stop_server(self) -> None:
        """Stop the server and clean up."""
        self.running = False
        for client_handler in list(self.clients.values()):
            client_handler.disconnect("Server shutting down")
        self.shutdown()
        self.server_close()


# noinspection PyBroadException
class SecureChatRequestHandler(socketserver.BaseRequestHandler):
    """Handles individual client connections."""
    server: SecureChatServer
    
    def __init__(self, request: socket.socket | tuple[bytes, socket.socket], client_address: str,
                 server: SecureChatServer,
                 ) -> None:
        self.client_id: str = ""
        self.connected: bool = True
        self.sender_lock: threading.Lock = threading.Lock()
        self.key_exchange_complete: bool = False
        self.announced_disconnect: bool = False
        self.upload_accepted: bool = False
        self.pending_deaddrop_upload_name: str = ""
        self.pending_deaddrop_expected_size: int = 0
        self.pending_deaddrop_file_hash: str = ""
        self.pending_deaddrop_received_size: int = 0
        self.pending_deaddrop_received_chunks: set[int] = set()
        self.pending_deaddrop_redownload_requested: bool = False
        self.pending_deaddrop_chunk_size: int = 0
        self.pending_deaddrop_max_index: int = -1
        self.correct_download_hash: bytes = b"\x00" * SINGLE_KEY_SIZE
        self.pending_deaddrop_download: str = ""
        self.pending_download_accepted: bool = False
        self.ml_kem_sk: bytes = b""
        self.shared_secret: bytes = b""
        
        # Deaddrop rate limiting
        self._last_deaddrop_check_time: float = 0.0
        self._last_deaddrop_download_time: float = 0.0
        
        # Keepalive tracking
        self.last_keepalive_time: float = time.time()
        self.keepalive_failures: int = 0
        self.waiting_for_keepalive_response: bool = False
        self.keepalive_thread: threading.Thread | None = None
        self.unexpected_message_count: int = 0
        self._ke_verification_count: int = 0
        
        super().__init__(request, client_address, server)
    
    def setup(self) -> None:
        """Called before handle() to perform initialization."""
        # Try to add this client to the server
        if not self.server.add_client(self):
            # Server is full, send rejection message and disconnect
            try:
                rejection_message = {
                    "type": MessageType.SERVER_FULL,
                }
                message_data = json.dumps(rejection_message).encode('utf-8')
                send_message(self.request, message_data)
            except (OSError, ConnectionError):
                # Ignore: client can't receive rejection or already disconnected
                pass
            return
        
        super().setup()
        
        # Send server version information to the newly connected client
        self.send_server_version_info()
    
    def handle(self) -> None:
        try:
            self._handle()
        except ConnectionResetError:
            self.disconnect("Connection reset", notify=False)
        except ConnectionError:
            self.disconnect("Unexpected disconnect", notify=False)
        finally:
            if not self.announced_disconnect:
                self.disconnect()
    
    def _handle(self) -> None:
        """Main client handling loop."""
        # If client wasn't added (server full), don't process
        if self.client_id is None:
            return
        
        self.start_keepalive()
        
        while self.connected:
            try:
                message_data = receive_message(self.request)
            except OSError as e:
                self.disconnect(f"Error receiving message: {e}", notify=False)
                break
            
            try:
                message = json.loads(message_data)
                message_type = message.get("type")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.handle_maybe_bin_data(message_data)
                continue
            
            if message_type == MessageType.KEEP_ALIVE_RESPONSE:
                self.handle_keepalive_response()
                continue
            
            if message_type == MessageType.KEY_VERIFICATION:
                self.route_verification_message(message_data)
                continue
            
            if message_type == MessageType.CLIENT_DISCONNECT:
                self.announced_disconnect = True
                self.disconnect("Client announced disconnect", notify=False)
                break
            
            # Deaddrop handshake (plaintext)
            if message_type == MessageType.DEADDROP_START:
                self.handle_deaddrop_start()
                continue
            if message_type == MessageType.DEADDROP_KE_RESPONSE:
                self.handle_deaddrop_ke_response(message)
                continue
            
            if message_type == MessageType.DEADDROP_MESSAGE:
                self.handle_deaddrop_message(message)
                continue
            
            if not self.key_exchange_complete:
                if message_type in (MessageType.KE_DSA_RANDOM, MessageType.KE_MLKEM_PUBKEY,
                                    MessageType.KE_MLKEM_CT_KEYS, MessageType.KE_X25519_HQC_CT,
                                    MessageType.KE_VERIFICATION,
                                    MessageType.KEY_EXCHANGE_RESET, MessageType.INITIATE_KEY_EXCHANGE):
                    self.handle_key_exchange(message, message_data)
                    continue
                
                # If we get here, it's an unexpected message during key exchange
                self.handle_unexpected_message("unexpected message during key exchange")
                continue
            
            self.server.route_message(self.client_id, message_data)
    
    def handle_key_exchange(self, message: dict[Any, Any], message_data: bytes) -> None:
        """Handle key exchange messages by routing them to the other client."""
        message_type = message.get("type")
        # Route the message to the other client
        other_client = self.get_other_client()
        if other_client:
            send_message(other_client.request, message_data)
            if message_type == MessageType.KE_VERIFICATION:
                # Track verification messages; both sides must send one
                self._ke_verification_count = getattr(self, '_ke_verification_count', 0) + 1
                other_client._ke_verification_count = getattr(other_client, '_ke_verification_count', 0)
                if self._ke_verification_count >= 1 and other_client._ke_verification_count >= 1:
                    self.key_exchange_complete = True
                    other_client.key_exchange_complete = True
        else:
            self.server.broadcast_error("Key exchange failed - no other client")
    
    def handle_maybe_bin_data(self, message_data: bytes) -> None:
        """
        Handle data that may be raw binary like deaddrops or file transfers
        """
        magic = message_data[:MAGIC_SIZE]
        if magic == MAGIC_NUMBER_FILE_TRANSFER:
            self.server.route_message(self.client_id, message_data)
            return
        
        if magic == MAGIC_NUMBER_DEADDROPS:
            decrypted = self.decrypt_deaddrop_data(
                    message_data[DEADDROP_NONCE_OFFSET:DEADDROP_CIPHERTEXT_OFFSET],
                    message_data[DEADDROP_CIPHERTEXT_OFFSET:],
            )
            
            self.handle_deaddrop_data(
                    int.from_bytes(decrypted[0:DEADDROP_LENGTH_PREFIX_SIZE], byteorder='big'),
                    decrypted[DEADDROP_LENGTH_PREFIX_SIZE:],
            )
            return
        
        self.handle_unexpected_message("unexpected binary message")
    
    def decrypt_deaddrop_data(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt incoming binary deaddrop data
        :param nonce: The chunk's nonce
        :param ciphertext: The ciphertext of the chunk
        :return: The decrypted chunk
        :raises InvalidTag: If decryption fails.
        :raises ValueError: If there is no shared key.
        """
        if not self.shared_secret:
            raise ValueError("No shared secret for deaddrop decryption")
        decryptor = ChaCha20Poly1305(self.shared_secret)
        data = decryptor.decrypt(nonce, ciphertext, associated_data=nonce)
        return data
    
    def handle_deaddrop_message(self, message: dict[Any, Any]) -> None:
        """Handle encrypted deaddrop messages."""
        try:
            nonce_b64 = str(message["nonce"])
            ct_b64 = str(message["ciphertext"])
            nonce = base64.b64decode(nonce_b64, validate=True)
            ciphertext = base64.b64decode(ct_b64, validate=True)
        except KeyError:
            self.handle_unexpected_message("deaddrop message missing fields")
            return
        except binascii.Error:
            self.handle_unexpected_message("deaddrop message invalid b64")
            return
        
        if not self.shared_secret:
            self.handle_unexpected_message("deaddrop message before handshake")
            return
        
        try:
            decryptor = ChaCha20Poly1305(self.shared_secret)
            aad_raw = json.dumps({
                "type":  MessageType.DEADDROP_MESSAGE,
                "nonce": nonce_b64,
            }).encode("utf-8")
            inner_bytes = decryptor.decrypt(nonce, ciphertext, aad_raw)
        except Exception:
            self.handle_unexpected_message("failed to decrypt deaddrop message")
            return
        
        # Try parse as JSON; for raw binary chunks we wrap inside json anyhow
        try:
            inner = json.loads(inner_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.handle_unexpected_message("invalid inner deaddrop message")
            return
        
        inner_type = inner.get("type", MessageType.NONE)
        if inner_type == MessageType.DEADDROP_CHECK:
            self.handle_deaddrop_check(inner)
            return
        if inner_type == MessageType.DEADDROP_UPLOAD:
            self.handle_deaddrop_upload(inner)
            return
        if inner_type == MessageType.DEADDROP_DOWNLOAD:
            self.handle_deaddrop_download(inner)
            return
        if inner_type == MessageType.DEADDROP_PROVE:
            self.handle_deaddrop_prove(inner)
            return
        if inner_type == MessageType.DEADDROP_ACCEPT:
            self.handle_deaddrop_accept()
            return
        if inner_type == MessageType.DEADDROP_COMPLETE:
            self.handle_deaddrop_complete()
            return
        
        # Unknown inner deaddrop msg
        self.handle_unexpected_message("unknown deaddrop inner message type")
        return
    
    def route_verification_message(self, message_data: bytes) -> None:
        """Route key verification messages between clients."""
        if not self.key_exchange_complete:
            self.handle_unexpected_message("verification before key exchange")
            return
        
        other_client = self.get_other_client()
        if other_client:
            send_message(other_client.request, message_data)
        
        else:
            self.server.broadcast_error("Verification failed - no other client")
    
    def get_other_client(self) -> "SecureChatRequestHandler | None":
        """Get the other connected client."""
        with self.server.clients_lock:
            for client_id, client_handler in self.server.clients.items():
                if client_id != self.client_id:
                    return client_handler
        return None
    
    def is_connected(self) -> bool:
        """Check if the client is still connected."""
        return self.connected
    
    def start_keepalive(self) -> None:
        """Start the keepalive thread."""
        if self.keepalive_thread is None:
            self.keepalive_thread = threading.Thread(target=self.keepalive_loop)
            self.keepalive_thread.daemon = True
            self.keepalive_thread.start()
    
    def keepalive_loop(self) -> None:
        """Keepalive loop to monitor client connection."""
        while self.connected:
            try:
                time.sleep(30)  # Send keepalive every 30 ish seconds
                
                if not self.connected:
                    break
                
                if self.server.deaddrop_busy:
                    continue
                
                if self.waiting_for_keepalive_response:
                    self.keepalive_failures += 1
                    if self.keepalive_failures >= 3:
                        self.disconnect("Keepalive timeout: no response after 3 attempts")
                        return
                
                self.send_keepalive()
            except (OSError, ConnectionError) as e:
                print(f"Keepalive socket error for {self.client_id}: {e}")
                break
            except Exception as e:
                print(f"Keepalive error for {self.client_id} (unexpected): {e}")
                break
    
    def send_keepalive(self) -> None:
        """Send a keepalive message to the client."""
        try:
            keepalive_message = {
                "type":      MessageType.KEEP_ALIVE,
                "timestamp": time.time(),
            }
            message_data = json.dumps(keepalive_message).encode('utf-8')
            with self.sender_lock:
                send_message(self.request, message_data)
            self.waiting_for_keepalive_response = True
            self.last_keepalive_time = time.time()
        except (OSError, ConnectionError) as e:
            print(f"Failed to send keepalive to {self.client_id} (socket): {e}")
            self.disconnect(f"Keepalive send failed: {e}")
        except Exception as e:
            print(f"Failed to send keepalive to {self.client_id} (unexpected): {e}")
            self.disconnect(f"Keepalive send failed: {e}")
    
    def handle_keepalive_response(self) -> None:
        """Handle keepalive response from client."""
        
        if self.waiting_for_keepalive_response:
            self.waiting_for_keepalive_response = False
            self.keepalive_failures = 0
            return
        
        self.handle_unexpected_message("keepalive response without request")
    
    def send_server_version_info(self) -> None:
        """Send protocol version information to the client."""
        try:
            version_message = {
                "type":             MessageType.SERVER_VERSION_INFO,
                "protocol_version": PROTOCOL_VERSION,
                "identifier":       self.server.server_identifier,
            }
            message_data = json.dumps(version_message).encode('utf-8')
            with self.sender_lock:
                send_message(self.request, message_data)
        except (OSError, ConnectionError) as e:
            print(f"Error sending protocol version info to {self.client_id} (socket): {e}")
        except Exception as e:
            print(f"Error sending protocol version info to {self.client_id} (unexpected): {e}")
    
    def disconnect(self, reason: str = "", notify: bool = True) -> None:
        """
        Disconnect the client and clean up.
        
        If a reason is provided, the server will attempt to send a SERVER_DISCONNECT
        control message with the reason before closing the connection.
        """
        if self.connected:
            print(f"[{datetime.datetime.now().strftime(format="%d.%m.%Y, %H:%M:%S")}] Disconnecting", self.client_id,
                  "Reason:", reason if reason else "No reason provided")
            self.connected = False
            
            # End any active deaddrop session and cleanup exclusivity
            self._end_deaddrop_session()
            
            # Attempt to notify client about server-initiated disconnect
            if notify:
                disconnect_message = {
                    "type":   MessageType.SERVER_DISCONNECT,
                    "reason": reason if reason else "Server disconnect",
                }
                encode_send_message(self.request, disconnect_message)
            
            if self.client_id:
                self.server.remove_client(self.client_id)
            try:
                self.request.close()
            except (OSError, socket.error):
                # ignore: closing a dead socket
                pass
    
    def handle_unexpected_message(self, extra_info: str = "") -> None:
        """Handle unexpected messages from the client."""
        self.unexpected_message_count += 1
        if self.unexpected_message_count >= _config["max_unexpected_msgs"]:
            self.disconnect("Too many unexpected messages: " + extra_info)
    
    def handle_deaddrop_start(self) -> None:
        """Handle deaddrop start message from client."""
        if not _config["deaddrop_enabled"]:
            deny_msg = {
                "type":      MessageType.DEADDROP_START,
                "supported": False,
            }
            with self.sender_lock:
                send_message(self.request, json.dumps(deny_msg).encode('utf-8'))
            return
        
        if self.get_other_client():
            with self.sender_lock:
                send_message(self.request, json.dumps({
                    "type":   MessageType.DEADDROP_DENY,
                    "reason": "Cannot start deaddrop while another client is connected.",
                }).encode('utf-8'))
            return
        
        # Mark server as busy with deaddrop until session ends
        with self.server.clients_lock:
            self.server.deaddrop_busy = True
            self.server.deaddrop_owner = self.client_id
        
        public_key, self.ml_kem_sk = ml_kem_1024.generate_keypair()
        msg = {
            "type":          MessageType.DEADDROP_START,
            "supported":     True,
            "max_file_size": _config["deaddrop_max_size"],
            "mlkem_public":  base64.b64encode(public_key).decode('utf-8'),
        }
        with self.sender_lock:
            send_message(self.request, json.dumps(msg).encode('utf-8'))
        
        print(f"Deaddrop session started by {self.client_id}")
    
    def handle_deaddrop_ke_response(self, message_data: dict[str, Any]) -> None:
        """Handle deaddrop key exchange response message from client."""
        try:
            client_mlkem_ct = base64.b64decode(message_data["mlkem_ct"], validate=True)
        except KeyError:
            with self.sender_lock:
                send_message(self.request, json.dumps({
                    "type":   MessageType.DEADDROP_DENY,
                    "reason": "Missing mlkem_ct in deaddrop ke response message",
                }).encode('utf-8'))
            return
        except binascii.Error:
            with self.sender_lock:
                send_message(self.request, json.dumps({
                    "type":   MessageType.DEADDROP_DENY,
                    "reason": "Invalid mlkem_ct in deaddrop ke response message",
                }).encode('utf-8'))
            return
        
        shared_secret = ml_kem_1024.decrypt(self.ml_kem_sk, client_mlkem_ct)
        self.shared_secret = ConcatKDFHash(
                algorithm=hashes.SHA3_512(),
                length=DEADDROP_KDF_KEY_LENGTH,
                otherinfo=b"deaddrop_key_exchange" + self.server.server_identifier.encode('utf-8'),
        ).derive(shared_secret)
        
        print(f"Deaddrop key exchange completed with {self.client_id}")
    
    def handle_deaddrop_check(self, message_data: dict[Any, Any]) -> None:
        """Handle deaddrop check message from client."""
        now = time.time()
        should_limit = now - self._last_deaddrop_check_time < 1.0
        self._last_deaddrop_check_time = now
        try:
            name = message_data["name"]
        except KeyError:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Missing name in deaddrop check message",
            }))
            return
        
        found = self.server.deaddrop_manager.check_file(name)
        if should_limit:
            msg = {
                "type":   MessageType.DEADDROP_CHECK_RESPONSE,
                "exists": False,
            }
            self.send_deaddrop_message(json.dumps(msg))
            return
        
        if found:
            msg = {
                "type":   MessageType.DEADDROP_CHECK_RESPONSE,
                "exists": True,
            }
            self.send_deaddrop_message(json.dumps(msg))
        else:
            msg = {
                "type":   MessageType.DEADDROP_CHECK_RESPONSE,
                "exists": False,
            }
            self.send_deaddrop_message(json.dumps(msg))
        
        print(f"Deaddrop check for {name} by {self.client_id} completed")
    
    def handle_deaddrop_download(self, message: dict[Any, Any]) -> None:
        now = time.time()
        should_limit = now - self._last_deaddrop_download_time < 5.0
        self._last_deaddrop_download_time = now
        if should_limit:
            download_salt = os.urandom(DEADDROP_SALT_SIZE)
            msg = {
                "type": MessageType.DEADDROP_PROVE,
                "salt": base64.b64encode(download_salt).decode('utf-8'),
            }
            self.send_deaddrop_message(json.dumps(msg).encode('utf-8'))
            return
        if not _config["deaddrop_enabled"]:
            self.send_deaddrop_message(json.dumps({"type": MessageType.DEADDROP_DENY}).encode('utf-8'))
            return
        
        try:
            name = str(message["name"])
        except KeyError:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Missing name in deaddrop download message",
            }))
            return
        except binascii.Error:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Invalid name field",
            }))
            return
        
        if not self.server.deaddrop_manager.check_file(name):
            not_found_msg = {
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Deaddrop file not found",
            }
            self.send_deaddrop_message(json.dumps(not_found_msg).encode('utf-8'))
            return
        
        download_salt = os.urandom(DEADDROP_SALT_SIZE)
        msg = {
            "type": MessageType.DEADDROP_PROVE,
            "salt": base64.b64encode(download_salt).decode('utf-8'),
        }
        self.send_deaddrop_message(json.dumps(msg).encode('utf-8'))
        
        og_hash = self.server.deaddrop_manager.get_password_hash(name).encode('utf-8')
        
        pbk = PBKDF2HMAC(
                algorithm=hashes.SHA3_512(),
                length=DEADDROP_KDF_KEY_LENGTH,
                salt=download_salt,
                iterations=DEADDROP_PBKDF2_ITERATIONS,
        )
        self.pending_deaddrop_download = name
        
        self.correct_download_hash = pbk.derive(og_hash)
    
    def handle_deaddrop_prove(self, message: dict[Any, Any]) -> None:
        try:
            client_hash = base64.b64decode(message["hash"], validate=True)
        except KeyError:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Missing hash in deaddrop prove message",
            }))
            self.pending_deaddrop_download = ""
            self._end_deaddrop_session()
            return
        except binascii.Error:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Invalid hash in deaddrop prove message",
            }))
            self.pending_deaddrop_download = ""
            self._end_deaddrop_session()
            return
        
        expected_len = len(self.correct_download_hash)
        padded_client_hash = (client_hash + bytes(expected_len))[:expected_len]
        correct = bytes_eq(padded_client_hash, self.correct_download_hash)
        non_empty = not bytes_eq(padded_client_hash, bytes(expected_len))
        if not (correct & non_empty):
            deny_msg = {
                "type": MessageType.DEADDROP_DENY,
            }
            self.send_deaddrop_message(json.dumps(deny_msg).encode('utf-8'))
            self.pending_deaddrop_download = ""
            return
        
        file_key_salt = self.server.deaddrop_manager.get_file_key_salt(self.pending_deaddrop_download)
        accept_msg = {
            "type":          MessageType.DEADDROP_ACCEPT,
            "file_hash":     self.server.deaddrop_manager.get_file_hash(self.pending_deaddrop_download),
            "file_key_salt": file_key_salt,
        }
        self.send_deaddrop_message(json.dumps(accept_msg).encode('utf-8'))
        self.pending_download_accepted = True
        print(f"Deaddrop download accepted for {self.pending_deaddrop_download} by {self.client_id}")
    
    def handle_deaddrop_accept(self) -> None:
        if not self.pending_download_accepted:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Deaddrop download not accepted yet",
            }))
            # Reset values just in case
            self.pending_download_accepted = False
            self.pending_deaddrop_download = ""
            return
        
        # Stream the requested deaddrop file to the client as DEADDROP_DATA
        # messages over the encrypted deaddrop channel.
        try:
            chunks = self.server.deaddrop_manager.chunk_file(self.pending_deaddrop_download)
        except Exception:
            # If we cannot open/chunk the file, abort the download cleanly.
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Internal server error",
            }))
            self.pending_download_accepted = False
            self.pending_deaddrop_download = ""
            self._end_deaddrop_session()
            return
        
        for chunk_index, chunk in enumerate(chunks):
            index_bytes = chunk_index.to_bytes(4, byteorder="little")
            self.send_raw_deaddrop_data(index_bytes + chunk)
        
        # Inform the client that all chunks have been transmitted.
        self.send_deaddrop_message({
            "type": MessageType.DEADDROP_COMPLETE,
        })
        
        # Reset download state and end the deaddrop session.
        self.pending_download_accepted = False
        self.pending_deaddrop_download = ""
        self._end_deaddrop_session()
    
    def handle_deaddrop_upload(self, message: dict[Any, Any]) -> None:
        try:
            name = str(message["name"])
            file_size = int(message["file_size"])
            file_hash = str(message["file_hash"])
            password_hash = str(message["file_password_hash"])
        except KeyError:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Missing field in deaddrop upload message",
            }))
            return
        except binascii.Error:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Invalid name or file hash",
            }))
            return
        except (ValueError, TypeError):
            self.handle_unexpected_message("deaddrop upload message with invalid values")
            return
        
        if file_size > _config["deaddrop_max_size"]:
            too_large_msg = {
                "type":   MessageType.DEADDROP_DENY,
                "reason": "File size exceeds maximum allowed size",
            }
            self.send_deaddrop_message(json.dumps(too_large_msg).encode('utf-8'))
            return
        
        try:
            file_key_salt = str(message.get("file_key_salt", ""))
            self.server.deaddrop_manager.add_file(name, password_hash, file_hash, file_key_salt)
        except Exception:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "Internal server error",
            }))
            return
        
        # Initialise upload session state
        self.upload_accepted = True
        self.pending_deaddrop_upload_name = name
        self.pending_deaddrop_expected_size = file_size
        self.pending_deaddrop_file_hash = file_hash
        self.pending_deaddrop_received_size = 0
        self.pending_deaddrop_received_chunks.clear()
        self.pending_deaddrop_redownload_requested = False
        self.pending_deaddrop_chunk_size = 0
        self.pending_deaddrop_max_index = -1
        self.send_deaddrop_message(json.dumps({"type": MessageType.DEADDROP_ACCEPT}).encode('utf-8'))
    
    def handle_deaddrop_data(self, chunk_index: int, chunk_data: bytes) -> None:
        """
        Writes decrypted deaddrop chunk data to the pending upload file.
        :param chunk_index: The index of the chunk being received.
        :param chunk_data: The data of the chunk
        :return: None
        """
        if not self.upload_accepted or not self.pending_deaddrop_upload_name:
            self.send_deaddrop_message(json.dumps({
                "type":   MessageType.DEADDROP_DENY,
                "reason": "No active deaddrop upload",
            }))
            return
        
        # Infer chunk size from first chunk
        if self.pending_deaddrop_chunk_size == 0 and len(chunk_data) > 0:
            self.pending_deaddrop_chunk_size = len(chunk_data)
        
        if self.pending_deaddrop_chunk_size <= DEADDROP_MIN_CHUNK_SIZE:
            self._fail_current_upload(f"Deaddrop chunk size too small. Min: {DEADDROP_MIN_CHUNK_SIZE} bytes")
            return
        
        # Track max index
        if chunk_index > self.pending_deaddrop_max_index:
            self.pending_deaddrop_max_index = chunk_index
        
        # Enforce maximum size (hard cap)
        if self.pending_deaddrop_received_size + len(chunk_data) > _config["deaddrop_max_size"]:
            self._fail_current_upload(f"Upload exceeded maximum allowed size")
            return
        
        if chunk_index not in self.pending_deaddrop_received_chunks:
            try:
                self.server.deaddrop_manager.append(self.pending_deaddrop_upload_name, chunk_data)
                self.pending_deaddrop_received_chunks.add(chunk_index)
                self.pending_deaddrop_received_size += len(chunk_data)
            except Exception:
                self._fail_current_upload(f"Internal server error")
                return
        
        if len(self.pending_deaddrop_received_chunks) > DEADDROP_MAX_CHUNKS:
            self._fail_current_upload("Max chunk limit exceeded")
            return
    
    def _find_missing_chunks(self, expected_last_index: int) -> list[int] | None:
        missing = []
        for i in range(expected_last_index + 1):
            if i not in self.pending_deaddrop_received_chunks:
                missing.append(i)
                if len(missing) >= MISSING_CHUNKS_LIMIT:
                    return None
        return missing
    
    def handle_deaddrop_complete(self) -> None:
        if not self.upload_accepted or not self.pending_deaddrop_upload_name:
            self._fail_current_upload(f"No active deaddrop upload to complete")
            return
        
        if self.pending_deaddrop_chunk_size <= 0:
            # Cannot verify without at least one chunk; fail
            self._fail_current_upload("No data received")
            return
        
        expected_last_index = (self.pending_deaddrop_expected_size - 1) // self.pending_deaddrop_chunk_size
        missing = self._find_missing_chunks(expected_last_index)
        
        if missing is None:
            self._fail_current_upload("Too many missing chunks")
            return
        
        if missing and not self.pending_deaddrop_redownload_requested:
            self.pending_deaddrop_redownload_requested = True
            self.send_deaddrop_message({
                "type":          MessageType.DEADDROP_REDOWNLOAD,
                "chunk_indexes": missing,
            })
            return
        
        if missing:
            # Still missing after a redownload cycle
            self._fail_current_upload("Missing chunks after redownload")
            return
        
        self.send_deaddrop_message({
            "type": MessageType.DEADDROP_COMPLETE,
        })
        
        self._end_deaddrop_session()
    
    def _fail_current_upload(self, reason: str) -> None:
        self.send_deaddrop_message({
            "type":   MessageType.DEADDROP_DENY,
            "reason": reason,
        })
        # Cleanup file and metadata
        try:
            if self.pending_deaddrop_upload_name:
                self.server.deaddrop_manager.remove_file(self.pending_deaddrop_upload_name)
        except Exception:
            pass
        self._end_deaddrop_session()
    
    def _end_deaddrop_session(self) -> None:
        # Reset handler state
        self.upload_accepted = False
        self.pending_deaddrop_upload_name = ""
        self.pending_deaddrop_expected_size = 0
        self.pending_deaddrop_file_hash = ""
        self.pending_deaddrop_received_size = 0
        self.pending_deaddrop_received_chunks.clear()
        self.pending_deaddrop_redownload_requested = False
        self.pending_deaddrop_chunk_size = 0
        self.pending_deaddrop_max_index = -1
        self.correct_download_hash = b"\x00" * SINGLE_KEY_SIZE
        # Release server busy flag
        with self.server.clients_lock:
            if self.server.deaddrop_owner == self.client_id:
                self.server.deaddrop_busy = False
                self.server.deaddrop_owner = ""
    
    def send_deaddrop_message(self, message: bytes | str | dict[Any, Any]) -> None:
        """Send a deaddrop message to the client."""
        msg: bytes
        if isinstance(message, dict):
            msg = json.dumps(message).encode('utf-8')
        elif isinstance(message, str):
            msg = message.encode('utf-8')
        else:
            msg = message
        
        encryptor = ChaCha20Poly1305(self.shared_secret)
        nonce = os.urandom(NONCE_SIZE)
        aad = {
            "type":  MessageType.DEADDROP_MESSAGE,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
        }
        aad_raw = json.dumps(aad).encode("utf-8")
        to_send = {
            "type":       MessageType.DEADDROP_MESSAGE,
            "nonce":      base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(encryptor.encrypt(nonce, msg, aad_raw)).decode('utf-8'),
        }
        with self.sender_lock:
            send_message(self.request, json.dumps(to_send).encode('utf-8'))
    
    def send_raw_deaddrop_data(self, message: bytes) -> None:
        """Send a raw deaddrop data message to the client."""
        encryptor = ChaCha20Poly1305(self.shared_secret)
        nonce = os.urandom(NONCE_SIZE)
        encrypted = encryptor.encrypt(nonce, message, nonce)
        to_send = MAGIC_NUMBER_DEADDROPS + nonce + encrypted
        with self.sender_lock:
            send_message(self.request, to_send)


def main() -> None:
    """Main entry point to start the secure chat server."""
    try:
        server = SecureChatServer()
        server.start_server()
    except (OSError, ConnectionError) as e:
        print(f"Server socket error: {e}")
    except KeyboardInterrupt:
        print("Server interrupted by user")
    except Exception as e:
        print(f"Server error (unexpected): {e}")


if __name__ == "__main__":
    main()
