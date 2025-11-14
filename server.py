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
import base64
import binascii
import io
import os.path
# pylint: disable=trailing-whitespace, broad-exception-caught, bare-except, too-many-instance-attributes
import socket
import socketserver
import threading
import json
import time
from collections.abc import Generator
from typing import Final, Any
import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pqcrypto.kem import ml_kem_1024 # type: ignore

from shared import send_message, receive_message, create_reset_message, MessageType, PROTOCOL_VERSION
import config_manager
import configs

assert config_manager  # Remove unused import warning

SERVER_VERSION: Final[int] = 7


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
        self.deaddrop_files: dict[str, str] = {}
        if not configs.DEADDROP_ENABLED:
            return
        files = os.listdir(configs.DEADDROP_FILE_LOCATION)
        for file in files:
            if file.endswith(".bin"):
                name = os.path.basename(file)[:-4]
                self.deaddrop_files[name] = file
    
    def __getitem__(self, item: str) -> str | None:
        """
        Get the path of a deaddrop file.
        :param item: The name of the deaddrop file.
        :return: The path of the deaddrop file as a string, or None if the deaddrop file does not exist.
        """
        if not configs.DEADDROP_ENABLED:
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
        if not configs.DEADDROP_ENABLED:
            return
        
        if name in self.deaddrop_files:
            with open(self.deaddrop_files[name], "ab") as f:
                f.write(data)
        else:
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
    
    def add_file(self, name: str, password: str, file_hash: str) -> None:
        """
        Create a new deaddrop file with name validation
        :param name: The name of the deaddrop file.
        :param password: The password to access the file.
        :param file_hash: The hash of the file.
        :return: None
        :raises ValueError: If the name is invalid.
        :raises FileExistsError: If the name is already in use.
        :raises OSError: If the file cannot be created.
        """
        if not configs.DEADDROP_ENABLED:
            return
        
        if not name.isalnum():
            raise ValueError(f"Invalid deaddrop name '{name}'")
        
        path = os.path.join(configs.DEADDROP_FILE_LOCATION, name + ".bin")
        if os.path.exists(path):
            raise FileExistsError(f"Deaddrop file '{name}' already exists")
        
        with open(path, "wb"):
            pass
        
        with open(path + ".metadata", "w") as f:
            f.write(password + "\n")
            f.write(file_hash)
        
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
        if not configs.DEADDROP_ENABLED:
            return
        
        if not name in self.deaddrop_files:
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        if not os.path.exists(self.deaddrop_files[name]):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        if os.path.isdir(self.deaddrop_files[name]):
            raise IsADirectoryError(f"Deaddrop file '{name}' is a directory")
        
        os.remove(self.deaddrop_files[name])
        del self.deaddrop_files[name]
    
    def check_file(self, name: str) -> bool:
        return name in self.deaddrop_files.keys()
    
    def get_file(self, name: str) -> io.BufferedReader:
        if not self.check_file(name):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")
        
        return open(self.deaddrop_files[name], "rb")
    
    def chunk_file(self, name: str) -> Generator[bytes, None, None]:
        with self.get_file(name) as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                yield data

    def get_password_hash(self, name: str) -> str:
        if not self.check_file(name):
            raise FileNotFoundError(f"Deaddrop file '{name}' does not exist")

        with open(self.deaddrop_files[name] + ".metadata", "r") as f:
            lines = f.readlines()
            if len(lines) < 2:
                raise ValueError(f"Deaddrop metadata for '{name}' is corrupted")
            return lines[0].strip()
    

# noinspection PyBroadException
class SecureChatServer(socketserver.ThreadingTCPServer):
    """
    Secure chat server that handles two-client connections with end-to-end encryption.
    Allows only two clients to connect simultaneously and facilitates key exchange
    and encrypted message routing between them.
    
    Logging is intentionally very minimal since this is a security and privacy focused application.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 16384):
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
        
        super().__init__((host, port), SecureChatRequestHandler)
        
        print(f"Secure chat server started on {host}:{port}")
        print("Waiting for clients to connect...")
    
    def add_client(self, client_handler: 'SecureChatRequestHandler') -> bool:
        """Add a client to the server. Returns True if added, False if server rejects the client."""
        with self.clients_lock:
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
    
    def remove_client(self, client_id: str):
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
    
    def initiate_key_exchange(self):
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
        attempts: list[tuple[bool, str]] = []
        with self.clients_lock:
            for client_id, client_handler in self.clients.items():
                if client_id != sender_id and client_handler.is_connected():
                    attempts.append(send_message(client_handler.request, message_data))
        
        all_sent = True
        for success, error_text in attempts:
            if not success:
                print(f"Failed to route message to {sender_id}: {error_text}")
                all_sent = False
        return all_sent
    
    
    def broadcast_error(self, error_text: str):
        """Broadcast an error message to all connected clients."""
        error_msg = json.dumps({"type":  MessageType.ERROR, "error": error_text}).encode('utf-8')
        with self.clients_lock:
            for client_handler in self.clients.values():
                send_message(client_handler.request, error_msg)
    
    def start_server(self):
        """Start the server and serve forever."""
        self.running = True
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("Server interrupted by user")
        finally:
            self.stop_server()
    
    def stop_server(self):
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
                 server: SecureChatServer) -> None:
        self.client_id: str = ""
        self.connected: bool = True
        self.key_exchange_complete: bool = False
        self.announced_disconnect: bool = False
        self.force_full: bool = False
        self.upload_accepted: bool = False
        self.correct_download_hash: bytes = bytes()
        self.ml_kem_sk: bytes = bytes()
        self.shared_secret: bytes = bytes()
        
        # Keepalive tracking
        self.last_keepalive_time: float = time.time()
        self.keepalive_failures: int = 0
        self.waiting_for_keepalive_response: bool = False
        self.keepalive_thread: threading.Thread | None = None
        self.unexpected_message_count: int = 0
        
        super().__init__(request, client_address, server)
    
    def setup(self) -> None:
        """Called before handle() to perform initialization."""
        # Try to add this client to the server
        if self.force_full or not self.server.add_client(self):
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
    
    def handle(self):
        try:
            self._handle()
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
            message_data = receive_message(self.request)
            
            try:
                message = json.loads(message_data)
                message_type = message.get("type")
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"Failed to parse message from {self.client_id}")
                self.handle_unexpected_message("failed to parse message")
                return
            
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
            
            if message_type == MessageType.DEADDROP_CHECK:
                # self.handle_deaddrop_check(message)
                # continue
                pass

            if message_type == MessageType.DEADDROP_UPLOAD:
                # self.handle_deaddrop_upload(message)
                # continue
                pass

            if message_type == MessageType.DEADDROP_DOWNLOAD:
                # self.handle_deaddrop_download(message)
                # continue
                pass

            if not self.key_exchange_complete:
                if message_type in (MessageType.KEY_EXCHANGE_INIT, MessageType.KEY_EXCHANGE_RESPONSE,
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
            if message_type == MessageType.KEY_EXCHANGE_RESPONSE:
                self.key_exchange_complete = True
                other_client.key_exchange_complete = True
                self.notify_key_exchange_complete()
        else:
            self.server.broadcast_error("Key exchange failed - no other client")

    
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
    
    def notify_key_exchange_complete(self) -> None:
        """Notify both clients that key exchange is complete."""
        complete_message = {
            "type":    MessageType.KEY_EXCHANGE_COMPLETE,
            "message": "Key exchange completed successfully"
        }
        message_data = json.dumps(complete_message).encode('utf-8')
        with self.server.clients_lock:
            for client_handler in self.server.clients.values():
                ok, err = send_message(client_handler.request, message_data)
                if not ok:
                    print(f"Failed to notify key exchange complete to {client_handler.client_id}: {err}")
    
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
                time.sleep(60)  # Send keepalive every 60 ish seconds
                
                if not self.connected:
                    break
                
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
                "timestamp": time.time()
            }
            message_data = json.dumps(keepalive_message).encode('utf-8')
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
                "protocol_version": PROTOCOL_VERSION
            }
            message_data = json.dumps(version_message).encode('utf-8')
            send_message(self.request, message_data)
        except (OSError, ConnectionError) as e:
            print(f"Error sending protocol version info to {self.client_id} (socket): {e}")
        except Exception as e:
            print(f"Error sending protocol version info to {self.client_id} (unexpected): {e}")
    
    def disconnect(self, reason: str = "", notify: bool = True) -> None:
        """Disconnect the client and clean up.
        
        If a reason is provided, the server will attempt to send a SERVER_DISCONNECT
        control message with the reason before closing the connection.
        """
        if self.connected:
            print(f"[{datetime.datetime.now().strftime(format="%d.%m.%Y, %H:%M:%S")}] Disconnecting", self.client_id,
                  "Reason:", reason if reason else "No reason provided")
            self.connected = False
            
            # Attempt to notify client about server-initiated disconnect
            if notify:
                disconnect_message = {
                    "type":   MessageType.SERVER_DISCONNECT,
                    "reason": reason if reason else "Server disconnect",
                }
                message_data = json.dumps(disconnect_message).encode('utf-8')
                send_message(self.request, message_data)
            
            
            if self.client_id:
                self.server.remove_client(self.client_id)
            try:
                self.request.close()
            except (OSError, ConnectionError, socket.error):
                # ignore: closing a dead socket
                pass
    
    def handle_unexpected_message(self, extra_info: str = "") -> None:
        """Handle unexpected messages from the client."""
        self.unexpected_message_count += 1
        if self.unexpected_message_count >= configs.MAX_UNEXPECTED_MSGS:
            self.disconnect("Too many unexpected messages" + extra_info)

    def handle_deaddrop_start(self) -> None:
        """Handle deaddrop start message from client."""
        if not configs.DEADDROP_ENABLED:
            deny_msg = {
                "type": MessageType.DEADDROP_START,
                "supported": False
            }
            send_message(self.request, json.dumps(deny_msg).encode('utf-8'))
            return

        public_key, self.ml_kem_sk = ml_kem_1024.generate_keypair()
        msg = {
            "type": MessageType.DEADDROP_START,
            "supported": True,
            "file_size": configs.DEADDROP_MAX_SIZE,
            "mlkem_public": base64.b64encode(public_key).decode('utf-8')
        }
        send_message(self.request, json.dumps(msg).encode('utf-8'))

    def handle_deaddrop_ke_response(self, message_data: dict[Any, Any]) -> None:
        """Handle deaddrop key exchange response message from client."""
        try:
            client_mlkem_ct = base64.b64decode(message_data["mlkem_ct"], validate = True)
        except KeyError:
            self.handle_unexpected_message("deaddrop ke response message without mlkem_ct")
            return
        except binascii.Error:
            self.handle_unexpected_message("deaddrop ke response message with invalid mlkem_ct")
            return

        shared_secret = ml_kem_1024.decrypt(client_mlkem_ct, self.ml_kem_sk)
        self.shared_secret = ConcatKDFHash(algorithm=hashes.SHA3_512(), length=32, otherinfo=b"deaddrop file transfer").derive(shared_secret)


    def handle_deaddrop_check(self, message_data: dict[Any, Any]) -> None:
        """Handle deaddrop check message from client."""
        # TODO: Add rate limiting, it'll just say false every time if you're rate limited.
        try:
            name = message_data["name"]
        except KeyError:
            self.handle_unexpected_message("deaddrop check message without name")
            return
        
        if self.server.deaddrop_manager.check_file(name):
            msg = {
                "type": MessageType.DEADDROP_CHECK_RESPONSE,
                "exists": True
            }
            send_message(self.request, json.dumps(msg).encode('utf-8'))
        else:
            msg = {
                "type": MessageType.DEADDROP_CHECK_RESPONSE,
                "exists": False
            }
            send_message(self.request, json.dumps(msg).encode('utf-8'))
    
    def handle_deaddrop_upload(self, message: dict[Any, Any]) -> None:
        if self.get_other_client():
            send_message(self.request, json.dumps({"type": MessageType.DEADDROP_DENY}).encode('utf-8'))
            return

        if not configs.DEADDROP_ENABLED:
            send_message(self.request, json.dumps({"type": MessageType.DEADDROP_DENY}).encode('utf-8'))
            return
        
        try:
            name = str(message["name"])
            file_size = int(message["file_size"])
            file_hash = str(message["file_hash"])
            password_hash = message["file_password_hash"]
        except KeyError:
            self.handle_unexpected_message("deaddrop upload message without name or password")
            return
        except binascii.Error:
            self.handle_unexpected_message("deaddrop upload message with invalid password")
            return
        except (ValueError, TypeError):
            self.handle_unexpected_message("deaddrop upload message with invalid file size")
            return

        if file_size > configs.DEADDROP_MAX_SIZE:
            too_large_msg = {
                "type": MessageType.DEADDROP_DENY,
                "reason": "File size exceeds maximum allowed size"
            }
            send_message(self.request, json.dumps(too_large_msg).encode('utf-8'))
            return

        self.upload_accepted = True
        self.force_full = True
        self.server.deaddrop_manager.add_file(name, password_hash, file_hash)
        send_message(self.request, json.dumps({"type": MessageType.DEADDROP_ACCEPT}).encode('utf-8'))

    def handle_deaddrop_download(self, message: dict[Any, Any]) -> None:
        if self.get_other_client():
            send_message(self.request, json.dumps({"type": MessageType.DEADDROP_DENY}).encode('utf-8'))
            return

        if not configs.DEADDROP_ENABLED:
            send_message(self.request, json.dumps({"type": MessageType.DEADDROP_DENY}).encode('utf-8'))
            return

        try:
            name = str(message["name"])
        except KeyError:
            self.handle_unexpected_message("deaddrop download message without name or password")
            return
        except binascii.Error:
            self.handle_unexpected_message("deaddrop download message with invalid password")
            return

        if not self.server.deaddrop_manager.check_file(name):
            not_found_msg = {
                "type": MessageType.DEADDROP_DENY,
                "reason": "Deaddrop file not found"
            }
            send_message(self.request, json.dumps(not_found_msg).encode('utf-8'))
            return

        download_salt = os.urandom(32)
        msg = {
            "type": MessageType.DEADDROP_PROVE,
            "salt": base64.b64encode(download_salt)
        }
        send_message(self.request, json.dumps(msg).encode('utf-8'))

        og_hash = self.server.deaddrop_manager.get_password_hash(name).encode('utf-8')

        pbk = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=download_salt,
            iterations=800000
        )

        self.correct_download_hash = pbk.derive(og_hash)

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
