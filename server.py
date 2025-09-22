"""
Secure chat server using socketserver.ThreadingTCPServer.
Rewritten to use proper socketserver architecture instead of manual socket handling.
"""
# pylint: disable=trailing-whitespace, broad-exception-caught, bare-except, too-many-instance-attributes
import socket
import socketserver
import threading
import json
import time
from typing import Final, Self

from shared import send_message, receive_message, create_error_message, \
    create_reset_message, MessageType, PROTOCOL_VERSION

SERVER_VERSION: Final[int] = 6
MAX_UNEXPECTED_MSGS: Final[int] = 10


# noinspection PyBroadException
class SecureChatServer(socketserver.ThreadingTCPServer):
    """
    Secure chat server that handles two-client connections with end-to-end encryption.
    Allows only two clients to connect simultaneously and facilitates key exchange
    and encrypted message routing between them.
    
    Logging is intentionally very minimal since this is a security and privacy focused application.
    """
    
    def __init__(self, host='0.0.0.0', port=16384):
        """Initialize the secure chat server.
        
        Args:
            host (str, optional): The hostname or IP address to bind the server to.
                Defaults to 'localhost'.
            port (int, optional): The port number to listen on. Defaults to 16384.
        """
        self.clients: dict[str, 'SecureChatRequestHandler'] = {}
        self.clients_lock = threading.Lock()
        self.running = False
        self.client_counter = 0  # Counter for unique client IDs
        
        super().__init__((host, port), SecureChatRequestHandler) # type: ignore
        
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
            
            print(f"Client {client_id} connected from {client_handler.client_address}")
            
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
                    try:
                        # Send key exchange reset message
                        reset_msg = create_reset_message()
                        send_message(remaining_client.request, reset_msg)
                        
                        # Reset the remaining client's key exchange state
                        remaining_client.key_exchange_complete = False
                        
                    except: # pylint: disable=bare-except
                        pass
    
    def initiate_key_exchange(self):
        """Initiate the key exchange process between two connected clients."""
        with self.clients_lock:
            
            if len(self.clients) != 2:
                return
                
            client_handlers = list(self.clients.values())
            client1 = client_handlers[0]
            
            # Tell first client to start key exchange
            try:
                initiate_message = {
                    "type": MessageType.INITIATE_KEY_EXCHANGE,
                    "message": "Starting key exchange..."
                }
                message_data = json.dumps(initiate_message).encode('utf-8')
                send_message(client1.request, message_data)
                
            except Exception as e:
                print(f"Key exchange initiation failed: {e}")
                self.broadcast_error("Key exchange failed")
    
    def route_message(self, sender_id: str, message_data: bytes):
        """Route encrypted message from sender to the other client."""
        with self.clients_lock:
            for client_id, client_handler in self.clients.items():
                if client_id != sender_id and client_handler.is_connected():
                    try:
                        send_message(client_handler.request, message_data)
                    except Exception as e:
                        print(f"Failed to route message to {client_id}: {e}")
                        client_handler.disconnect(f"Routing failure: {e}")
    
    def broadcast_error(self, error_text: str):
        """Broadcast an error message to all connected clients."""
        error_msg = create_error_message(error_text)
        with self.clients_lock:
            for client_handler in self.clients.values():
                try:
                    send_message(client_handler.request, error_msg)
                except: # pylint: disable=bare-except
                    pass
    
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
    
    def start(self):
        """Compatibility method for existing tests."""
        return self.start_server()
    
    def stop(self):
        """Compatibility method for existing tests."""
        return self.stop_server()


# noinspection PyBroadException
class SecureChatRequestHandler(socketserver.BaseRequestHandler):
    """Handles individual client connections."""
    server: 'SecureChatServer'
    
    def __init__(self, request: socket.socket | tuple[bytes, socket.socket], client_address: str,
                 server: SecureChatServer) -> None:
        self.client_id = None
        self.connected = True
        self.key_exchange_complete = False
        self.announced_disconnect = False
        
        # Keepalive tracking
        self.last_keepalive_time = time.time()
        self.keepalive_failures = 0
        self.waiting_for_keepalive_response = False
        self.keepalive_thread = None
        self.unexpected_message_count = 0
        
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
            except:
                # we don't care if this fails, the client is being rejected either way
                pass
            return
        
        super().setup()
        
        # Send server version information to the newly connected client
        self.send_server_version_info()
    
    def handle(self) -> None:
        """Main client handling loop."""
        # If client wasn't added (server full), don't process
        if self.client_id is None:
            return
        
        try:
            self.start_keepalive()
            
            while self.connected:
                try:
                    message_data = receive_message(self.request)
                    
                    parsed = False
                    try:
                        message = json.loads(message_data.decode('utf-8'))
                        message_type = message.get("type")
                        parsed = True
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        message_type = None
                    
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
                    
                    if not self.key_exchange_complete:
                        if (not parsed) or (message_type in (MessageType.KEY_EXCHANGE_INIT,
                                                             MessageType.KEY_EXCHANGE_RESPONSE,
                                                             MessageType.KEY_EXCHANGE_RESET,
                                                             MessageType.INITIATE_KEY_EXCHANGE)):
                            self.handle_key_exchange(message_data)
                            continue
                        
                        # If we get here, it's an unexpected message during key exchange
                        self.handle_unexpected_message("unexpected message during key exchange")
                        continue
                    
                    self.server.route_message(self.client_id, message_data)
                        
                except ConnectionError as e:
                    print(f"Client {self.client_id} disconnected unexpectedly: {e}")
                    break
                except Exception as e:
                    print(f"Error handling client {self.client_id}: {e}")
                    break
                    
        finally:
            if not self.announced_disconnect:
                self.disconnect()
    
    def handle_key_exchange(self, message_data: bytes)-> None:
        """Handle key exchange messages by routing them to the other client."""
        try:
            # Parse message to determine type for logging
            try:
                message = json.loads(message_data.decode('utf-8'))
                message_type = message.get("type")
                
            except (json.JSONDecodeError, UnicodeDecodeError):
                # If we can't parse the message, assume it's binary key exchange data
                message_type = "binary_key_exchange"
            
            # Route the message to the other client
            other_client = self.get_other_client()
            if other_client:
                send_message(other_client.request, message_data)
                
                # If this is a key exchange response, the key exchange is complete
                if message_type == MessageType.KEY_EXCHANGE_RESPONSE:
                    # Mark both clients as having completed key exchange
                    self.key_exchange_complete = True
                    other_client.key_exchange_complete = True
                    # Notify both clients that key exchange is complete
                    self.notify_key_exchange_complete()
                    
            else:
                self.server.broadcast_error("Key exchange failed - no other client")
                    
        except Exception as e:
            print(f"Key exchange routing error for {self.client_id}: {e}")
            self.server.broadcast_error("Key exchange failed")
    
    def route_verification_message(self, message_data: bytes) -> None:
        """Route key verification messages between clients."""
        try:
            if self.key_exchange_complete:
                self.handle_unexpected_message("verification after key exchange")
                return
            # Route the verification message to the other client
            other_client = self.get_other_client()
            if other_client:
                send_message(other_client.request, message_data)
            else:
                self.server.broadcast_error("Verification failed - no other client")
                
        except Exception as e:
            print(f"Verification routing error for {self.client_id}: {e}")
            self.server.broadcast_error("Verification failed")
    
    def notify_key_exchange_complete(self) -> None:
        """Notify both clients that key exchange is complete."""
        try:
            complete_message = {
                "type": MessageType.KEY_EXCHANGE_COMPLETE,
                "message": "Key exchange completed successfully"
            }
            message_data = json.dumps(complete_message).encode('utf-8')
            
            # Send to both clients
            with self.server.clients_lock:
                for client_handler in self.server.clients.values():
                    try:
                        send_message(client_handler.request, message_data)
                    except: # pylint: disable=bare-except
                        pass
                        
            
        except Exception as e:
            print(f"Failed to notify key exchange completion: {e}")
    
    def get_other_client(self) -> Self | None:
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

                    
            except Exception as e:
                print(f"Keepalive error for {self.client_id}: {e}")
                break
    
    def send_keepalive(self) -> None:
        """Send a keepalive message to the client."""
        try:
            keepalive_message = {
                "type": MessageType.KEEP_ALIVE,
                "timestamp": time.time()
            }
            message_data = json.dumps(keepalive_message).encode('utf-8')
            send_message(self.request, message_data)
            
            self.waiting_for_keepalive_response = True
            self.last_keepalive_time = time.time()
            
        except Exception as e:
            print(f"Failed to send keepalive to {self.client_id}: {e}")
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
            # Create protocol version message (only protocol version, no compatibility matrix or server version)
            version_message = {
                "type": MessageType.SERVER_VERSION_INFO,
                "protocol_version": PROTOCOL_VERSION
            }
            
            message_data = json.dumps(version_message).encode('utf-8')
            send_message(self.request, message_data)
            
        except Exception as e:
            print(f"Error sending protocol version info to {self.client_id}: {e}")
    
    def disconnect(self, reason: str = "", notify: bool = True) -> None:
        """Disconnect the client and clean up.
        
        If a reason is provided, the server will attempt to send a SERVER_DISCONNECT
        control message with the reason before closing the connection.
        """
        if self.connected:
            print("Disconnecting client", self.client_id, "Reason:", reason if reason else "No reason provided")
            self.connected = False

            # Attempt to notify client about server-initiated disconnect
            if notify:
                try:
                    disconnect_message = {
                        "type": MessageType.SERVER_DISCONNECT,
                        "reason": reason if reason else "Server disconnect",
                    }
                    message_data = json.dumps(disconnect_message).encode('utf-8')
                    send_message(self.request, message_data)
                except:  # pylint: disable=bare-except
                    # Best-effort notification; continue with disconnect
                    pass
            
            if self.client_id:
                self.server.remove_client(self.client_id)
            
            try:
                self.request.close()
            except: # pylint: disable=bare-except
                pass
    
    def handle_unexpected_message(self, extra_info: str = "") -> None:
        """Handle unexpected messages from the client."""
        self.unexpected_message_count += 1
        if self.unexpected_message_count >= MAX_UNEXPECTED_MSGS:
            self.disconnect("Too many unexpected messages" + extra_info)


def main() -> None:
    """Main entry point to start the secure chat server."""
    try:
        server = SecureChatServer()
        server.start_server()
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    main()
