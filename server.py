"""
Secure Chat Server that handles two-client connections with end-to-end encryption.
This server accepts two clients, initiates a key exchange, and routes encrypted messages; it cannot read the messages.
"""
# server.py - Secure chat server
# pylint: disable=trailing-whitespace
import socket
import threading
import json
from typing import Optional
import time

from shared import SecureChatProtocol, send_message, receive_message, create_error_message, create_reset_message, \
    MSG_TYPE_KEY_EXCHANGE_RESPONSE, MSG_TYPE_KEY_VERIFICATION, MSG_TYPE_KEEP_ALIVE, MSG_TYPE_KEEP_ALIVE_RESPONSE, \
    PROTOCOL_VERSION


class SecureChatServer:
    """Secure chat server that handles two-client connections with end-to-end encryption."""
    
    def __init__(self, host='localhost', port=16384):
        """Initialize the secure chat server.
        
        Args:
            host (str, optional): The hostname or IP address to bind the server to.
                Defaults to 'localhost'.
            port (int, optional): The port number to listen on. Defaults to 16384.
                
        Attributes:
            host (str): Server hostname or IP address.
            port (int): Server port number.
            clients (dict[str, ClientHandler]): Dictionary mapping client IDs to 
                their handler instances.
            server_socket (socket.socket): The main server socket for accepting connections.
            running (bool): Flag indicating whether the server is currently running.
        """
        self.host = host
        self.port = port
        self.clients: dict[str, 'ClientHandler'] = {}
        self.server_socket = None
        self.running = False
        
    def start(self):
        """Start the server and listen for client connections.
        
        Creates a server socket, binds it to the configured host and port, and enters
        the main server loop to accept up to 2 client connections. When exactly 2
        clients are connected, automatically initiates the key exchange process.
        
        The server uses a timeout-based accept loop to allow for graceful shutdown
        and client monitoring. The method blocks until the server is stopped or
        an error occurs.
        
        Note:
            This method will print status messages to stdout and handles KeyboardInterrupt
            for graceful shutdown. The server socket is configured with SO_REUSEADDR
            to allow quick restart after shutdown.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)  # Set timeout for non-blocking accept
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(2)  # Only allow 2 clients
            self.running = True
            
            print(f"Secure chat server started on {self.host}:{self.port}")
            print("Waiting for clients to connect...")
            
            # Main server loop - continuously accept new connections and monitor clients
            while self.running:
                try:
                    # Try to accept new connections if we have less than 2 clients
                    if len(self.clients) < 2:
                        try:
                            client_socket, address = self.server_socket.accept()
                            client_id = f"client_{len(self.clients) + 1}"
                            
                            print(f"Client {client_id} connected from {address}")
                            
                            # Create client handler
                            client_handler = ClientHandler(client_socket, client_id, self)
                            self.clients[client_id] = client_handler
                            
                            # Start client thread
                            client_thread = threading.Thread(target=client_handler.handle)
                            client_thread.daemon = True
                            client_thread.start()
                            
                            # If we now have exactly 2 clients, start key exchange
                            if len(self.clients) == 2:
                                print("Two clients connected. Starting key exchange...")
                                self.initiate_key_exchange()
                                
                        except socket.timeout:
                            # Timeout is expected, continue to client monitoring
                            pass
                        except socket.error as e:
                            if self.running:
                                print(f"Error accepting connection: {e}")
                    
                    
                    # Sleep briefly to avoid busy waiting
                    time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    print("Server interrupted by user")
                    break
                except Exception as e:
                    print(f"Error in server main loop: {e}")
                    break
                        
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop()
    
    def initiate_key_exchange(self):
        """Initiate the key exchange process between two connected clients.
        
        This method is called automatically when exactly 2 clients are connected.
        It sends a key exchange initiation message to the first client, which
        will then start the ML-KEM-1024 key exchange protocol.
        
        The method ensures that exactly 2 clients are connected before proceeding.
        If the initiation fails, an error is broadcast to all clients.
        
        Note:
            This method only sends the initiation signal. The actual key exchange
            protocol is handled by the SecureChatProtocol class in the clients.
            The server acts as a message router and cannot decrypt the exchanged keys.
        """
        if len(self.clients) != 2:
            return
            
        client_handlers = list(self.clients.values())
        client1 = client_handlers[0]
        
        # Tell first client to start key exchange
        try:
            initiate_message = {
                "type": "initiate_key_exchange",
                "message": "Starting key exchange..."
            }
            message_data = json.dumps(initiate_message).encode('utf-8')
            send_message(client1.socket, message_data)
            print(f"Key exchange initiation sent to {client1.client_id}")
            
        except Exception as e:
            print(f"Key exchange initiation failed: {e}")
            self.broadcast_error("Key exchange failed")
    
    def route_message(self, sender_id: str, message_data: bytes):
        """Route encrypted message from sender to the other client."""
        for client_id, client_handler in self.clients.items():
            if client_id != sender_id and client_handler.is_connected():
                try:
                    send_message(client_handler.socket, message_data)
                except Exception as e:
                    print(f"Failed to route message to {client_id}: {e}")
                    client_handler.disconnect()
    
    def remove_client(self, client_id: str):
        """Remove a client from the server."""
        if client_id in self.clients:
            del self.clients[client_id]
            print(f"Client {client_id} removed")
            
            # Notify remaining client to reset key exchange
            if self.clients:
                remaining_client = list(self.clients.values())[0]
                try:
                    # Send key exchange reset message
                    reset_msg = create_reset_message()
                    send_message(remaining_client.socket, reset_msg)
                    
                    # Reset the remaining client's key exchange state
                    remaining_client.key_exchange_complete = False
                    remaining_client.protocol.reset_key_exchange()
                    
                    print(f"Key exchange reset sent to remaining client {remaining_client.client_id}")
                except: # pylint: disable=bare-except
                    pass
    
    def broadcast_error(self, error_text: str):
        """Send error message to all connected clients."""
        error_msg = create_error_message(error_text)
        for client_handler in self.clients.values():
            if client_handler.is_connected():
                try:
                    send_message(client_handler.socket, error_msg)
                except: # pylint: disable=bare-except
                    pass
    
    def stop(self):
        """Stop the server and close all connections."""
        self.running = False
        
        # Close all client connections
        for client_handler in list(self.clients.values()):
            client_handler.disconnect()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except: # pylint: disable=bare-except
                pass
        
        print("Server stopped")

class ClientHandler:
    """Handles individual client connections."""
    
    def __init__(self, socket: socket.socket, client_id: str, server: SecureChatServer):
        self.socket = socket
        self.client_id = client_id
        self.server = server
        self.protocol = SecureChatProtocol()
        self.connected = True
        self.key_exchange_complete = False
        
        # Keepalive tracking
        self.last_keepalive_time = time.time()
        self.keepalive_failures = 0
        self.waiting_for_keepalive_response = False
        self.keepalive_thread = None
        
    def handle(self):
        """Main client handling loop."""
        try:
            while self.connected:
                try:
                    # Receive message from client
                    message_data = receive_message(self.socket)
                    
                    if not self.key_exchange_complete:
                        # Handle key exchange messages
                        self.handle_key_exchange(message_data)
                    else:
                        # Check if this is a verification message or keepalive response
                        try:
                            message = json.loads(message_data.decode('utf-8'))
                            message_type = message.get("type")
                            
                            if message_type == MSG_TYPE_KEY_VERIFICATION:
                                # Route verification messages
                                self.route_verification_message(message_data)
                            elif message_type == MSG_TYPE_KEEP_ALIVE_RESPONSE:
                                # Handle keepalive response
                                self.handle_keepalive_response(message_data)
                            else:
                                # Route encrypted messages to other client
                                self.server.route_message(self.client_id, message_data)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # This is likely an encrypted message (binary data)
                            self.server.route_message(self.client_id, message_data)
                        
                except ConnectionError:
                    break
                except Exception as e:
                    print(f"Error handling client {self.client_id}: {e}")
                    break
                    
        finally:
            self.disconnect()
    
    
    def handle_key_exchange(self, message_data: bytes):
        """Handle key exchange messages by routing them to the other client."""
        try:
            # Parse message to determine type for logging
            try:
                message = json.loads(message_data.decode('utf-8'))
                message_type = message.get("type")
                
                # Check for protocol version mismatch
                if "version" in message:
                    peer_version = message.get("version")
                    if peer_version != PROTOCOL_VERSION:
                        print(f"\nWARNING: Protocol version mismatch detected in message from {self.client_id}.")
                        print(f"Server version: {PROTOCOL_VERSION}, Client version: {peer_version}")
                        print("Communication between clients may not work properly.")
                
            except (json.JSONDecodeError, UnicodeDecodeError):
                # If we can't parse the message, assume it's binary key exchange data
                message_type = "binary_key_exchange"
            
            # Route the message to the other client
            other_client = self.get_other_client()
            if other_client:
                send_message(other_client.socket, message_data)
                print(f"Key exchange message (type {message_type}) routed from {self.client_id} to {other_client.client_id}")
                
                # If this is a key exchange response, the key exchange is complete
                if message_type == MSG_TYPE_KEY_EXCHANGE_RESPONSE:
                    print(f"Key exchange completed between {self.client_id} and {other_client.client_id}")
                    # Mark both clients as having completed key exchange
                    self.key_exchange_complete = True
                    other_client.key_exchange_complete = True
                    # Notify both clients that key exchange is complete
                    self.notify_key_exchange_complete()
                    
            else:
                print(f"No other client available to route key exchange message from {self.client_id}")
                self.server.broadcast_error("Key exchange failed - no other client")
                    
        except Exception as e:
            print(f"Key exchange routing error for {self.client_id}: {e}")
            self.server.broadcast_error("Key exchange failed")
    
    def route_verification_message(self, message_data: bytes):
        """Route key verification messages between clients."""
        try:
            # Route the verification message to the other client
            other_client = self.get_other_client()
            if other_client:
                send_message(other_client.socket, message_data)
                print(f"Key verification message routed from {self.client_id} to {other_client.client_id}")
            else:
                print(f"No other client available to route verification message from {self.client_id}")
                self.server.broadcast_error("Verification failed - no other client")
                
        except Exception as e:
            print(f"Verification message routing error for {self.client_id}: {e}")
            self.server.broadcast_error("Verification message routing failed")
    
    def notify_key_exchange_complete(self):
        """Notify both clients that key exchange is complete."""
        success_message = {
            "type": "key_exchange_complete",
            "message": "Secure connection established. You can now send messages.",
            "version": PROTOCOL_VERSION  # Include server's protocol version
        }
        message_data = json.dumps(success_message).encode('utf-8')
        
        # Send to both clients
        for client_handler in self.server.clients.values():
            if client_handler.is_connected():
                try:
                    send_message(client_handler.socket, message_data)
                    client_handler.key_exchange_complete = True
                    
                    # Start keepalive for this client
                    client_handler.start_keepalive()
                except: # pylint: disable=bare-except
                    pass
    
    def get_other_client(self) -> Optional['ClientHandler']:
        """Get the other connected client."""
        for client_id, client_handler in self.server.clients.items():
            if client_id != self.client_id and client_handler.is_connected():
                return client_handler
        return None
    
    def is_connected(self) -> bool:
        """Check if client is still connected."""
        return self.connected
    
    def start_keepalive(self):
        """Start the keepalive thread."""
        if self.keepalive_thread is None:
            self.keepalive_thread = threading.Thread(target=self.keepalive_loop)
            self.keepalive_thread.daemon = True
            self.keepalive_thread.start()
            print(f"Started keepalive for client {self.client_id}")
    
    def keepalive_loop(self):
        """Send keepalive messages every minute and track responses."""
        while self.connected:
            # Send a keepalive message
            self.send_keepalive()
            
            # Wait for 10 seconds for a response
            response_wait_start = time.time()
            while self.waiting_for_keepalive_response and (time.time() - response_wait_start) < 10:
                time.sleep(0.1)  # Short sleep to avoid busy waiting
                
                if not self.connected:
                    break
            
            # If we're still waiting for a response after 10 seconds, count it as a failure
            if self.waiting_for_keepalive_response:
                self.keepalive_failures += 1
                print(f"Keepalive failure for client {self.client_id} (failure {self.keepalive_failures}/3)")
                
                # Disconnect after 3 failures
                if self.keepalive_failures >= 3:
                    print(f"Client {self.client_id} failed 3 keepalives, disconnecting")
                    self.disconnect()
                    break
            
            # Wait for the remainder of the minute before sending the next keepalive
            # Total cycle should be 60 seconds (1 minute)
            elapsed = time.time() - self.last_keepalive_time
            if elapsed < 60:
                time.sleep(60 - elapsed)
            
            if not self.connected:
                break
    
    def send_keepalive(self):
        """Send a keepalive message to the client."""
        if not self.connected or not self.key_exchange_complete:
            return
            
        try:
            # Create keepalive message
            keepalive_message = {
                "version": PROTOCOL_VERSION,
                "type": MSG_TYPE_KEEP_ALIVE
            }
            message_data = json.dumps(keepalive_message).encode('utf-8')
            
            # Send to client
            send_message(self.socket, message_data)
            print("Sent keepalive to client", self.client_id)
            
            # Update tracking
            self.last_keepalive_time = time.time()
            self.waiting_for_keepalive_response = True
            
        except Exception as e:
            print(f"Error sending keepalive to client {self.client_id}: {e}")
            self.disconnect()
    
    def handle_keepalive_response(self, message_data: bytes):
        """Handle a keepalive response from the client."""
        try:
            # Parse message to verify it's a keepalive response
            message = json.loads(message_data.decode('utf-8'))
            if message.get("type") == MSG_TYPE_KEEP_ALIVE_RESPONSE:
                # Reset tracking
                self.waiting_for_keepalive_response = False
                self.keepalive_failures = 0
                
        except Exception as e:
            print(f"Error handling keepalive response from client {self.client_id}: {e}")
    
    def disconnect(self):
        """Disconnect the client."""
        # pylint: disable=
        if self.connected:
            self.connected = False
            try:
                self.socket.close()
            except: # pylint: disable=bare-except
                pass
            
            self.server.remove_client(self.client_id)

if __name__ == "__main__":
    server = SecureChatServer("0.0.0.0", 16384)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()