# server.py - Secure chat server
import socket
import threading
import json
from typing import Optional

from shared import SecureChatProtocol, send_message, receive_message, create_error_message, MSG_TYPE_KEY_VERIFICATION, MSG_TYPE_KEY_EXCHANGE_RESPONSE

class SecureChatServer:
    """Secure chat server that handles two-client connections with end-to-end encryption."""
    
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.clients: dict[str, 'ClientHandler'] = {}
        self.server_socket = None
        self.running = False
        
    def start(self):
        """Start the server and listen for connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(2)  # Only allow 2 clients
            self.running = True
            
            print(f"Secure chat server started on {self.host}:{self.port}")
            print("Waiting for clients to connect...")
            
            # Accept up to 2 clients
            while self.running and len(self.clients) < 2:
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
                    
                    if len(self.clients) == 2:
                        print("Two clients connected. Starting key exchange...")
                        self.initiate_key_exchange()
                        break  # Stop accepting new connections but keep server running
                        
                except socket.error as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
            
            # Keep server running to handle client communication
            print("Server is now handling client communication...")
            while self.running and self.clients:
                try:
                    # Check if any clients are still connected
                    connected_clients = [c for c in self.clients.values() if c.is_connected()]
                    if not connected_clients:
                        print("No clients connected. Shutting down server.")
                        break
                    
                    # Sleep briefly to avoid busy waiting
                    import time
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
        """Initiate key exchange between the two connected clients."""
        if len(self.clients) != 2:
            return
            
        client_handlers = list(self.clients.values())
        client1, client2 = client_handlers[0], client_handlers[1]
        
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
            
            # Notify remaining client
            if self.clients:
                remaining_client = list(self.clients.values())[0]
                try:
                    error_msg = create_error_message("Other client disconnected")
                    send_message(remaining_client.socket, error_msg)
                except:
                    pass
    
    def broadcast_error(self, error_text: str):
        """Send error message to all connected clients."""
        error_msg = create_error_message(error_text)
        for client_handler in self.clients.values():
            if client_handler.is_connected():
                try:
                    send_message(client_handler.socket, error_msg)
                except:
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
            except:
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
                        # Check if this is a verification message
                        try:
                            message = json.loads(message_data.decode('utf-8'))
                            if message.get("type") == MSG_TYPE_KEY_VERIFICATION:
                                # Route verification messages
                                self.route_verification_message(message_data)
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
            "message": "Secure connection established. You can now send messages."
        }
        message_data = json.dumps(success_message).encode('utf-8')
        
        # Send to both clients
        for client_handler in self.server.clients.values():
            if client_handler.is_connected():
                try:
                    send_message(client_handler.socket, message_data)
                    client_handler.key_exchange_complete = True
                except:
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
    
    def disconnect(self):
        """Disconnect the client."""
        if self.connected:
            self.connected = False
            try:
                self.socket.close()
            except:
                pass
            self.server.remove_client(self.client_id)

if __name__ == "__main__":
    server = SecureChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()