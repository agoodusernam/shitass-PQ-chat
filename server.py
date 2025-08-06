#!/usr/bin/env python3
"""
Secure chat server using socketserver.ThreadingTCPServer.
Rewritten to use proper socketserver architecture instead of manual socket handling.
"""

import socketserver
import threading
import json
import time
from typing import Optional

from shared import SecureChatProtocol, send_message, receive_message, create_error_message, create_reset_message, \
    MessageType, PROTOCOL_VERSION

SERVER_VERSION = 5


# noinspection PyBroadException
class SecureChatServer(socketserver.ThreadingTCPServer):
    """Secure chat server that handles two-client connections with end-to-end encryption."""
    
    # Allow address reuse
    allow_reuse_address = True
    
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
        """Add a client to the server. Returns True if added, False if server is full."""
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
                print(f"Client {client_id} removed")
                
                # Notify remaining client to reset key exchange
                if self.clients:
                    remaining_client = list(self.clients.values())[0]
                    try:
                        # Send key exchange reset message
                        reset_msg = create_reset_message()
                        send_message(remaining_client.request, reset_msg)
                        
                        # Reset the remaining client's key exchange state
                        remaining_client.key_exchange_complete = False
                        remaining_client.protocol.reset_key_exchange()
                        
                        print(f"Key exchange reset sent to remaining client {remaining_client.client_id}")
                    except: # pylint: disable=bare-except
                        pass
    
    def initiate_key_exchange(self):
        """Initiate the key exchange process between two connected clients."""
        print("Running key exchange initiation...")
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
                print(f"Key exchange initiation sent to {client1.client_id}")
                
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
                        client_handler.disconnect()
    
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
        self.shutdown()
        self.server_close()
        print("Server stopped")
    
    def start(self):
        """Compatibility method for existing tests."""
        return self.start_server()
    
    def stop(self):
        """Compatibility method for existing tests."""
        return self.stop_server()


# noinspection PyBroadException
class SecureChatRequestHandler(socketserver.BaseRequestHandler):
    """Handles individual client connections."""
    server: 'SecureChatServer'  # Type hint
    
    def __init__(self, request, client_address, server):
        self.client_id = None
        self.protocol = SecureChatProtocol()
        self.connected = True
        self.key_exchange_complete = False
        
        # Keepalive tracking
        self.last_keepalive_time = time.time()
        self.keepalive_failures = 0
        self.waiting_for_keepalive_response = False
        self.keepalive_thread = None
        
        super().__init__(request, client_address, server)
        
    
    def setup(self):
        """Called before handle() to perform initialization."""
        # Try to add this client to the server
        if not self.server.add_client(self):
            # Server is full, send rejection message and disconnect
            try:
                rejection_message = {
                    "type": MessageType.SERVER_FULL,
                    "message": "Server only supports 2 clients. Connection rejected."
                }
                message_data = json.dumps(rejection_message).encode('utf-8')
                send_message(self.request, message_data)
                print(f"Rejected connection from {self.client_address} - server full")
            except:
                pass
            # Don't call super().setup() to prevent further processing
            return
        
        super().setup()
        
        # Send server version information to the newly connected client
        self.send_server_version_info()
    
    def handle(self):
        """Main client handling loop."""
        # If client wasn't added (server full), don't process
        if self.client_id is None:
            return
        
        try:
            # Start keepalive thread after key exchange is complete
            self.start_keepalive()
            
            while self.connected:
                try:
                    # Receive message from client
                    message_data = receive_message(self.request)
                    
                    if not self.key_exchange_complete:
                        # Handle key exchange messages
                        self.handle_key_exchange(message_data)
                    else:
                        # Check if this is a verification message or keepalive response
                        try:
                            message = json.loads(message_data.decode('utf-8'))
                            message_type = message.get("type")
                            
                            if message_type == MessageType.KEY_VERIFICATION:
                                # Route verification messages
                                self.route_verification_message(message_data)
                            elif message_type == MessageType.KEEP_ALIVE_RESPONSE:
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
                send_message(other_client.request, message_data)
                print(f"Key exchange message (type {message_type}) routed from {self.client_id} to {other_client.client_id}")
                
                # If this is a key exchange response, the key exchange is complete
                if message_type == MessageType.KEY_EXCHANGE_RESPONSE:
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
                send_message(other_client.request, message_data)
                print(f"Key verification message routed from {self.client_id} to {other_client.client_id}")
            else:
                print(f"No other client available to route verification message from {self.client_id}")
                self.server.broadcast_error("Verification failed - no other client")
                
        except Exception as e:
            print(f"Verification routing error for {self.client_id}: {e}")
            self.server.broadcast_error("Verification failed")
    
    def notify_key_exchange_complete(self):
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
                        
            print("Key exchange completion notification sent to all clients")
            
        except Exception as e:
            print(f"Failed to notify key exchange completion: {e}")
    
    def get_other_client(self) -> Optional['SecureChatRequestHandler']:
        """Get the other connected client."""
        with self.server.clients_lock:
            for client_id, client_handler in self.server.clients.items():
                if client_id != self.client_id:
                    return client_handler
        return None
    
    def is_connected(self) -> bool:
        """Check if the client is still connected."""
        return self.connected
    
    def start_keepalive(self):
        """Start the keepalive thread."""
        if self.keepalive_thread is None:
            self.keepalive_thread = threading.Thread(target=self.keepalive_loop)
            self.keepalive_thread.daemon = True
            self.keepalive_thread.start()
    
    def keepalive_loop(self):
        """Keepalive loop to monitor client connection."""
        while self.connected:
            try:
                time.sleep(60)  # Send keepalive every 60 ish seconds
                
                if not self.connected:
                    break
                
            
                self.send_keepalive()
                    
            except Exception as e:
                print(f"Keepalive error for {self.client_id}: {e}")
                break
    
    def send_keepalive(self):
        """Send a keepalive message to the client."""
        try:
            if self.waiting_for_keepalive_response:
                self.keepalive_failures += 1
                if self.keepalive_failures >= 3:
                    print(f"Client {self.client_id} failed to respond to keepalive. Disconnecting.")
                    self.disconnect()
                    return
            
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
            self.disconnect()
    
    def handle_keepalive_response(self, message_data: bytes):
        """Handle keepalive response from client."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            if message.get("type") == MessageType.KEEP_ALIVE_RESPONSE:
                self.waiting_for_keepalive_response = False
                self.keepalive_failures = 0
                
        except Exception as e:
            print(f"Error handling keepalive response from {self.client_id}: {e}")
    
    def send_server_version_info(self):
        """Send protocol version information to the client."""
        try:
            # Create protocol version message (only protocol version, no compatibility matrix or server version)
            version_message = {
                "type": MessageType.SERVER_VERSION_INFO,
                "protocol_version": PROTOCOL_VERSION
            }
            
            message_data = json.dumps(version_message).encode('utf-8')
            send_message(self.request, message_data)
            print(f"Sent protocol version info to {self.client_id}: Protocol v{PROTOCOL_VERSION}")
            
        except Exception as e:
            print(f"Error sending protocol version info to {self.client_id}: {e}")
    
    def disconnect(self):
        """Disconnect the client and clean up."""
        if self.connected:
            self.connected = False
            
            if self.client_id:
                self.server.remove_client(self.client_id)
            
            try:
                self.request.close()
            except: # pylint: disable=bare-except
                pass
            
            if self.client_id:
                print(f"Client {self.client_id} disconnected")


def main():
    try:
        server = SecureChatServer()
        server.start_server()
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    main()