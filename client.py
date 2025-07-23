# client.py - Secure chat client
import socket
import threading
import json
import sys
from shared import SecureChatProtocol, send_message, receive_message

class SecureChatClient:
    """Secure chat client with end-to-end encryption."""
    
    def __init__(self, host='localhost', port=16384):
        self.host = host
        self.port = port
        self.socket = None
        self.protocol = SecureChatProtocol()
        self.connected = False
        self.key_exchange_complete = False
        self.verification_complete = False
        self.username = ""
        
    def connect(self):
        """Connect to the chat server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            print(f"Connected to secure chat server at {self.host}:{self.port}")
            print("Waiting for another user to connect...")
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            return True
            
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            return False
    
    def receive_messages(self):
        """Receive and handle messages from the server."""
        try:
            while self.connected:
                try:
                    message_data = receive_message(self.socket)
                    self.handle_message(message_data)
                    
                except ConnectionError:
                    print("\nConnection to server lost.")
                    break
                except Exception as e:
                    print(f"\nError receiving message: {e}")
                    break
                    
        except Exception as e:
            print(f"Receive thread error: {e}")
        finally:
            self.disconnect()
    
    def handle_message(self, message_data: bytes):
        """Handle different types of messages from the server."""
        try:
            # Try to parse as JSON first (for control messages)
            try:
                message = json.loads(message_data.decode('utf-8'))
                message_type = message.get("type")
                
                if message_type == 1:  # MSG_TYPE_KEY_EXCHANGE_INIT
                    self.handle_key_exchange_init(message_data)
                elif message_type == 2:  # MSG_TYPE_KEY_EXCHANGE_RESPONSE
                    self.handle_key_exchange_response(message_data)
                elif message_type == 3:  # MSG_TYPE_ENCRYPTED_MESSAGE
                    if self.key_exchange_complete:
                        self.handle_encrypted_message(message_data)
                    else:
                        print("\nReceived encrypted message before key exchange complete")
                elif message_type == 4:  # MSG_TYPE_ERROR
                    print(f"\nServer error: {message.get('error', 'Unknown error')}")
                elif message_type == 5:  # MSG_TYPE_KEY_VERIFICATION
                    self.handle_key_verification_message(message_data)
                elif message.get("type") == "key_exchange_complete":
                    self.handle_key_exchange_complete(message)
                elif message.get("type") == "initiate_key_exchange":
                    self.initiate_key_exchange()
                else:
                    print(f"\nUnknown message type: {message_type}")
                    
            except (json.JSONDecodeError, UnicodeDecodeError):
                # This case should ideally not be hit for valid protocol messages
                print("\nReceived a message that could not be decoded.")
                
        except Exception as e:
            print(f"\nError handling message: {e}")
    
    def initiate_key_exchange(self):
        """Initiate key exchange as the first client."""
        try:
            # Generate keypair
            public_key, self.private_key = self.protocol.generate_keypair()
            
            # Create key exchange init message
            init_message = self.protocol.create_key_exchange_init(public_key)
            
            # Send to server (which will route to other client)
            send_message(self.socket, init_message)
            
        except Exception as e:
            print(f"Failed to initiate key exchange: {e}")

    def handle_key_exchange_init(self, message_data: bytes):
        """Handle key exchange initiation from another client."""
        try:
            shared_secret, ciphertext = self.protocol.process_key_exchange_init(message_data)
            response = self.protocol.create_key_exchange_response(ciphertext)
            
            # Send response back through server
            send_message(self.socket, response)
            
        except Exception as e:
            print(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes):
        """Handle key exchange response from another client."""
        try:
            if hasattr(self, 'private_key'):
                shared_secret = self.protocol.process_key_exchange_response(message_data, self.private_key)
                print("Key exchange completed successfully.")
            else:
                print("Received key exchange response but no private key found")
                
        except Exception as e:
            print(f"Key exchange response error: {e}")
    
    def handle_key_exchange_complete(self, message: dict):
        """Handle key exchange completion notification."""
        self.key_exchange_complete = True
        self.start_key_verification()
    
    def start_key_verification(self):
        """Start the key verification process."""
        try:
            
            # Display session fingerprint (same for both users)
            print("\nSession fingerprint:")
            print("-"*40)
            session_fingerprint = self.protocol.get_own_key_fingerprint()
            print(session_fingerprint)
            
            print("\nINSTRUCTIONS:")
            print("1. Compare the fingerprint above with the other person through a")
            print("   secure channel (phone call, in-person, secure messaging)")
            print("2. Both users should see the SAME fingerprint")
            print("3. Only confirm if you both see identical fingerprints!")
            print("4. If the fingerprints don't match, there may be a security issue")
            
            # Prompt for verification
            while True:
                try:
                    response = input("\nDo the fingerprints match? (yes/no): ").lower().strip()
                    if response in ['yes', 'y']:
                        self.confirm_key_verification(True)
                        break
                    elif response in ['no', 'n']:
                        self.confirm_key_verification(False)
                        break
                    else:
                        print("Please enter 'yes', 'y' or 'no', 'n'")
                except (EOFError, KeyboardInterrupt):
                    print("\nVerification cancelled. Connection will be insecure.")
                    self.confirm_key_verification(False)
                    break
                    
        except Exception as e:
            print(f"Error during key verification: {e}")
            self.confirm_key_verification(False)
    
    def confirm_key_verification(self, verified: bool):
        """Confirm the key verification result."""
        try:
            # Update local verification status
            self.protocol.verify_peer_key(verified)
            
            # Send verification status to peer
            verification_message = self.protocol.create_key_verification_message(verified)
            send_message(self.socket, verification_message)
            
            if verified:
                print("\n✓ Key verification successful!")
            else:
                print("\nKey verification failed or declined")
                print("Communication will proceed but may not be secure.")
            
            self.verification_complete = True
            print("\nYou can now start chatting!")
            print("Type your messages and press Enter to send.")
            print("Type '/quit' to exit.")
            print("Type '/verify' to re-verify keys at any time.\n")
            
        except Exception as e:
            print(f"Error confirming verification: {e}")
    
    def handle_key_verification_message(self, message_data: bytes):
        """Handle key verification message from peer."""
        try:
            verification_info = self.protocol.process_key_verification_message(message_data)
            peer_verified = verification_info["verified"]
            
            if peer_verified:
                print("\n✓ Peer has verified your key successfully.")
            else:
                print("\nPeer has NOT verified your key.")
            
        except Exception as e:
            print(f"Error handling verification message: {e}")
    
    def handle_encrypted_message(self, message_data: bytes):
        """Handle encrypted chat messages."""
        try:
            decrypted_text = self.protocol.decrypt_message(message_data)
            print(f"\nOther user: {decrypted_text}")
            
        except Exception as e:
            print(f"\nFailed to decrypt message: {e}")
    
    def send_message(self, text: str):
        """Encrypt and send a chat message."""
        if not self.key_exchange_complete:
            print("Cannot send messages - key exchange not complete")
            return False
        
        # Check verification status and warn user
        allowed, status_msg = self.protocol.should_allow_communication()
        if not allowed:
            print(f"Cannot send message: {status_msg}")
            return False
        
        if not self.protocol.is_peer_key_verified():
            print("Sending message to unverified peer")
            
        try:
            encrypted_data = self.protocol.encrypt_message(text)
            send_message(self.socket, encrypted_data)
            return True
            
        except Exception as e:
            print(f"Failed to send message: {e}")
            return False
    
    def start_chat(self):
        """Start the interactive chat interface."""
        if not self.connected:
            print("Not connected to server")
            return
            
        print("Secure Chat Client")
        print("==================")
        
        try:
            while self.connected:
                if self.key_exchange_complete and self.verification_complete:
                    try:
                        message = input()
                        if message.lower() == '/quit':
                            break
                        elif message.lower() == '/verify':
                            self.start_key_verification()
                        elif message.strip():
                            if self.send_message(message):
                                if self.protocol.is_peer_key_verified():
                                    print(f"You: {message}")
                                else:
                                    print(f"You (unverified): {message}")
                    except KeyboardInterrupt:
                        break
                    except EOFError:
                        break
                else:
                    # Wait for key exchange and verification to complete
                    import time
                    time.sleep(0.1)
                    
        except Exception as e:
            print(f"Chat error: {e}")
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Disconnect from the server."""
        if self.connected:
            self.connected = False
            try:
                if self.socket:
                    self.socket.close()
            except:
                pass
            print("\nDisconnected from server.")

def main():
    """Main function to run the secure chat client."""
    print("Secure Chat Client")
    print("==================")
    
    # Get server details (handle non-interactive mode)
    try:
        host = input("Enter server host (default: localhost): ").strip()
        if not host:
            host = 'localhost'
    except EOFError:
        # Non-interactive mode, use defaults
        host = 'localhost'
        print("Using default host: localhost")
    
    try:
        port_input = input("Enter server port (default: 16384): ").strip()
        if port_input:
            try:
                port = int(port_input)
            except ValueError:
                print("Invalid port number, using default 16384")
                port = 16384
        else:
            port = 16384
    except EOFError:
        # Non-interactive mode, use defaults
        port = 16384
        print("Using default port: 16384")
    
    # Create and connect client
    client = SecureChatClient(host, port)
    
    if client.connect():
        try:
            client.start_chat()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            client.disconnect()
    else:
        print("Failed to connect to server")
        sys.exit(1)

if __name__ == "__main__":
    main()