"""
Secure Chat Client with End-to-End Encryption
It uses KRYSTALS KYBER protocol for secure key exchange and message encryption.
"""
# pylint: disable=trailing-whitespace
import socket
import threading
import json
import sys
from shared import SecureChatProtocol, send_message, receive_message, MSG_TYPE_FILE_METADATA, \
    MSG_TYPE_FILE_ACCEPT, MSG_TYPE_FILE_REJECT, MSG_TYPE_FILE_CHUNK, MSG_TYPE_FILE_COMPLETE, MSG_TYPE_KEY_EXCHANGE_RESET

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
        self.receive_thread = None
        
        # File transfer state
        self.pending_file_transfers = {}  # Track outgoing file transfers
        self.active_file_metadata = {}    # Track incoming file metadata
        
    def connect(self):
        """Connect to the chat server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            print(f"Connected to secure chat server at {self.host}:{self.port}")
            print("Waiting for another user to connect...")
            
            # Start receiving thread
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = False  # Non-daemon thread for proper cleanup
            self.receive_thread.start()
            
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
                elif message_type == MSG_TYPE_FILE_METADATA:
                    self.handle_file_metadata(message_data)
                elif message_type == MSG_TYPE_FILE_ACCEPT:
                    self.handle_file_accept(message_data)
                elif message_type == MSG_TYPE_FILE_REJECT:
                    self.handle_file_reject(message_data)
                elif message_type == MSG_TYPE_FILE_CHUNK:
                    self.handle_file_chunk(message_data)
                elif message_type == MSG_TYPE_FILE_COMPLETE:
                    self.handle_file_complete(message_data)
                elif message_type == MSG_TYPE_KEY_EXCHANGE_RESET:
                    self.handle_key_exchange_reset(message_data)
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
            _, ciphertext = self.protocol.process_key_exchange_init(message_data)
            response = self.protocol.create_key_exchange_response(ciphertext)
            
            # Send response back through server
            send_message(self.socket, response)
            
        except Exception as e:
            print(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes):
        """Handle key exchange response from another client."""
        try:
            if hasattr(self, 'private_key'):
                self.protocol.process_key_exchange_response(message_data, self.private_key)
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
                    if response in ['no', 'n']:
                        self.confirm_key_verification(False)
                        
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
    
    def handle_key_exchange_reset(self, message_data: bytes):
        """Handle key exchange reset message when other client disconnects."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            reset_message = message.get("message", "Key exchange reset")
            
            # Reset client state
            self.key_exchange_complete = False
            self.verification_complete = False
            self.protocol.reset_key_exchange()
            
            # Clear any pending file transfers
            self.pending_file_transfers.clear()
            self.active_file_metadata.clear()
            
            # Notify user
            print(f"\n{'='*50}")
            print("⚠️  KEY EXCHANGE RESET")
            print(f"Reason: {reset_message}")
            print("The secure session has been terminated.")
            print("Waiting for a new client to connect...")
            print("A new key exchange will start automatically.")
            print(f"{'='*50}")
            
        except Exception as e:
            print(f"Error handling key exchange reset: {e}")
    
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
    
    def send_file(self, file_path: str):
        """Send a file to the other client."""
        try:
            if not self.verification_complete:
                print("Cannot send file: Key verification not complete")
                return
            
            # Create file metadata message
            metadata_msg = self.protocol.create_file_metadata_message(file_path)
            
            # Store file path for later sending
            metadata = self.protocol.process_file_metadata(metadata_msg)
            transfer_id = metadata["transfer_id"]
            self.pending_file_transfers[transfer_id] = {
                "file_path": file_path,
                "metadata": metadata
            }
            
            # Send metadata to peer
            send_message(self.socket, metadata_msg)
            print(f"File transfer request sent: {metadata['filename']} ({metadata['file_size']} bytes)")
            
        except Exception as e:
            print(f"Failed to send file: {e}")
    
    def handle_file_metadata(self, message_data: bytes):
        """Handle incoming file metadata."""
        try:
            metadata = self.protocol.process_file_metadata(message_data)
            transfer_id = metadata["transfer_id"]
            
            # Store metadata for potential acceptance
            self.active_file_metadata[transfer_id] = metadata
            
            # Prompt user for acceptance
            print(f"\nIncoming file transfer:")
            print(f"  Filename: {metadata['filename']}")
            print(f"  Size: {metadata['file_size']} bytes")
            print(f"  Chunks: {metadata['total_chunks']}")
            
            while True:
                try:
                    response = input("Accept file? (yes/no): ").lower().strip()
                    if response in ['yes', 'y']:
                        # Send acceptance
                        accept_msg = self.protocol.create_file_accept_message(transfer_id)
                        send_message(self.socket, accept_msg)
                        print("File transfer accepted. Waiting for file...")
                        break
                    elif response in ['no', 'n']:
                        # Send rejection
                        reject_msg = self.protocol.create_file_reject_message(transfer_id)
                        send_message(self.socket, reject_msg)
                        print("File transfer rejected.")
                        del self.active_file_metadata[transfer_id]
                        break
                    else:
                        print("Please enter 'yes' or 'no'")
                except (EOFError, KeyboardInterrupt):
                    # Send rejection on interrupt
                    reject_msg = self.protocol.create_file_reject_message(transfer_id)
                    send_message(self.socket, reject_msg)
                    print("File transfer rejected.")
                    del self.active_file_metadata[transfer_id]
                    break
                    
        except Exception as e:
            print(f"Error handling file metadata: {e}")
    
    def handle_file_accept(self, message_data: bytes):
        """Handle file acceptance from peer."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            transfer_id = message["transfer_id"]
            
            if transfer_id not in self.pending_file_transfers:
                print("Received acceptance for unknown file transfer")
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            file_path = transfer_info["file_path"]
            
            print(f"File transfer accepted. Sending {transfer_info['metadata']['filename']}...")
            
            # Start sending file chunks
            self._send_file_chunks(transfer_id, file_path)
            
        except Exception as e:
            print(f"Error handling file acceptance: {e}")
    
    def handle_file_reject(self, message_data: bytes):
        """Handle file rejection from peer."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            transfer_id = message["transfer_id"]
            reason = message.get("reason", "Unknown reason")
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                print(f"File transfer rejected: {filename} - {reason}")
                del self.pending_file_transfers[transfer_id]
            
        except Exception as e:
            print(f"Error handling file rejection: {e}")
    
    def handle_file_chunk(self, message_data: bytes):
        """Handle incoming file chunk."""
        try:
            chunk_info = self.protocol.process_file_chunk(message_data)
            transfer_id = chunk_info["transfer_id"]
            
            if transfer_id not in self.active_file_metadata:
                print("Received chunk for unknown file transfer")
                return
            
            metadata = self.active_file_metadata[transfer_id]
            
            # Add chunk to protocol buffer
            is_complete = self.protocol.add_file_chunk(
                transfer_id,
                chunk_info["chunk_index"],
                chunk_info["chunk_data"],
                metadata["total_chunks"]
            )
            
            # Show progress
            received_chunks = len(self.protocol.received_chunks.get(transfer_id, {}))
            progress = (received_chunks / metadata["total_chunks"]) * 100
            print(f"Receiving {metadata['filename']}: {progress:.1f}% ({received_chunks}/{metadata['total_chunks']} chunks)")
            
            if is_complete:
                # Reassemble file
                import os
                output_path = os.path.join(os.getcwd(), metadata["filename"])
                
                # Handle filename conflicts
                counter = 1
                base_name, ext = os.path.splitext(metadata["filename"])
                while os.path.exists(output_path):
                    output_path = os.path.join(os.getcwd(), f"{base_name}_{counter}{ext}")
                    counter += 1
                
                try:
                    self.protocol.reassemble_file(transfer_id, output_path, metadata["file_hash"])
                    print(f"File received successfully: {output_path}")
                    
                    # Send completion message
                    complete_msg = self.protocol.create_file_complete_message(transfer_id)
                    send_message(self.socket, complete_msg)
                    
                except Exception as e:
                    print(f"File reassembly failed: {e}")
                
                # Clean up
                del self.active_file_metadata[transfer_id]
            
        except Exception as e:
            print(f"Error handling file chunk: {e}")
    
    def handle_file_complete(self, message_data: bytes):
        """Handle file transfer completion notification."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            transfer_id = message["transfer_id"]
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                print(f"File transfer completed: {filename}")
                del self.pending_file_transfers[transfer_id]
            
        except Exception as e:
            print(f"Error handling file completion: {e}")
    
    def _send_file_chunks(self, transfer_id: str, file_path: str):
        """Send file chunks to peer."""
        try:
            chunks = self.protocol.chunk_file(file_path)
            total_chunks = len(chunks)
            
            for i, chunk in enumerate(chunks):
                chunk_msg = self.protocol.create_file_chunk_message(transfer_id, i, chunk)
                send_message(self.socket, chunk_msg)
                
                # Show progress
                progress = ((i + 1) / total_chunks) * 100
                print(f"Sending: {progress:.1f}% ({i + 1}/{total_chunks} chunks)")
            
            print("File chunks sent successfully.")
            
        except Exception as e:
            print(f"Error sending file chunks: {e}")
    
    def start_chat(self):
        """Start the interactive chat interface."""
        if not self.connected:
            print("Not connected to server")
            return
            
        print("Secure Chat Client")
        print("==================")
        print("Commands:")
        print("  /quit - Exit the chat")
        print("  /verify - Start key verification")
        print("  /file <path> - Send a file")
        print("  /help - Show this help message")
        print()
        
        try:
            while self.connected:
                if self.key_exchange_complete and self.verification_complete:
                    try:
                        message = input()
                        if message.lower() == '/quit':
                            break
                        elif message.lower() == '/verify':
                            self.start_key_verification()
                        elif message.lower() == '/help':
                            print("Commands:")
                            print("  /quit - Exit the chat")
                            print("  /verify - Start key verification")
                            print("  /file <path> - Send a file")
                            print("  /help - Show this help message")
                        elif message.lower().startswith('/file '):
                            file_path = message[6:].strip()
                            if file_path:
                                self.send_file(file_path)
                            else:
                                print("Usage: /file <path>")
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
            
            # Wait for receive thread to finish cleanly
            if self.receive_thread and self.receive_thread.is_alive():
                try:
                    self.receive_thread.join(timeout=2.0)  # Wait up to 2 seconds
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
    