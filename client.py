"""
Secure Chat Client with End-to-End Encryption
It uses KRYSTALS KYBER protocol for secure key exchange and message encryption.
"""
# pylint: disable=trailing-whitespace
import socket
import threading
import json
import sys
import os
import time

from shared import SecureChatProtocol, send_message, receive_message, MessageType, PROTOCOL_VERSION


# noinspection PyUnresolvedReferences,PyBroadException
class SecureChatClient:
    
    def __init__(self, host='localhost', port=16384):
        """The secure chat client.
        
        Args:
            host (str, optional): The server hostname or IP address to connect to. 
                Defaults to 'localhost'.
            port (int, optional): The server port number to connect to. 
                Defaults to 16384.
        
        Attributes:
            host (str): Server hostname or IP address.
            port (int): Server port number.
            socket (socket.socket): The client socket connection.
            protocol (SecureChatProtocol): The encryption protocol handler.
            connected (bool): Whether the client is connected to the server.
            key_exchange_complete (bool): Whether key exchange has been completed.
            verification_complete (bool): Whether key verification has been completed.
            username (str): The client's username (currently unused).
            receive_thread (threading.Thread): Thread for receiving messages.
            pending_file_transfers (dict): Tracks outgoing file transfers by transfer ID.
            active_file_metadata (dict): Tracks incoming file metadata by transfer ID.
        """
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
        self.pending_file_transfers: dict = {}  # Track outgoing file transfers
        self.active_file_metadata = {}    # Track incoming file metadata
        self._last_progress_shown = {}    # Track file transfer progress display
        
        # Key exchange state
        self.private_key = None  # Private key for key exchange
        
        # Server version information
        self.server_version = None
        self.server_protocol_version = None
        self.server_compatible_versions = None
        
    def connect(self) -> bool:
        """Connect to the chat server and start the message receiving thread.
        
        Establishes a TCP socket connection to the server, sets the connected state,
        and starts a background thread to handle incoming messages.
        
        Returns:
            bool: True if connection was successful, False otherwise.
            
        Note:
            This method will print connection status messages to stdout.
            The receiving thread is started as a non-daemon thread for proper cleanup.
        """
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
    
    def receive_messages(self) -> None:
        """Continuously receive and handle messages from the server.
        
        This method runs in a separate thread and continuously listens for incoming
        messages from the server. It handles connection errors gracefully and ensures
        proper cleanup by calling disconnect() when the loop exits.
        
        Note:
            This method is designed to run in a background thread. It will continue
            running until the connection is lost or an error occurs. All exceptions
            are caught and logged to prevent the thread from crashing.
        """
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
    
    def handle_message(self, message_data: bytes) -> None:
        """Handle different types of messages received from the server.

        This method acts as a message dispatcher, parsing incoming messages and
        routing them to appropriate handler methods based on the message type.

        Args:
            message_data (bytes): Raw message data received from the server.

        Note:
            Messages can be either JSON-encoded (for control messages) or binary
            (for optimized file chunks). The method first tries JSON parsing for
            control messages (including keepalives), then falls back to binary
            file chunk processing if JSON parsing fails.

            All exceptions are caught and logged to prevent crashes.
        """
        try:
            # First, try to parse as JSON (for control messages including keepalive)
            # This is more efficient for frequent messages like keepalives
            try:
                message = json.loads(message_data.decode('utf-8'))
                message_type = MessageType(message.get("type"))
                
                if message_type == MessageType.KEY_EXCHANGE_INIT:
                    self.handle_key_exchange_init(message_data)
                elif message_type == MessageType.KEY_EXCHANGE_RESPONSE:
                    self.handle_key_exchange_response(message_data)
                elif message_type == MessageType.ENCRYPTED_MESSAGE:
                    if self.key_exchange_complete:
                        self.handle_encrypted_message(message_data)
                    else:
                        print("\nReceived encrypted message before key exchange complete")
                elif message_type == MessageType.ERROR:
                    print(f"\nServer error: {message.get('error', 'Unknown error')}")
                elif message_type == MessageType.KEY_VERIFICATION:
                    self.handle_key_verification_message(message_data)
                elif message_type == MessageType.KEY_EXCHANGE_RESET:
                    self.handle_key_exchange_reset(message_data)
                elif message_type == MessageType.KEEP_ALIVE:
                    self.handle_keepalive()
                elif message_type == MessageType.KEY_EXCHANGE_COMPLETE:
                    self.handle_key_exchange_complete()
                elif message_type == MessageType.INITIATE_KEY_EXCHANGE:
                    self.initiate_key_exchange()
                elif message_type == MessageType.SERVER_FULL:
                    self.handle_server_full()
                elif message_type == MessageType.SERVER_VERSION_INFO:
                    self.handle_server_version_info(message_data)
                else:
                    print(f"\nUnknown message type: {message_type}")
                return  # Successfully processed as JSON message
            
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Not a JSON message, try binary file chunk processing
                pass
            
            # If JSON parsing failed, check if this might be a binary file chunk message
            # Binary file chunks start with a 12-byte nonce and are not UTF-8 decodable
            if len(message_data) >= 12 and self.key_exchange_complete:
                try:
                    # Try to process as binary file chunk
                    result = self.protocol.process_file_chunk(message_data)
                    self.handle_file_chunk_binary(result)
                    return
                except Exception:
                    # Not a binary file chunk either
                    pass
            
            # If we reach here, the message could not be processed
            print("\nReceived a message that could not be decoded.")
        
        except Exception as e:
            print(f"\nError handling message: {e}")
            
    def handle_keepalive(self) -> None:
        """Handle keepalive messages from the server.
        """
        try:
            # Create keepalive response message
            response_message = {
                "version": PROTOCOL_VERSION,
                "type": MessageType.KEEP_ALIVE_RESPONSE
            }
            response_data = json.dumps(response_message).encode('utf-8')
            
            # Send response to server
            send_message(self.socket, response_data)
            
        except Exception as e:
            print(f"\nError handling keepalive: {e}")
    
    def handle_delivery_confirmation(self, message: str) -> None:
        """Handle delivery confirmation messages from the peer.
        
        Args:
            message (str): The decrypted delivery confirmation message.
        """
        try:
            confirmation = json.loads(decrypted_text).get("confirmed_counter")
            print(f"\n✓ Message {confirmed_counter} delivered")
            
        except Exception as e:
            print(f"\nError handling delivery confirmation: {e}")
    
    def initiate_key_exchange(self) -> None:
        """Initiate the key exchange process as the first client.
        
        Generates a new keypair using the ML-KEM-1024 algorithm, creates a key
        exchange initialization message, and sends it to the server to be routed
        to the other client.
        
        Note:
            This method is called when this client is designated as the initiator
            of the key exchange process. The generated private key is stored in
            self.private_key for later use in processing the response.
            
        Raises:
            Exception: If key generation or message sending fails.
        """
        try:
            # Generate keypair
            public_key, self.private_key = self.protocol.generate_keypair()
            
            # Create key exchange init message
            init_message = self.protocol.create_key_exchange_init(public_key)
            
            # Send to server (which will route to other client)
            send_message(self.socket, init_message)
            
        except Exception as e:
            print(f"Failed to initiate key exchange: {e}")

    def handle_key_exchange_init(self, message_data: bytes) -> None:
        """Handle key exchange initiation from another client.
        
        This method processes the key exchange initialization message received
        from the server, extracts the ciphertext, and creates a response message
        to send back to the server.
        
        Args:
            message_data (bytes): The raw key exchange initialization message data.
            
        Note:
            This method is called when this client receives a key exchange init
            message from the server, indicating that another client has initiated
            the key exchange process.
            It expects the message to contain the ciphertext that needs to be processed.
            The response will be sent back to the server to continue the key exchange.
        """
        try:
            _, ciphertext, version_warning = self.protocol.process_key_exchange_init(message_data)
            
            # Display version warning if present
            if version_warning:
                print(f"\n{version_warning}")
                
            response = self.protocol.create_key_exchange_response(ciphertext)
            
            # Send response back through server
            send_message(self.socket, response)
            
        except Exception as e:
            print(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes) -> None:
        """Handle key exchange response from another client."""
        try:
            if self.private_key is not None:
                _, version_warning = self.protocol.process_key_exchange_response(message_data, self.private_key)
                
                # Display version warning if present
                if version_warning:
                    print(f"\n{version_warning}")
                    
                print("Key exchange completed successfully.")
            else:
                print("Received key exchange response but no private key found")
                
        except Exception as e:
            print(f"Key exchange response error: {e}")
    
    def handle_key_exchange_complete(self) -> None:
        """Handle key exchange completion notification."""
        self.key_exchange_complete = True
        self.start_key_verification()
    
    def start_key_verification(self) -> None:
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
    
    def confirm_key_verification(self, verified: bool) -> None:
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
            
            # Start the sender thread for message queuing
            self.protocol.start_sender_thread(self.socket)
            
            print("\nYou can now start chatting!")
            print("Type your messages and press Enter to send.")
            print("Type '/quit' to exit.")
            print("Type '/verify' to re-verify keys at any time.\n")
            
        except Exception as e:
            print(f"Error confirming verification: {e}")
    
    def handle_key_verification_message(self, message_data: bytes) -> None:
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
    
    
    def display_regular_message(self, message: str, error=False) -> None:
        """Display a regular chat message."""
        if error:
            print(f"\nError: {message}")
        else:
            print(f"\nOther user: {message}")
    
    def handle_encrypted_message(self, message_data: bytes) -> None:
        """Handle encrypted chat messages."""
        try:
            decrypted_text = self.protocol.decrypt_message(message_data)
            
            # Get the message counter that was just processed for delivery confirmation
            received_message_counter = self.protocol.peer_counter
            
            # Attempt to parse the decrypted text as a JSON message
            try:
                message_type: int = json.loads(decrypted_text).get("type")
                
                match message_type:
                    case MessageType.EMERGENCY_CLOSE:
                        self.handle_emergency_close(message_data)
                    case MessageType.DUMMY_MESSAGE:
                        # This is a dummy message, ignore it
                        pass
                    case MessageType.FILE_METADATA:
                        self.handle_file_metadata(decrypted_text)
                    case MessageType.FILE_ACCEPT:
                        self.handle_file_accept(decrypted_text)
                    case MessageType.FILE_REJECT:
                        self.handle_file_reject(decrypted_text)
                    case MessageType.FILE_COMPLETE:
                        self.handle_file_complete(decrypted_text)
                    case MessageType.DELIVERY_CONFIRMATION:
                        if self.key_exchange_complete:
                            self.handle_delivery_confirmation(decrypted_text)
                    case _:
                        # It's a regular chat message if it's not a file-related type
                        self.display_regular_message(decrypted_text)
                        self._send_delivery_confirmation(received_message_counter)
            
            except (json.JSONDecodeError, TypeError):
                # If it's not JSON, it's a regular chat message
                self.display_regular_message(decrypted_text)
                # Send delivery confirmation for text messages only
                self._send_delivery_confirmation(received_message_counter)
            
        except Exception as e:
            self.display_regular_message(str(e), error=True)
    
    def _send_delivery_confirmation(self, confirmed_counter: int) -> None:
        """Send a delivery confirmation for a received text message."""
        print("delivery confirmation sent, client.py")
        try:
            confirmation_data = self.protocol.create_delivery_confirmation_message(confirmed_counter)
            send_message(self.socket, confirmation_data)
        except Exception as e:
            print(f"\nError sending delivery confirmation: {e}")
    
    def handle_key_exchange_reset(self, message_data: bytes) -> None:
        """Handle key exchange reset message when the other client disconnects."""
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
    
    def send_emergency_close(self) -> None:
        """Send an emergency close message to notify the other client.
        
        Uses a pre-encrypted emergency close message for immediate sending,
        bypassing the queue system. The message is encrypted so the server
        cannot detect that it's an emergency close.
        """
        try:
            # Use the protocol's emergency close method that bypasses the queue
            if self.protocol.send_emergency_close():
                return
                
            # Fallback to unencrypted emergency close if pre-encrypted message fails
            emergency_message = {
                "version": PROTOCOL_VERSION,
                "type": MessageType.EMERGENCY_CLOSE,
            }
            message_data = json.dumps(emergency_message).encode('utf-8')
            send_message(self.socket, message_data)
        except Exception:
            return
    
    def handle_emergency_close(self, message_data: bytes) -> None:
        """Handle emergency close message from the other client."""
        try:
            print(f"\n{'='*50}")
            print("EMERGENCY CLOSE RECEIVED")
            print("The other client has activated emergency close.")
            print("Connection will be terminated immediately.")
            print(f"{'='*50}")
            
            # Immediately disconnect
            self.disconnect()
            self.key_exchange_complete = False
            self.verification_complete = False
            self.protocol.reset_key_exchange()
            
            # Clear any pending file transfers
            self.pending_file_transfers.clear()
            self.active_file_metadata.clear()
            
        except Exception as e:
            print(f"Error handling emergency close: {e}")
    
    def send_message(self, text: str) -> bool | None:
        """Encrypt and queue a chat message for sending."""
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
            self.protocol.queue_message(encrypted_data)
            return True
            
        except Exception as e:
            print(f"Failed to send message: {e}")
            return None
    
    def send_file(self, file_path: str, compress: bool = True) -> None:
        """Send a file to the other client."""
        try:
            if not self.verification_complete:
                print("Cannot send file: Key verification not complete")
                return

            # Create file metadata message
            metadata_msg, metadata = self.protocol.create_file_metadata_message(file_path, return_metadata=True, compress=compress)
            
            # Store file path for later sending
            transfer_id = metadata["transfer_id"]
            self.pending_file_transfers[transfer_id] = {
                "file_path": file_path,
                "metadata": metadata,
                "compress": compress
            }
            
            # Send metadata to peer
            send_message(self.socket, metadata_msg)
            compression_text = "compressed" if compress else "uncompressed"
            print(f"File transfer request sent: {metadata['filename']} ({metadata['file_size']} bytes, {compression_text})")
            
        except Exception as e:
            print(f"Failed to send file: {e}")
    
    def handle_file_metadata(self, decrypted_message: str) -> None:
        """Handle incoming file metadata."""
        try:
            metadata = self.protocol.process_file_metadata(decrypted_message)
            transfer_id = metadata["transfer_id"]
            
            # Store metadata for potential acceptance
            self.active_file_metadata[transfer_id] = metadata
            
            # Prompt user for acceptance
            print("\nIncoming file transfer:")
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
                        
                    elif response in ['no', 'n']:
                        # Send rejection
                        reject_msg = self.protocol.create_file_reject_message(transfer_id)
                        send_message(self.socket, reject_msg)
                        print("File transfer rejected.")
                        del self.active_file_metadata[transfer_id]
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
    
    def handle_file_accept(self, decrypted_message: str) -> None:
        """Handle file acceptance from peer."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id not in self.pending_file_transfers:
                print("Received acceptance for unknown file transfer")
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            file_path = transfer_info["file_path"]
            
            print(f"File transfer accepted. Sending {transfer_info['metadata']['filename']}...")
            
            # Start tracking the sending transfer in the protocol
            self.protocol.start_sending_transfer(transfer_id, transfer_info['metadata'])
            
            # Start sending file chunks in a separate thread to avoid blocking message processing
            chunk_thread = threading.Thread(
                target=self._send_file_chunks,
                args=(transfer_id, file_path),
                daemon=True
            )
            chunk_thread.start()
            
        except Exception as e:
            print(f"Error handling file acceptance: {e}")
    
    def handle_file_reject(self, decrypted_message: str) -> None:
        """Handle file rejection from peer."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            reason = message.get("reason", "Unknown reason")
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                print(f"File transfer rejected: {filename} - {reason}")
                # Clean up transfer tracking
                self.protocol.stop_sending_transfer(transfer_id)
                del self.pending_file_transfers[transfer_id]
            
        except Exception as e:
            print(f"Error handling file rejection: {e}")
    
    
    def handle_file_chunk_binary(self, chunk_info: dict) -> None:
        """Handle incoming file chunk (optimized binary format)."""
        try:
            self._process_file_chunk_common(chunk_info)
            
        except Exception as e:
            print(f"Error handling binary file chunk: {e}")
    
    def _process_file_chunk_common(self, chunk_info: dict) -> None:
        """Common file chunk processing logic for both JSON and binary formats."""
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
        
        # Show progress - but only at significant intervals to avoid console spam
        received_chunks = len(self.protocol.received_chunks.get(transfer_id, set()))
        progress = (received_chunks / metadata["total_chunks"]) * 100
        
        # Initialize progress tracking for this transfer if not exists
        if transfer_id not in self._last_progress_shown:
            self._last_progress_shown[transfer_id] = -1
        
        # Only show progress every 10% or on completion to reduce console interference
        if (progress - self._last_progress_shown[transfer_id] >= 10 or 
            is_complete or 
            received_chunks == 1):  # Always show first chunk
            print(f"Receiving {metadata['filename']}: {progress:.1f}% ({received_chunks}/{metadata['total_chunks']} chunks)")
            self._last_progress_shown[transfer_id] = progress
        
        if is_complete:
            # Reassemble file
            output_path = os.path.join(os.getcwd(), metadata["filename"])
            
            # Handle filename conflicts
            counter = 1
            base_name, ext = os.path.splitext(metadata["filename"])
            while os.path.exists(output_path):
                output_path = os.path.join(os.getcwd(), f"{base_name}_{counter}{ext}")
                counter += 1
            
            try:
                # Get compression status from metadata
                compressed = metadata.get("compressed", True)  # Default to compressed for backward compatibility
                self.protocol.reassemble_file(transfer_id, output_path, metadata["file_hash"], compressed=compressed)
                
                compression_text = "compressed" if compressed else "uncompressed"
                print(f"File received successfully ({compression_text}): {output_path}")
                
                # Send the completion message
                complete_msg = self.protocol.create_file_complete_message(transfer_id)
                send_message(self.socket, complete_msg)
                
            except Exception as e:
                print(f"File reassembly failed: {e}")
            
            # Clean up
            del self.active_file_metadata[transfer_id]
            
            # Clean up progress tracking
            if transfer_id in self._last_progress_shown:
                del self._last_progress_shown[transfer_id]
    
    def handle_file_complete(self, decrypted_message: str) -> None:
        """Handle file transfer completion notification."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                print(f"File transfer completed: {filename}")
                del self.pending_file_transfers[transfer_id]
            
            
        except Exception as e:
            print(f"Error handling file completion: {e}")
    
    def handle_server_full(self) -> None:
        """Handle server full notification."""
        print("\n⚠️ Server is full. Cannot connect at this time.")
        print("Please try again later or contact the server administrator.")
        self.disconnect()
    
    def handle_server_version_info(self, message_data: bytes) -> None:
        """Handle server version information."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            
            # Store server protocol version information
            self.server_protocol_version = message.get("protocol_version")
            
            print(f"\n📡 Server Protocol Version: v{self.server_protocol_version}")
            
            # Check compatibility using local compatibility matrix from shared.py
            if self.server_protocol_version != PROTOCOL_VERSION:
                print(f"⚠️ Protocol version mismatch: Client v{PROTOCOL_VERSION}, Server v{self.server_protocol_version}")
                # Use local compatibility matrix since server no longer sends it
                from shared import PROTOCOL_COMPATIBILITY
                client_compatible_versions = PROTOCOL_COMPATIBILITY.get(PROTOCOL_VERSION, [PROTOCOL_VERSION])
                if self.server_protocol_version in client_compatible_versions:
                    print("✅ Versions are compatible for communication")
                else:
                    print("❌ Versions may not be compatible - communication issues possible")
            else:
                print("✅ Protocol versions match")
                
        except Exception as e:
            print(f"Error handling server version info: {e}")
    
    def _send_file_chunks(self, transfer_id: str, file_path: str) -> None:
        """Send file chunks to peer."""
        try:
            # Get transfer info including compression setting
            transfer_info = self.pending_file_transfers[transfer_id]
            total_chunks = transfer_info["metadata"]["total_chunks"]
            compress = transfer_info.get("compress", True)  # Default to compressed for backward compatibility
            
            chunk_generator = self.protocol.chunk_file(file_path, compress=compress)
            
            for i, chunk in enumerate(chunk_generator):
                chunk_msg = self.protocol.create_file_chunk_message(transfer_id, i, chunk)
                send_message(self.socket, chunk_msg)
                
                # Show progress
                progress = ((i + 1) / total_chunks) * 100
                compression_text = "compressed" if compress else "uncompressed"
                print(f"Sending ({compression_text}): {progress:.1f}% ({i + 1}/{total_chunks} chunks)")
            
            print("File chunks sent successfully.")
            
            # Stop tracking the sending transfer
            self.protocol.stop_sending_transfer(transfer_id)
            
        except Exception as e:
            print(f"Error sending file chunks: {e}")
            # Stop tracking on error as well
            self.protocol.stop_sending_transfer(transfer_id)
    
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
                        if message.lower() == '/verify':
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
                    time.sleep(0.1)
                    
        except Exception as e:
            print(f"Chat error: {e}")
        finally:
            self.disconnect()
    
    def disconnect(self) -> None:
        """Disconnect from the server."""
        if self.connected:
            self.connected = False
            
            # Stop the sender thread first
            self.protocol.stop_sender_thread()
            
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

def main() -> None:
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
