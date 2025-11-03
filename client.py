"""
Secure Chat Client with End-to-End Encryption
It uses KRYSTALS KYBER protocol + X25519 for secure key exchange and message encryption.
"""
# pylint: disable=trailing-whitespace, broad-exception-caught
import socket
import string
import threading
import json
import sys
import os
import time
from copy import deepcopy
from typing import Any

import shared
from shared import (SecureChatProtocol, send_message, receive_message, MessageType,
                    PROTOCOL_VERSION, FileMetadata)


# noinspection PyBroadException
class SecureChatClient:
    def __init__(self, host: str = 'localhost', port: int = 16384):
        """
        The SecureChatClient handles client-side operations for a secure chat application.

        This class is responsible for managing the client-server communication, ensuring
        secure data transmission through protocol adherence, and managing user-related
        functionalities like file transfer, voice calls, and key exchange procedures.
        It maintains the state of the connection, user permissions, and ongoing
        operations such as file transfers and audio sessions.
        
        Args:
            host (str, optional): The server hostname or IP address to connect to. 
                Defaults to 'localhost'.
            port (int, optional): The server port number to connect to. 
                Defaults to 16384.
        
        A guaranteed attribute is an attribute that is guaranteed to exist and have a valid value.
        This means that the value of the attribute is always correct and can be safely used.
        
        Guaranteed Attributes:
            host (str): The hostname or IP address of the server.
            port (int): The port number of the server.
            protocol (SecureChatProtocol): The secure chat protocol instance.
            connected (bool): Whether the client is connected to the server.
            key_exchange_complete (bool): Whether the key exchange is complete.
            verification_complete (bool): Whether the key verification is complete.
            peer_nickname (str): The nickname of the peer.
            nickname_change_allowed (bool): Whether the peer nickname can be changed.
            allow_file_transfers (bool): Whether file transfers are allowed.
            send_delivery_receipts (bool): Whether delivery receipts are sent.
            voice_call_active (bool): Whether a voice call is active.
        
        Unsafe attributes are attributes that may not have a valid value.
        These may be None, empty, or have invalid values.
        They will default to whatever an "empty" value would be.
        
        Unsafe Attributes:
            socket (socket.socket): The socket instance.
            receive_thread (threading.Thread): The receiving thread.
            pending_file_transfers (dict[str, dict[str, FileMetadata | bool | str]]): A dictionary of pending file
            transfers and their metadata.
            active_file_metadata (dict[str, FileMetadata]): A dictionary of active file transfers and their metadata.
            _last_progress_shown (dict[str, float | int]): A dictionary of file transfers and their last progress shown.
            private_key (bytes): The private key used for key exchange. Defaults to an empty byte string.
            server_protocol_version (str): The protocol version of the server. Defaults to "0.0.0".
            _rl_window_start (float): The timestamp at the start of the rate-limiting window.
            _rl_count (int): The number of messages received in the rate-limiting window.
        """
        # Connection configuration
        self.host: str = host
        self.port: int = port
        self.socket: socket.socket = socket.socket()
        
        # Protocol/crypto engine
        self.protocol: SecureChatProtocol = SecureChatProtocol()
        
        # Threads
        self.receive_thread: threading.Thread | None = None
        
        # Session state flags
        self.connected: bool = False
        self.key_exchange_complete: bool = False
        self.verification_complete: bool = False
        
        # Peer identity and permissions
        self.peer_nickname: str = "Other user"
        self.nickname_change_allowed: bool = self.protocol.config["peer_nickname_change"]
        
        # Feature toggles/preferences
        self.allow_file_transfers: bool = True
        self.send_delivery_receipts: bool = True
        
        # Voice call state
        self.voice_call_active: bool = False
        
        # File transfer state
        self.pending_file_transfers: dict[str, dict[str, FileMetadata | bool | str]] = {}
        self.active_file_metadata: dict[str, FileMetadata] = {}
        self._last_progress_shown: dict[str, float | int] = {}
        
        # Key exchange state
        self.private_key: bytes = bytes()
        
        # Server version information
        self.server_protocol_version: str = "0.0.0"
        
        # Rate limiting (pre-verification)
        self._rl_window_start: float = 0.0
        self._rl_count: int = 0
    
    @property
    def file_transfer_active(self) -> bool:
        """Whether any file transfers are currently in progress."""
        return bool(self.pending_file_transfers or self.active_file_metadata)
    
    @property
    def bypass_unverified_limits(self) -> bool:
        """Whether to bypass the rate-limiting and file size restrictions for unverified peers.
        Bypass during file transfer, voice call, or an in-progress rekey handshake to avoid
        dropping legitimate control bursts from unverified peers.
        """
        return bool(self.file_transfer_active or self.voice_call_active or self.protocol.rekey_in_progress)
    
    def close_audio(self):
        pass
        
    @staticmethod
    def _sanitize_field_name(field: str) -> str:
        """Return ASCII-only field name truncated to 32 chars; fallback to '?' if empty."""
        try:
            s = str(field)
        except Exception:
            s = repr(field)
        try:
            s_ascii = s.encode('ascii', errors='ignore').decode('ascii', errors='ignore')
        except Exception:
            s_ascii = s
        if len(s_ascii) > 32:
            s_ascii = s_ascii[:32]
        return s_ascii or "?"
        
    def _first_unexpected_field(self, obj: dict[str, Any], allowed: set[str]) -> str | None:
        """Return the first key not in allowed or None if all keys allowed."""
        try:
            for k in obj.keys():
                if k not in allowed:
                    return self._sanitize_field_name(k)
        except Exception:
            return None
        return None
    
    @staticmethod
    def _allowed_unverified_outer_fields(msg_type: Any) -> set[str]:
        """Whitelist of allowed top-level fields for pre-verification JSON messages."""
        base = {"type", "protocol_version", "version"}
        try:
            mt = MessageType(msg_type)
        except Exception:
            # Unknown type: only allow 'type'
            return base
        
        match mt:
            case MessageType.KEY_EXCHANGE_INIT:
                return base | {"public_key", "dh_public_key"}
            case MessageType.KEY_EXCHANGE_RESPONSE:
                return base | {"ciphertext", "public_key", "dh_public_key"}
            case MessageType.ENCRYPTED_MESSAGE:
                return base | {"counter", "nonce", "ciphertext", "dh_public_key", "verification"}
            case MessageType.KEY_VERIFICATION:
                return base | {"verified"}
            case MessageType.KEY_EXCHANGE_RESET:
                return base | {"message"}
        if mt in (
            MessageType.KEEP_ALIVE,
            MessageType.KEY_EXCHANGE_COMPLETE,
            MessageType.INITIATE_KEY_EXCHANGE,
            MessageType.SERVER_FULL,
            MessageType.SERVER_VERSION_INFO,
            MessageType.SERVER_DISCONNECT,
            MessageType.ERROR,
        ):
            # Allow common server control fields
            return base | {"reason", "message", "timestamp"}
        return base
        
    @staticmethod
    def _allowed_unverified_inner_fields() -> set[str]:
        """Whitelist superset of allowed decrypted JSON fields before verification."""
        return {
            # common
            "type", "message", "reason", "text",
            # delivery
            "confirmed_counter",
            # file transfer
            "transfer_id", "filename", "file_size", "file_hash", "total_chunks", "processed_size", "compressed",
            # rekey
            "action", "public_key", "ciphertext",
            # dummy
            "data",
            # ephemeral mode / nickname
            "mode", "owner_id", "nickname",
            # voice call (GUI/client variants may use these)
            "rate", "chunk_size", "audio_format", "audio_data"
        }
        
    def connect(self) -> bool:
        """Connect to the chat server and start the message receiving thread.
        
        Establishes a TCP socket connection to the server, sets the connected state,
        and starts a background thread to handle incoming messages.
        
        Returns:
            bool: True if connection was successful, False otherwise.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            self.display_system_message(f"Connected to secure chat server at {self.host}:{self.port}")
            self.display_system_message("Waiting for another user to connect...")
            
            # Start receiving thread
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = False
            self.receive_thread.start()
            
            return True
        
        except socket.timeout:
            self.display_error_message("Connection timed out. Please try again.")
            self.socket.close()
            return False
        
        except ConnectionRefusedError:
            self.display_error_message("Connection refused. Please check the server address and port.")
            self.socket.close()
            return False
        
        except Exception as e:
            self.display_error_message(f"Failed to connect to server: {e}")
            self.socket.close()
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
                    self.display_system_message("Connection to server lost.")
                    break
                except Exception as e:
                    if not self.connected:
                        break
                    self.display_error_message(f"Error receiving message: {e}")
                    break
        
        except Exception as e:
            self.display_error_message(f"Receive thread error: {e}")
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
            (for optimised file chunks). The method first tries JSON parsing for
            control messages (including keepalives), then falls back to binary
            file chunk processing if JSON parsing fails.
            
            All exceptions are caught and logged to prevent crashes.
        """
        try:
            # Rate-limit unverified peers to 5 messages/sec, unless in file transfer or voice call
            if not self.protocol.peer_key_verified:
                if not self.bypass_unverified_limits:
                    now = time.time()
                    if now - self._rl_window_start >= 1.0:
                        self._rl_window_start = now
                        self._rl_count = 0
                    if self._rl_count >= 5:
                        # Drop excess messages
                        self.display_error_message("Rate-limited unverified peer: drop message")
                        return
                    self._rl_count += 1
            
            # First, try to parse as JSON (for control messages including keepalive)
            try:
                if (not self.protocol.peer_key_verified and len(message_data) > 8192 and not
                self.bypass_unverified_limits):
                    # Prevent potential DoS with large messages before key verification
                    self.display_error_message("Received overly large message without key verification. Dropping.")
                    return
                
                message_json: dict[str, Any] = json.loads(message_data.decode('utf-8'))
                message_type = MessageType(int(message_json.get("type", -1)))
                if message_type == -1:
                    self.display_error_message("Received message with invalid type.")
                    return
                
                # Validate unexpected fields when peer is unverified (outer JSON)
                allowed = self._allowed_unverified_outer_fields(message_type)
                unexpected = self._first_unexpected_field(message_json, allowed)
                if unexpected:
                    self.display_error_message(f"Dropped message from unverified peer due to unexpected field '{unexpected}'.")
                    return
                
                match message_type:
                    case MessageType.KEY_EXCHANGE_INIT:
                        self.handle_key_exchange_init(message_data)
                    case MessageType.KEY_EXCHANGE_RESPONSE:
                        self.handle_key_exchange_response(message_data)
                    case MessageType.ENCRYPTED_MESSAGE:
                        if self.key_exchange_complete:
                            self.handle_encrypted_message(message_data)
                        else:
                            self.display_error_message("\nReceived encrypted message before key exchange complete")
                    case MessageType.ERROR:
                        self.display_error_message(f"{message_json.get('error', 'Unknown error')}")
                    case MessageType.KEY_VERIFICATION:
                        self.handle_key_verification_message(message_data)
                    case MessageType.KEY_EXCHANGE_RESET:
                        self.handle_key_exchange_reset(message_data)
                    case MessageType.KEEP_ALIVE:
                        self.handle_keepalive()
                    case MessageType.KEY_EXCHANGE_COMPLETE:
                        self.handle_key_exchange_complete()
                    case MessageType.INITIATE_KEY_EXCHANGE:
                        self.initiate_key_exchange()
                    case MessageType.SERVER_FULL:
                        self.handle_server_full()
                    case MessageType.SERVER_VERSION_INFO:
                        self.handle_server_version_info(message_data)
                    case MessageType.SERVER_DISCONNECT:
                        reason = message_json.get('reason', 'Server initiated disconnect')
                        self.on_server_disconnect(reason)
                    case _:
                        self.display_error_message(f"Unknown message type: {message_type}")
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
            self.display_error_message("Received a message that could not be decoded.")
        
        except Exception as e:
            self.display_error_message(f"Error handling message: {e}")
    
    def handle_keepalive(self) -> None:
        """Handle keepalive messages from the server."""
        # Create keepalive response message
        response_message = {"type": MessageType.KEEP_ALIVE_RESPONSE}
        response_data = json.dumps(response_message).encode('utf-8')
        
        # Send response to server
        send_message(self.socket, response_data)
    
    def handle_delivery_confirmation(self, message: str) -> None:
        """Handle delivery confirmation messages from the peer.
        
        Args:
            message (str): The decrypted delivery confirmation message.
        """
        try:
            confirmed_counter = json.loads(message).get("confirmed_counter")
            print(f"\n✓ Message {confirmed_counter} delivered")
        
        except Exception as e:
            self.display_error_message(f"Error handling delivery confirmation: {e}")
    
    def initiate_key_exchange(self) -> None:
        """Initiate the key exchange process as the first client.
        
        Generates a new keypair using the ML-KEM-1024 algorithm, creates a key
        exchange initialization message, and sends it to the server to be routed
        to the other client.
        
        Note:
            This method is called when this client is designated as the initiator
            of the key exchange process. The generated private key is stored in
            self.private_key for later use in processing the response.
            
        """
        # Generate keypair
        public_key, self.private_key = self.protocol.generate_keypair()
        
        # Create key exchange init message
        init_message = self.protocol.create_key_exchange_init(public_key)
        
        # Send to server (which will route to other client)
        send_message(self.socket, init_message)
    
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
        _, ciphertext, version_warning = self.protocol.process_key_exchange_init(message_data)
        
        # Display version warning if present
        if version_warning:
            self.display_system_message(f"{version_warning}")
        
        response = self.protocol.create_key_exchange_response(ciphertext)
        
        # Send response back through server
        send_message(self.socket, response)
    
    def handle_key_exchange_response(self, message_data: bytes) -> bool:
        """Handle key exchange response from another client."""
        try:
            if self.private_key:
                _, version_warning = self.protocol.process_key_exchange_response(message_data, self.private_key)
                
                # Display version warning if present
                if version_warning:
                    self.display_regular_message(f"{version_warning}")
                    
                self.display_system_message("Key exchange completed successfully.")
                return True
            else:
                self.display_system_message("Received key exchange response but no private key found")
                return False
        
        except Exception as e:
            self.display_error_message(f"Key exchange response error: {e}")
            return False
    
    def handle_key_exchange_complete(self) -> None:
        """Handle key exchange completion notification."""
        self.key_exchange_complete = True
        self.start_key_verification()
    
    def start_key_verification(self) -> None:
        """Start the key verification process."""
        try:
            
            # Display session fingerprint (same for both users)
            print("\nSession fingerprint:")
            print("-" * 40)
            session_fingerprint = self.protocol.get_own_key_fingerprint()
            print(session_fingerprint)
            
            print("\nINSTRUCTIONS:")
            print("1. Compare the fingerprint above with the other person through a")
            print("   secure channel (phone call, in-person, secure messaging)")
            print("2. Both users should see the SAME fingerprint")
            print("3. Only confirm if you both see identical fingerprints!")
            print("4. If the fingerprints don't match, there may be a Man-in-the-Middle attack.")
            
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
            self.protocol.peer_key_verified = verified
            
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
            print("Type '/rekey' to initiate a rekey for fresh session keys.\n")
        
        except Exception as e:
            print(f"Error confirming verification: {e}")
    
    def handle_key_verification_message(self, message_data: bytes) -> None:
        """Handle key verification message from peer."""
        try:
            peer_verified = self.protocol.process_key_verification_message(message_data)
            
            if peer_verified:
                self.display_system_message("Peer has verified your key successfully.")
            else:
                self.display_system_message("Peer has NOT verified your key.")
        
        except Exception as e:
            self.display_error_message(f"Error handling verification message: {e}")
    
    def display_regular_message(self, message: str, prefix: str = "") -> None:
        """Display a regular chat message."""
        if prefix != "":
            print(f"\n{prefix}: {message}")
        else:
            print(f"\n{self.peer_nickname}: {message}")
    
    def display_error_message(self, message: str) -> None:
        print(f"\nError: {message}")
        
    def display_system_message(self, message: str) -> None:
        """Display a system message."""
        print(f"\n[SYSTEM]: {message}")
    
    def prompt_rekey_from_unverified(self) -> bool:
        """Prompt the user whether to proceed with a rekey from an unverified peer.
        Returns True to proceed with rekey, False to disconnect.
        """
        try:
            print("\nWARNING: Rekey requested by an UNVERIFIED peer.")
            print("Proceeding may expose you to Man-in-the-Middle attacks if this peer is not who you expect.")
            while True:
                try:
                    resp = input("Do you want to commence the rekey? (yes = proceed, no = disconnect): ").strip().lower()
                    if resp in ("yes", "y"):  # proceed with rekey
                        return True
                    if resp in ("no", "n"):   # disconnect
                        return False
                    print("Please answer 'yes'/'y' or 'no'/'n'.")
                except (EOFError, KeyboardInterrupt):
                    print("\nNo response provided. Defaulting to disconnect.")
                    return False
        except Exception:
            # On any unexpected error, be conservative and disconnect
            return False
    
    def handle_encrypted_message(self, message_data: bytes) -> None:
        """Handle encrypted chat messages."""
        try:
            decrypted_text = self.protocol.decrypt_message(message_data)
        except ValueError as e:
            self.display_error_message(str(e))
            return
        
        # Get the message counter that was just processed for delivery confirmation
        received_message_counter = self.protocol.peer_counter
        
        # Attempt to parse the decrypted text as a JSON message
        try:
            message_obj: dict[str, Any] = json.loads(decrypted_text)
            
            # Validate unexpected fields when peer is unverified (inner JSON)
            if not self.protocol.peer_key_verified:
                allowed_inner = self._allowed_unverified_inner_fields()
                unexpected_inner = self._first_unexpected_field(message_obj, allowed_inner)
                if unexpected_inner:
                    self.display_error_message(f"Dropped decrypted message from unverified peer due to unexpected field '{unexpected_inner}'.")
                    return
            
            message_type: int | None = message_obj.get("type")
            if message_type is None:
                self.display_error_message("Dropped message without inside type.")
                return
            
            match message_type:
                case MessageType.TEXT_MESSAGE:
                    text = str(message_obj.get("text", ""))
                    if not self.protocol.peer_key_verified:
                        text = "".join(ch for ch in text if ch in string.printable)
                    self.display_regular_message(text)
                    self._send_delivery_confirmation(received_message_counter)
                case MessageType.EMERGENCY_CLOSE:
                    self.handle_emergency_close()
                case MessageType.DUMMY_MESSAGE:
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
                case MessageType.EPHEMERAL_MODE_CHANGE:
                    self.handle_ephemeral_mode_change(decrypted_text)
                case MessageType.REKEY:
                    self.handle_rekey(decrypted_text)
                case MessageType.VOICE_CALL_INIT:
                    self.handle_voice_call_init(decrypted_text)
                case MessageType.VOICE_CALL_ACCEPT:
                    self.handle_voice_call_accept(decrypted_text)
                case MessageType.VOICE_CALL_REJECT:
                    self.handle_voice_call_reject()
                case MessageType.VOICE_CALL_DATA:
                    self.handle_voice_call_data(decrypted_text)
                case MessageType.VOICE_CALL_END:
                    self.handle_voice_call_end()
                case MessageType.NICKNAME_CHANGE:
                    self.handle_nickname_change(decrypted_text)
                case _:
                    self.display_error_message(f"Dropped message with unknown inside type: {message_type}")
                    return
        
        except (json.JSONDecodeError, TypeError):
            self.display_error_message("Dropped message without inside type (not JSON).")
            return
    
    
    def _send_delivery_confirmation(self, confirmed_counter: int) -> None:
        """Send a delivery confirmation for a received text message."""
        if not self.send_delivery_receipts:
            return
        # Queue delivery confirmation as JSON; loop will encrypt
        message = {
            "type":              MessageType.DELIVERY_CONFIRMATION,
            "confirmed_counter": confirmed_counter,
        }
        self.protocol.queue_message(("encrypt_json", message))
    
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
            print(f"\n{'=' * 50}")
            print("KEY EXCHANGE RESET")
            print(f"Reason: {reset_message}")
            print("The secure session has been terminated.")
            print("Waiting for a new client to connect...")
            print("A new key exchange will start automatically.")
            print(f"{'=' * 50}")
        
        except Exception as e:
            print(f"Error handling key exchange reset: {e}")
    
    def handle_emergency_close(self) -> None:
        """Handle emergency close message from the other client."""
        try:
            print(f"\n{'=' * 50}")
            print("EMERGENCY CLOSE RECEIVED")
            print("The other client has activated emergency close.")
            print("Connection will be terminated immediately.")
            print(f"{'=' * 50}")
            
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
    
    def initiate_rekey(self) -> None:
        """Initiate a rekey to establish fresh session keys using the existing secure channel."""
        if not self.key_exchange_complete:
            self.display_error_message("Cannot rekey - key exchange not complete")
            return
        try:
            payload = self.protocol.create_rekey_init()
            # Send REKEY init under old key
            self.protocol.queue_message(("encrypt_json", payload))
            self.display_system_message("Rekey initiated.")
        except Exception as e:
            self.display_error_message(f"Failed to initiate rekey: {e}")
    
    def send_message(self, text: str) -> bool:
        """Encrypt and queue a chat message for sending."""
        if not self.key_exchange_complete:
            print("Cannot send messages - key exchange not complete")
            return False
        
        # Check verification status and warn user
        if not self.protocol.encryption_ready:
            print(f"Cannot send message, encryption isn't ready")
            return False
        
        if not self.protocol.peer_key_verified:
            print("Sending message to unverified peer")
        
        try:
            # Queue plaintext; sender loop will handle encryption
            self.protocol.queue_message(("encrypt_text", text))
            return True
        
        except Exception as e:
            print(f"Failed to send message: {e}")
            return False
    
    def send_file(self, file_path: str, compress: bool = True) -> None:
        """Send a file to the other client."""
        try:
            if not self.verification_complete:
                print("Cannot send file: Key verification not complete")
                return
            
            # Warn if keys are unverified (potential MitM vulnerability)
            if not self.protocol.peer_key_verified:
                self.display_system_message("Warning: Sending file over an unverified connection. This is vulnerable to MitM attacks.")
            
            # Create file metadata message
            metadata = self.protocol.create_file_metadata_message(file_path, compress=compress)
            
            # Use the effective compression decided by the protocol (auto-detects incompressible types)
            compress = bool(metadata.get("compressed", True))
            
            # Store file path for later sending
            transfer_id = metadata["transfer_id"]
            self.pending_file_transfers[transfer_id] = {
                "file_path": file_path,
                "metadata":  metadata,
                "compress":  compress
            }
            metadata_message = deepcopy(dict(metadata))
            metadata_message["type"] = MessageType.FILE_METADATA
            # Send metadata to peer via queue (loop will encrypt)
            self.protocol.queue_message(("encrypt_json", metadata_message))
            compression_text = "compressed" if compress else "uncompressed"
            print(
                    f"File transfer request sent: {metadata['filename']} ({metadata['file_size']} bytes, {compression_text})")
        
        except Exception as e:
            print(f"Failed to send file: {e}")
    
    def handle_ephemeral_mode_change(self, decrypted_message: str) -> None:
        """Handle incoming ephemeral mode change from peer (console feedback)."""
        try:
            message = json.loads(decrypted_message)
            if message.get("type") != MessageType.EPHEMERAL_MODE_CHANGE:
                return
            mode = str(message.get("mode", "OFF")).upper()
            if mode == "GLOBAL":
                print("\nPeer enabled GLOBAL ephemeral mode. Only the enabler can disable it.")
            elif mode == "OFF":
                print("\nPeer disabled GLOBAL ephemeral mode.")
        
        except Exception as e:
            print(f"\nError handling ephemeral mode change: {e}")
    
    def handle_file_metadata(self, decrypted_message: str) -> None:
        """Handle incoming file metadata."""
        try:
            metadata = self.protocol.process_file_metadata(decrypted_message)
            transfer_id = metadata["transfer_id"]
            if not self.allow_file_transfers:
                print("File transfers are disabled. Ignoring incoming file.")
                self.protocol.queue_message(("encrypt_json", {
                    "type":        MessageType.FILE_REJECT,
                    "transfer_id": transfer_id,
                    "reason":      "User disabled file transfers",
                }))
                return
            
            # Warn if keys are unverified (potential MitM vulnerability)
            if not self.protocol.peer_key_verified:
                self.display_system_message("Warning: Incoming file request over an unverified connection. This is vulnerable to MitM attacks.")
            
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
                        # Send acceptance via queue (loop will encrypt)
                        self.protocol.queue_message(("encrypt_json", {
                            "type":        MessageType.FILE_ACCEPT,
                            "transfer_id": transfer_id,
                        }))
                        print("File transfer accepted. Waiting for file...")
                        self.protocol.send_dummy_messages = False
                    
                    elif response in ['no', 'n']:
                        # Send rejection via queue (loop will encrypt)
                        self.protocol.queue_message(("encrypt_json", {
                            "type":        MessageType.FILE_REJECT,
                            "transfer_id": transfer_id,
                            "reason":      "User declined",
                        }))
                        print("File transfer rejected.")
                        del self.active_file_metadata[transfer_id]
                    else:
                        print("Please enter 'yes' or 'no'")
                except (EOFError, KeyboardInterrupt):
                    # Send rejection on interrupt via queue
                    self.protocol.queue_message(("encrypt_json", {
                        "type":        MessageType.FILE_REJECT,
                        "transfer_id": transfer_id,
                        "reason":      "User canceled",
                    }))
                    print("File transfer rejected.")
                    del self.active_file_metadata[transfer_id]
                    break
        
        except Exception as e:
            print(f"Error handling file metadata: {e}")
    
    def handle_file_accept(self, decrypted_message: str) -> None:
        """Handle file acceptance from peer."""
        try:
            self.protocol.send_dummy_messages = False
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id not in self.pending_file_transfers:
                print("Received acceptance for unknown file transfer")
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            file_path = transfer_info["file_path"]
            
            print(f"File transfer accepted. Sending {transfer_info['metadata']['filename']}...")
            
            # Start tracking the sending transfer in the protocol
            self.protocol.sending_transfers[transfer_id] = transfer_info['metadata']
            
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
    
    def handle_rekey(self, decrypted_text: str) -> None:
        try:
            inner = json.loads(decrypted_text)
            action = inner.get("action")
            if action == "init":
                # If the peer is unverified, ask the user whether to proceed or disconnect
                if not self.protocol.peer_key_verified:
                    proceed = self.prompt_rekey_from_unverified()
                    if not proceed:
                        self.display_system_message("Disconnecting as requested: rekey received from an unverified peer.")
                        self.disconnect()
                        return
                self.display_system_message("Rekey initiated by peer.")
                response = self.protocol.process_rekey_init(inner)
                # Send response under old key
                self.protocol.queue_message(("encrypt_json", response))
            elif action == "response":
                commit = self.protocol.process_rekey_response(inner)
                # Send commit under old key; do not switch yet (wait for ack)
                self.protocol.queue_message(("encrypt_json", commit))
            elif action == "commit":
                ack = self.protocol.process_rekey_commit(inner)
                # Send ack under old key, then switch to new keys
                self.protocol.queue_message(("encrypt_json_then_switch", ack))
                self.display_system_message("Rekey completed successfully.")
                self.display_system_message("You are now using fresh encryption keys.")
            elif action == "commit_ack":
                # Initiator: switch to new keys upon receiving ack
                self.protocol.activate_pending_keys()
                self.display_system_message("Rekey completed successfully.")
                self.display_system_message("You are now using fresh encryption keys.")                          
            else:
                self.display_error_message("Received unknown rekey action")
        except Exception as rekey_err:
            self.display_error_message(f"Error handling rekey message: {rekey_err}")
    
    def handle_voice_call_init(self, decrypted_text: str) -> None:
        """Handle incoming voice call initiation (console feedback)."""
        print("Voice calls not supported on the terminal client.")
    
    def handle_voice_call_accept(self, decrypted_text: str) -> None:
        """Handle incoming voice call acceptance (console feedback)."""
        print("Voice calls not supported on the terminal client.")
    
    def handle_voice_call_reject(self) -> None:
        """Handle incoming voice call rejection (console feedback)."""
        print("Voice calls not supported on the terminal client.")
    
    def handle_voice_call_data(self, decrypted_text: str) -> None:
        """Handle incoming voice call data (console feedback)."""
        print("Voice calls not supported on the terminal client.")
    
    def handle_voice_call_end(self) -> None:
        """Handle incoming voice call end (console feedback)."""
        print("Voice calls not supported on the terminal client.")
    
    def handle_nickname_change(self, decrypted_text: str) -> None:
        """Handle incoming nickname change from peer."""
        try:
            # Disable nickname changes when keys are unverified
            if not self.protocol.peer_key_verified:
                self.display_system_message("Ignored nickname change from peer: connection is unverified")
                return
            if not self.nickname_change_allowed:
                self.display_system_message("Peer attempted to change nickname")
                return
            message = json.loads(decrypted_text)
            self.peer_nickname = str(message.get("nickname", "Other User"))[:32]
            self.display_system_message(f"Peer changed nickname to: {self.peer_nickname}")
        
        except Exception as e:
            self.display_error_message(f"Error handling nickname change: {e}")
    
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
            print(
                    f"Receiving {metadata['filename']}: {progress:.1f}% ({received_chunks}/{metadata['total_chunks']} chunks)")
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
                
                # Send the completion message via queue (loop will encrypt)
                self.protocol.queue_message(("encrypt_json", {
                    "type":        MessageType.FILE_COMPLETE,
                    "transfer_id": transfer_id,
                }))
            
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
                self.protocol.send_dummy_messages = True
        
        
        except Exception as e:
            print(f"Error handling file completion: {e}")
    
    def handle_server_full(self) -> None:
        """Handle server full notification."""
        print("\nServer is full. Cannot connect at this time.")
        print("Please try again later or contact the server administrator.")
        self.disconnect()
    
    def handle_server_version_info(self, message_data: bytes) -> None:
        """Handle server version information."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            
            # Store server protocol version information
            self.server_protocol_version = message.get("protocol_version")
            
            print(f"\nServer Protocol Version: v{self.server_protocol_version}")
            
            # Check compatibility
            if self.server_protocol_version != PROTOCOL_VERSION:
                print(
                        f"Protocol version mismatch: Client v{PROTOCOL_VERSION}, Server v{self.server_protocol_version}")
                # Use local compatibility matrix since server no longer sends it
                major_server = self.server_protocol_version.split('.')[0]
                major_client = PROTOCOL_VERSION.split('.')[0]
                if major_server == major_client:
                    print("Versions are compatible for communication")
                else:
                    print("Versions may not be compatible - communication issues possible")
            else:
                print("Protocol versions match")
        
        except Exception as e:
            print(f"Error handling server version info: {e}")
    
    def on_server_disconnect(self, reason: str) -> None:
        """Hook: called when server notifies of server-initiated disconnect."""
        try:
            print(f"\nServer disconnected: {reason}")
        finally:
            self.disconnect()
    
    def _send_file_chunks(self, transfer_id: str, file_path: str) -> None:
        """Send file chunks to peer."""
        try:
            # Get transfer info including compression setting
            transfer_info = self.pending_file_transfers[transfer_id]
            total_chunks = int(transfer_info["metadata"]["total_chunks"])
            compress = transfer_info.get("compress", True)  # Default to compressed for backward compatibility
            
            chunk_generator = self.protocol.chunk_file(file_path, compress=compress)
            
            for i, chunk in enumerate(chunk_generator):
                # Queue chunk instruction; loop will encrypt and send
                send_message(self.socket, self.protocol.create_file_chunk_message(transfer_id,
                                                                                  i, chunk))
                
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
                if not (self.key_exchange_complete and self.verification_complete):
                    continue
                try:
                    message = input()
                    if message.lower() == '/quit':
                        break
                    if message.lower() == '/verify':
                        self.start_key_verification()
                    elif message.lower() == '/rekey':
                        self.initiate_rekey()
                    elif message.lower() == '/help':
                        print("Commands:")
                        print("  /quit - Exit the chat")
                        print("  /verify - Start key verification")
                        print("  /file <path> - Send a file")
                        print("  /rekey - Initiate a rekey for fresh session keys")
                        print("  /help - Show this help message")
                    elif message.lower().startswith('/file '):
                        file_path = message[6:].strip()
                        if file_path:
                            self.send_file(file_path)
                        else:
                            print("Usage: /file <path>")
                    elif message.lower().startswith('/nick ') or message.lower().startswith('/nickname '):
                        new_nickname = message[6:].strip()
                        if new_nickname:
                            self.protocol.queue_message(("encrypt_json", {
                                "type":     MessageType.NICKNAME_CHANGE,
                                "nickname": new_nickname,
                            }))
                            print(f"Nickname changed to: {self.peer_nickname}")
                        else:
                            print("Usage: /nick <new_nickname>")
                    
                    elif message.strip():
                        if not self.send_message(message):
                            continue
                        
                        if self.protocol.peer_key_verified:
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
            # If the key exchange was complete there is a peer, notify them of disconnect
            self.end_call(notify_peer=self.key_exchange_complete)
            self.protocol.stop_sender_thread()
            self.close_audio()
            
            self.connected = False
            
            shared.send_message(self.socket, json.dumps({"type": MessageType.CLIENT_DISCONNECT}).encode('utf-8'))
            
            try:
                if self.socket:
                    self.socket.close()
            except Exception:
                pass
            
            # Wait for receive thread to finish cleanly
            if self.receive_thread and self.receive_thread.is_alive():
                try:
                    self.receive_thread.join(timeout=2.0)
                except Exception:
                    pass
            
            print("\nDisconnected from server.")
    
    def end_call(self, notify_peer: bool = True) -> None:
        pass


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
