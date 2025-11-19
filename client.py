"""
Secure Chat Client with End-to-End Encryption
It uses KRYSTALS KYBER protocol + X25519 for secure key exchange and message encryption.
"""
import base64
import binascii
import hashlib
# pylint: disable=trailing-whitespace, broad-exception-caught
import socket
import string
import threading
import json
import sys
import os
import time
from copy import deepcopy
from typing import Any, BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pqcrypto.kem import ml_kem_1024  # type: ignore

import shared
from shared import (SecureChatProtocol, send_message, receive_message, MessageType,
                    PROTOCOL_VERSION, FileMetadata, FileTransfer, SEND_CHUNK_SIZE,
                    StreamingDoubleEncryptor)


# noinspection PyBroadException
class SecureChatClient:
    def __init__(self) -> None:
        """
        The SecureChatClient handles client-side operations for a secure chat application.

        This class is responsible for managing the client-server communication, ensuring
        secure data transmission through protocol adherence, and managing user-related
        functionalities like file transfer, voice calls, and key exchange procedures.
        It maintains the state of the connection, user permissions, and ongoing
        operations such as file transfers and audio sessions.
        
        A guaranteed attribute is an attribute that is guaranteed to exist and have a valid value.
        This means that the value of the attribute is always correct and can be safely used.
        
        Guaranteed Attributes:
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
            host (str): The hostname or IP address of the server.
            port (int): The port number of the server.
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
        self.host: str = "0.0.0.0"
        self.port: int = 16384
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
        self.pending_file_transfers: dict[str, FileTransfer] = {}
        self.active_file_metadata: dict[str, FileMetadata] = {}
        self._last_progress_shown: dict[str, float | int] = {}
        
        # Server version information
        self.server_protocol_version: str = "0.0.0"
        self.server_identifier: str = ""
        # Deaddrop session state
        self.deaddrop_shared_secret: bytes | None = None
        self.deaddrop_supported: bool = False
        self.deaddrop_max_size: int = 0
        self._deaddrop_in_progress: bool = False
        self._deaddrop_chunks: dict[int, bytes] = {}
        self._deaddrop_file_size: int = 0
        self._deaddrop_name: str = ""
        self._deaddrop_password_hash: str = ""
        # Download-specific state
        self._deaddrop_download_in_progress: bool = False
        self._deaddrop_download_name: str = ""
        self._deaddrop_download_expected_hash: str | None = None
        self._deaddrop_download_chunks: dict[int, bytes] = {}
        self._deaddrop_download_max_index: int = -1
        self._deaddrop_download_key: bytes | None = None
        self._deaddrop_download_otp_secret: bytes | None = None
        # Streaming download state (for deaddrop)
        self._deaddrop_dl_encryptor: StreamingDoubleEncryptor | None = None
        self._deaddrop_dl_next_nonce: bytes | None = None
        self._deaddrop_dl_expected_index: int = 0
        self._deaddrop_dl_part_path: str | None = None
        self._deaddrop_dl_file: BinaryIO | None = None  # file handle for .part writing
        self._deaddrop_dl_bytes_downloaded: int = 0
        # Event to signal completion of the deaddrop handshake
        self._deaddrop_handshake_event: threading.Event | None = None
        
        # Rate limiting
        self._rl_window_start: float = 0.0
        self._rl_count: int = 0
    
    @property
    def file_transfer_active(self) -> bool:
        """Whether any file transfers are currently in progress."""
        return bool(self.pending_file_transfers or self.active_file_metadata or self._deaddrop_download_in_progress)
    
    @property
    def bypass_rate_limits(self) -> bool:
        """Whether to bypass the rate-limiting and file size restrictions for unverified peers.
        Bypass during file transfer, voice call, or an in-progress rekey handshake to avoid
        dropping legitimate control bursts from unverified peers.
        """
        return bool(self.file_transfer_active or self.voice_call_active or self.protocol.rekey_in_progress)
    
    @bypass_rate_limits.setter
    def bypass_rate_limits(self, bypass: bool) -> None:
        raise ValueError("Cannot set bypass_rate_limits directly.")
    
    @property
    def has_priv_key(self) -> bool:
        return bool(self.protocol.dh_private_key)
    
    def close_audio(self) -> None:
        pass
    
    @staticmethod
    def _first_unexpected_field(obj: dict[Any, Any], allowed: set[str]) -> str | None:
        """Return the first key not in allowed or None if all keys allowed."""
        for k in obj.keys():
            if k not in allowed:
                return shared.sanitize_str(k)
        return None
    
    @staticmethod
    def _allowed_outer_fields(msg_type: Any) -> set[str]:
        """Whitelist of allowed top-level fields for pre-verification JSON messages."""
        base = {"type", "protocol_version", "version"}
        mt = MessageType(msg_type)
        
        server_control: list[MessageType] = [MessageType.KEEP_ALIVE, MessageType.KEY_EXCHANGE_COMPLETE,
                                             MessageType.INITIATE_KEY_EXCHANGE, MessageType.SERVER_FULL,
                                             MessageType.SERVER_VERSION_INFO, MessageType.SERVER_DISCONNECT,
                                             MessageType.ERROR]
        
        match mt:
            case MessageType.SERVER_VERSION_INFO:
                # Allow server identifier in version info announcement
                return base | {"identifier"}
            case MessageType.KEY_EXCHANGE_INIT:
                return base | {"mlkem_public_key", "dh_public_key", "hqc_public_key"}
            case MessageType.KEY_EXCHANGE_RESPONSE:
                return base | {"mlkem_ciphertext", "hqc_ciphertext", "mlkem_public_key", "hqc_public_key",
                               "dh_public_key"}
            case MessageType.ENCRYPTED_MESSAGE:
                return base | {"counter", "nonce", "ciphertext", "dh_public_key", "verification"}
            case MessageType.KEY_VERIFICATION:
                return base | {"verified"}
            case MessageType.KEY_EXCHANGE_RESET:
                return base | {"message"}
            case MessageType.DEADDROP_START:
                # Plaintext handshake: may include capability fields
                return base | {"supported", "max_file_size", "mlkem_public"}
            case MessageType.DEADDROP_MESSAGE:
                # Encrypted deaddrop envelope
                return base | {"nonce", "ciphertext"}
        
        if mt in server_control:
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
        
    def connect(self, host: str, port: int) -> bool:
        """Connect to the chat server and start the message receiving thread.
        
        Establishes a TCP socket connection to the server, sets the connected state,
        and starts a background thread to handle incoming messages.
        
        Returns:
            bool: True if connection was successful, False otherwise.
        """
        try:
            self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            self.host, self.port = host, port
            
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
    
    def handle_message(self, message_data: bytes) -> None:
        """
        Handle different types of messages received from the server.

        This method acts as a message dispatcher, parsing incoming messages and
        routing them to appropriate handler methods based on the message type.

        Args:
            message_data (bytes): Raw message data received from the server.

        Note:
            Messages can be either JSON-encoded (for control messages) or binary
            (for optimised file chunks). The method first tries JSON parsing for
            control messages (including keepalives), then falls back to binary
            file chunk processing if JSON parsing fails.
        
        """
        # Rate-limit peers to 5 messages/sec, unless in file transfer or voice call
        if not self.bypass_rate_limits:
            now = time.time()
            if now - self._rl_window_start >= 1.0:
                self._rl_window_start = now
                self._rl_count = 0
            if self._rl_count >= 5:
                # Drop excess messages
                self.display_error_message("Rate-limited peer: dropped message")
                return
            self._rl_count += 1

        if len(message_data) > 33260 and not self.bypass_rate_limits:
            # Prevent potential DoS with large messages
            self.display_error_message("Received overly large message without key verification. Dropping." +
                                       f" ({len(message_data)} bytes)")
            return
        
        # First, try to parse as JSON (for control messages including keepalive)
        try:
            message_json: dict[Any, Any] = json.loads(message_data)
            message_type = MessageType(int(message_json.get("type")))  # type: ignore
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            # If JSON parsing failed, check if this might be a binary file chunk message
            success = self.handle_maybe_binary_chunk(message_data)
            if not success:
                self.display_error_message("Received message that could not be decoded.")
            return
            
        if message_type == MessageType.NONE:
            self.display_error_message("Received message with invalid type.")
            return
        
        # Validate unexpected fields when peer is unverified (outer JSON)
        allowed = self._allowed_outer_fields(message_type)
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
            case MessageType.DEADDROP_START:
                # Handle server response to deaddrop start
                self._handle_deaddrop_start_response(message_json)
            case MessageType.DEADDROP_MESSAGE:
                self._handle_deaddrop_encrypted_message(message_json)
            case _:
                self.display_error_message(f"Unknown message type: {message_type}")
        return
        
    
    def handle_maybe_binary_chunk(self, message_data: bytes) -> bool:
        if not (len(message_data) >= 48 and self.key_exchange_complete):
            return False
        try:
            # Try to process as binary file chunk
            result = self.protocol.process_file_chunk(message_data)
            self.handle_file_chunk_binary(result)
            return True
        except ValueError:
            # Not a binary file chunk either
            return False
    
    def handle_keepalive(self) -> None:
        """Handle keepalive messages from the server."""
        # Create keepalive response message
        response_message = {"type": MessageType.KEEP_ALIVE_RESPONSE}
        response_data = json.dumps(response_message).encode('utf-8')
        
        # Send response to server
        ok, err = send_message(self.socket, response_data)
        if not ok:
            self.display_error_message(f"Failed to send keepalive response: {err}")
            self.display_system_message("Server may disconnect after 3 keepalive failures.")
    
    def handle_delivery_confirmation(self, message: dict[Any, Any]) -> None:
        """
        Handle delivery confirmation messages from the other client.
        GUI exclusive
        """
        pass
    
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
        public_key = self.protocol.generate_keys()
        
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
        hqc_ciphertext, mlkem_ciphertext, version_warning = self.protocol.process_key_exchange_init(message_data)
        
        # Display version warning if present
        if version_warning:
            self.display_system_message(f"{version_warning}")
        
        response = self.protocol.create_key_exchange_response(mlkem_ciphertext, hqc_ciphertext)
        
        # Send response back through server
        send_message(self.socket, response)
    
    def handle_key_exchange_response(self, message_data: bytes) -> bool:
        """Handle key exchange response from another client."""
        if self.has_priv_key:
            version_warning = self.protocol.process_key_exchange_response(message_data)
            
            # Display version warning if present
            if version_warning:
                self.display_system_message(f"{version_warning}")
                
            self.display_system_message("Key exchange completed successfully.")
            return True
        self.display_system_message("Received key exchange response but no private key found")
        return False
    
    
    def handle_key_exchange_complete(self) -> None:
        """Handle key exchange completion notification."""
        self.key_exchange_complete = True
        self.start_key_verification()
    
    def start_key_verification(self) -> None:
        """Start the key verification process."""
        
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
                print("\nVerification cancelled. Connection may be insecure.")
                self.confirm_key_verification(False)
                break
    
    def confirm_key_verification(self, verified: bool) -> None:
        """Confirm the key verification result."""
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
    
    def handle_key_verification_message(self, message_data: bytes) -> None:
        """Handle key verification message from peer."""
        try:
            peer_verified = self.protocol.process_key_verification_message(message_data)
        except shared.DecodeError as e:
            self.display_error_message(e)
            return
            
        
        if peer_verified:
            self.display_system_message("Peer has verified your key successfully.")
        else:
            self.display_system_message("Peer has NOT verified your key.")
    
    def display_regular_message(self, message: str, prefix: str = "") -> None:
        """Display a regular chat message."""
        if prefix != "":
            print(f"\n{prefix}: {message}")
        else:
            print(f"\n{self.peer_nickname}: {message}")
    
    def display_error_message(self, message: str | Exception) -> None:
        print(f"Error: {message}")
        
    def display_system_message(self, message: str) -> None:
        """Display a system message."""
        print(f"[SYSTEM]: {message}")
    
    def prompt_rekey_from_unverified(self) -> bool:
        """Prompt the user whether to proceed with a rekey from an unverified peer.
        Returns True to proceed with rekey, False to disconnect.
        """
        self.display_system_message("WARNING: Rekey requested by an UNVERIFIED peer.")
        self.display_system_message("Proceeding may expose you to Man-in-the-Middle attacks " +
                                    "if this peer is not who you expect.")
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
    
    def handle_encrypted_message(self, message_data: bytes) -> None:
        """Handle encrypted chat messages."""
        try:
            decrypted_text = self.protocol.decrypt_message(message_data)
        except ValueError as e:
            self.display_error_message(e)
            return
        
        # Get the message counter that was just processed for delivery confirmation
        received_message_counter = self.protocol.peer_counter
        
        # Attempt to parse the decrypted text as a JSON message
        try:
            message_json: dict[Any, Any] = json.loads(decrypted_text)
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
            self.display_error_message("Received message that could not be decoded.")
            return
        
        # Validate unexpected fields when peer is unverified (inner JSON)
        if not self.protocol.peer_key_verified:
            allowed_inner = self._allowed_unverified_inner_fields()
            unexpected_inner = self._first_unexpected_field(message_json, allowed_inner)
            if unexpected_inner:
                self.display_error_message(f"Dropped decrypted message from unverified peer due to unexpected field '{unexpected_inner}'.")
                return
        
        message_type = MessageType(message_json.get("type", -1))
        if message_type == MessageType.NONE:
            self.display_error_message("Received message with invalid type.")
            return
        
        try:
            self.handle_message_types(message_type, message_json, received_message_counter)
        except Exception as e:
            self.display_error_message(f"Error handling a message: {e}")
            return
        
        # Check if automatic rekey should be initiated after processing the message
        self.check_and_initiate_auto_rekey()
    
    
    def handle_message_types(self, message_type: MessageType, message_json: dict[Any, Any],
                             received_message_counter: int) -> bool:
        """
        Handle the different types of messages.
        Handlers may raise errors which should be caught by the caller.
        
        :param message_type: The type of message
        :param message_json: The JSON message, serialized into a dictionary
        :param received_message_counter: The counter of the message, to be used for delivery confirmation
        :return: True if it could be handled successfully, False if not
        """
        match message_type:
            case MessageType.TEXT_MESSAGE:
                text = str(message_json.get("text", ""))
                if not self.protocol.peer_key_verified:
                    text = "".join(ch for ch in text if ch in string.printable)
                self.display_regular_message(text)
                self._send_delivery_confirmation(received_message_counter)
                
            case MessageType.EMERGENCY_CLOSE:
                self.handle_emergency_close()
                
            case MessageType.DUMMY_MESSAGE:
                pass
            
            case MessageType.FILE_METADATA:
                self.handle_file_metadata(message_json)
                
            case MessageType.FILE_ACCEPT:
                self.handle_file_accept(message_json)
                
            case MessageType.FILE_REJECT:
                self.handle_file_reject(message_json)
                
            case MessageType.FILE_COMPLETE:
                self.handle_file_complete(message_json)
                
            case MessageType.DELIVERY_CONFIRMATION:
                if self.key_exchange_complete:
                    self.handle_delivery_confirmation(message_json)
                    
            case MessageType.EPHEMERAL_MODE_CHANGE:
                self.handle_ephemeral_mode_change(message_json)
                
            case MessageType.REKEY:
                self.handle_rekey(message_json)
                
            case MessageType.VOICE_CALL_INIT:
                self.handle_voice_call_init(message_json)
                
            case MessageType.VOICE_CALL_ACCEPT:
                self.handle_voice_call_accept(message_json)
                
            case MessageType.VOICE_CALL_REJECT:
                self.handle_voice_call_reject()
                
            case MessageType.VOICE_CALL_DATA:
                self.handle_voice_call_data(message_json)
                
            case MessageType.VOICE_CALL_END:
                self.handle_voice_call_end()
                
            case MessageType.NICKNAME_CHANGE:
                self.handle_nickname_change(message_json)
                
            case _:
                self.display_error_message(f"Dropped message with unknown inside type: {message_type}")
                return False
        
        return True
    
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
        
    
    def handle_emergency_close(self) -> None:
        """Handle emergency close message from the other client."""
        self.display_system_message("EMERGENCY CLOSE RECEIVED")
        self.display_system_message("The other client has activated emergency close.")
        self.display_system_message("Connection will be terminated immediately.")
        
        # Immediately disconnect
        self.disconnect()
        self.key_exchange_complete = False
        self.verification_complete = False
        self.protocol.reset_key_exchange()
        
        # Clear any pending file transfers
        self.pending_file_transfers.clear()
        self.active_file_metadata.clear()
        
    def initiate_rekey(self) -> None:
        """Initiate a rekey to establish fresh session keys using the existing secure channel."""
        if not self.key_exchange_complete:
            self.display_error_message("Cannot rekey - key exchange not complete")
            return
        payload = self.protocol.create_rekey_init()
        # Send REKEY init under old key
        self.protocol.queue_message(("encrypt_json", payload))
        self.display_system_message("Rekey initiated.")
    
    def check_and_initiate_auto_rekey(self) -> None:
        """Check if automatic rekey should be initiated and initiate if conditions are met."""
        # Check if rekey is needed based on message count
        if not self.protocol.should_auto_rekey():
            return
        
        # Don't rekey during file transfers
        if self.file_transfer_active or self.protocol.has_active_file_transfers:
            return
        
        # Don't rekey during voice calls
        if self.voice_call_active:
            return
        
        # All conditions met, initiate automatic rekey
        if not self.key_exchange_complete:
            return
        
        payload = self.protocol.create_rekey_init()
        self.protocol.queue_message(("encrypt_json", payload))
    
    def send_message(self, text: str) -> bool:
        """Encrypt and queue a chat message for sending."""
        if not self.key_exchange_complete:
            print("Cannot send messages - key exchange not complete")
            return False
        
        # Check verification status and warn user
        if not self.protocol.encryption_ready:
            print("Cannot send message, encryption isn't ready")
            return False
        
        if not self.protocol.peer_key_verified:
            print("Sending message to unverified peer")
        
        # Queue plaintext; sender loop will handle encryption
        self.protocol.queue_message(("encrypt_text", text))
        
        # Check if automatic rekey should be initiated after sending
        self.check_and_initiate_auto_rekey()
        
        return True
    
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
            compress = metadata["compressed"]
            
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
            print(f"File transfer request sent: {metadata['filename']} ({metadata['file_size']} bytes, {compression_text})")
        
        except Exception as e:
            print(f"Failed to send file: {e}")
    
    def handle_ephemeral_mode_change(self, message: dict[Any, Any]) -> None:
        """Handle incoming ephemeral mode change from peer (console feedback)."""
        mode = str(message.get("mode", "OFF")).upper()
        if mode == "GLOBAL":
            print("\nPeer enabled GLOBAL ephemeral mode. Only the enabler can disable it.")
        elif mode == "OFF":
            print("\nPeer disabled GLOBAL ephemeral mode.")
    
    def handle_file_metadata(self, decrypted_message: dict[Any, Any]) -> None:
        """Handle incoming file metadata."""
        try:
            metadata = self.protocol.process_file_metadata(decrypted_message)
        except KeyError as e:
            self.display_error_message(e)
            return
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
            self.display_system_message("Warning: Incoming file request over an unverified connection. " +
                                        "This is vulnerable to MitM attacks.")
        
        # Store metadata for potential acceptance
        self.active_file_metadata[transfer_id] = metadata
        
        # Prompt user for acceptance
        print("\nIncoming file transfer:")
        print(f"  Filename: {metadata['filename']}")
        print(f"  Size: {metadata['file_size']} bytes")
        print(f"  Chunks: {metadata['total_chunks']}")
        
        while True:
            try:
                response = input("Accept file? (y/n): ").lower().strip()
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
    
    def handle_file_accept(self, message: dict[Any, Any]) -> None:
        """Handle file acceptance from peer."""
        self.protocol.send_dummy_messages = False
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self.display_error_message("Received acceptance without transfer ID")
            self.protocol.send_dummy_messages = True
            return
            
        if transfer_id not in self.pending_file_transfers:
            print("Received acceptance for unknown file transfer")
            self.protocol.send_dummy_messages = True
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
    
    def handle_file_reject(self, message: dict[Any, Any]) -> None:
        """Handle file rejection from peer."""
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            print("Received rejection without transfer ID")
            return
        reason = message.get("reason", "Unknown reason")
        
        if transfer_id in self.pending_file_transfers:
            filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
            print(f"File transfer rejected: {filename} - {reason}")
            # Clean up transfer tracking
            self.protocol.stop_sending_transfer(transfer_id)
            del self.pending_file_transfers[transfer_id]
        else:
            print("Received rejection for unknown file transfer")
    
    def handle_rekey(self, inner: dict[Any, Any]) -> None:
        try:
            action = inner["action"]
        except KeyError:
            self.display_error_message("Dropped rekey message without action. Invalid JSON.")
            return
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
            ack = {"type": MessageType.REKEY, "action": "commit_ack",}
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
    
    def handle_voice_call_init(self, init_msg: dict[Any, Any]) -> None:
        """Handle incoming voice call initiation, GUI exclusive"""
        self.protocol.queue_message(("encrypt_json", {"type": MessageType.VOICE_CALL_REJECT}))
        self.display_system_message("Incoming voice call rejected: voice calls not supported on terminal client.")
    
    def handle_voice_call_accept(self, message: dict[Any, Any]) -> None:
        """Handle incoming voice call acceptance, GUI exclusive"""
        pass
    
    def handle_voice_call_reject(self) -> None:
        """Handle incoming voice call rejection, GUI exclusive"""
        pass
    
    def handle_voice_call_data(self, data: dict[Any, Any]) -> None:
        """Handle incoming voice call data, GUI exclusive"""
        pass
    
    def handle_voice_call_end(self) -> None:
        """Handle incoming voice call end, GUI exclusive"""
        pass
    
    def handle_nickname_change(self, message: dict[Any, Any]) -> None:
        """Handle incoming nickname change from peer."""
        # Disable nickname changes when keys are unverified
        if not self.protocol.peer_key_verified:
            self.display_system_message("Ignored nickname change from peer: connection is unverified")
            return
        if not self.nickname_change_allowed:
            self.display_system_message("Peer attempted to change nickname")
            return
        self.peer_nickname = str(message.get("nickname", "Other User"))[:32]
        self.display_system_message(f"Peer changed nickname to: {self.peer_nickname}")
    
    def handle_file_chunk_binary(self, chunk_info: dict[Any, Any]) -> None:
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
        
        # Initialise progress tracking for this transfer if not exists
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
    
    def handle_file_complete(self, message: dict[Any, Any]) -> None:
        """Handle file transfer completion notification."""
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self.display_error_message("Dropped file complete message without transfer ID. Invalid JSON.")
            return
        
        if transfer_id in self.pending_file_transfers:
            filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
            self.display_system_message(f"File transfer completed: {filename}")
            del self.pending_file_transfers[transfer_id]
            self.protocol.send_dummy_messages = True
        else:
            self.display_error_message(f"Received file complete for unknown transfer ID: {transfer_id}")
            
    
    def handle_server_full(self) -> None:
        """Handle server full notification."""
        print("\nServer is full. Cannot connect at this time.")
        print("Please try again later or contact the server administrator.")
        self.disconnect()

    def start_deaddrop_handshake(self) -> None:
        """Initiate deaddrop handshake with the server.

        This sends a plaintext DEADDROP_START message; the server replies with either
        unsupported/deny or a DEADDROP_START containing capabilities and an ML-KEM
        public key. The actual ML-KEM encryption and shared-secret derivation are
        performed in ``_handle_deaddrop_start_response``.
        """
        if not self.connected:
            self.display_error_message("Cannot start deaddrop - not connected")
            return

        if self._deaddrop_in_progress:
            self.display_error_message("Deaddrop already in progress")
            return

        # Reset handshake state and (re)initialise the event so callers can
        # wait for completion in a thread-safe manner.
        self.deaddrop_shared_secret = None
        self.deaddrop_supported = False
        if self._deaddrop_handshake_event is None:
            self._deaddrop_handshake_event = threading.Event()
        else:
            self._deaddrop_handshake_event.clear()

        self.display_system_message("Starting deaddrop handshake")

        msg = {"type": MessageType.DEADDROP_START}
        send_message(self.socket, json.dumps(msg).encode("utf-8"))

    def wait_for_deaddrop_handshake(self, timeout: float = 3.0) -> bool:
        """Block until the deaddrop handshake completes or ``timeout`` elapses.

        Returns ``True`` if a shared secret was successfully established, and
        ``False`` if the handshake failed, was not supported, or timed out.
        """
        if not self.connected:
            self.display_error_message("Cannot wait for deaddrop handshake - not connected")
            return False

        if self._deaddrop_handshake_event is None:
            # Handshake was never started for this wait call.
            self.display_error_message("Deaddrop handshake has not been started")
            return False

        completed = self._deaddrop_handshake_event.wait(timeout)
        if not completed:
            self.display_error_message("Deaddrop handshake timed out")
            return False

        # If the event was set but no shared secret is present, treat as failure
        # or unsupported deaddrop.
        return bool(self.deaddrop_shared_secret)

    def _handle_deaddrop_start_response(self, message: dict[str, Any]) -> None:
        """Process server's response to DEADDROP_START.

        On success, derives a 32-byte shared secret via ML-KEM and SHA3-512-based
        ConcatKDFHash using ``b"deaddrop key exchange"`` as otherinfo.
        """
        supported = bool(message.get("supported", False))
        if not supported:
            # Either deaddrop is disabled or server refused
            reason = message.get("reason", "Server does not support deaddrop")
            self.display_error_message(reason)
            self.deaddrop_shared_secret = None
            self.deaddrop_supported = False
            self._deaddrop_in_progress = False
            if self._deaddrop_handshake_event is not None:
                self._deaddrop_handshake_event.set()
            return

        try:
            mlkem_public_b64 = str(message["mlkem_public"])
            mlkem_public = base64.b64decode(mlkem_public_b64, validate=True)
        except KeyError:
            self.display_error_message("Invalid deaddrop start response: missing mlkem_public")
            if self._deaddrop_handshake_event is not None:
                self._deaddrop_handshake_event.set()
            return
        except binascii.Error:
            self.display_error_message("Invalid deaddrop start response: bad mlkem_public encoding")
            if self._deaddrop_handshake_event is not None:
                self._deaddrop_handshake_event.set()
            return

        # Perform ML-KEM encapsulation
        mlkem_ciphertext, kem_shared_secret = ml_kem_1024.encrypt(mlkem_public)

        # Derive the 32-byte shared secret using SHA3-512 via ConcatKDFHash
        kdf = ConcatKDFHash(algorithm=hashes.SHA3_512(), length=32,
                            otherinfo=b"deaddrop key exchange")
        self.deaddrop_shared_secret = kdf.derive(kem_shared_secret)
        self.deaddrop_supported = True
        self.deaddrop_max_size = int(message.get("max_file_size", 0))

        # Send key exchange response back to server
        resp = {
            "type": MessageType.DEADDROP_KE_RESPONSE,
            "mlkem_ct": base64.b64encode(mlkem_ciphertext).decode("utf-8"),
        }
        send_message(self.socket, json.dumps(resp).encode("utf-8"))
        self.display_system_message("Deaddrop handshake complete")
        if self._deaddrop_handshake_event is not None:
            self._deaddrop_handshake_event.set()

    def _encrypt_deaddrop_inner(self, inner: bytes) -> dict[str, Any]:
        """Encrypt inner deaddrop JSON bytes into a DEADDROP_MESSAGE envelope."""
        if not self.deaddrop_shared_secret:
            raise ValueError("Deaddrop shared secret not established")
        nonce = os.urandom(12)
        aad = {
            "type": MessageType.DEADDROP_MESSAGE,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
        }
        aad_raw = json.dumps(aad).encode("utf-8")
        aead = ChaCha20Poly1305(self.deaddrop_shared_secret)
        ciphertext = aead.encrypt(nonce, inner, aad_raw)
        return {
            "type": MessageType.DEADDROP_MESSAGE,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    def _handle_deaddrop_encrypted_message(self, outer: dict[str, Any]) -> None:
        """Handle DEADDROP_MESSAGE from server (encrypted channel wrapper).

        Supports upload and download flows including:
        - DEADDROP_CHECK_RESPONSE
        - DEADDROP_ACCEPT / DEADDROP_DENY
        - DEADDROP_PROVE (salt during download)
        - DEADDROP_DATA / DEADDROP_COMPLETE
        - DEADDROP_REDOWNLOAD
        """
        if not self.deaddrop_shared_secret:
            self.display_error_message("Received deaddrop message before handshake was complete")
            return

        try:
            nonce_b64 = str(outer["nonce"])
            ct_b64 = str(outer["ciphertext"])
            nonce = base64.b64decode(nonce_b64, validate=True)
            ciphertext = base64.b64decode(ct_b64, validate=True)
        except KeyError:
            self.display_error_message("Malformed deaddrop message from server")
            return
        except binascii.Error:
            self.display_error_message("Invalid base64 in deaddrop message from server")
            return

        aad_raw = json.dumps({
            "type": MessageType.DEADDROP_MESSAGE,
            "nonce": nonce_b64,
        }).encode("utf-8")

        try:
            aead = ChaCha20Poly1305(self.deaddrop_shared_secret)
            inner_bytes = aead.decrypt(nonce, ciphertext, aad_raw)
            inner = json.loads(inner_bytes.decode("utf-8"))
        except Exception:
            self.display_error_message("Failed to decrypt deaddrop message from server")
            return

        inner_type = MessageType(int(inner.get("type", MessageType.NONE)))
        if inner_type == MessageType.DEADDROP_CHECK_RESPONSE:
            exists = bool(inner.get("exists", False))
            name = self._deaddrop_name or inner.get("name", "")
            if exists:
                self.display_system_message(f"Deaddrop '{name}' exists on server.")
            else:
                self.display_error_message(f"Deaddrop '{name}' does not exist on server.")
        elif inner_type == MessageType.DEADDROP_ACCEPT:
            # Server accepted upload or download. For uploads, nothing more to
            # track here; for downloads we must acknowledge with our own
            # DEADDROP_ACCEPT so the server starts streaming the file.
            self._deaddrop_in_progress = True
            if self._deaddrop_download_in_progress:
                # Download accepted: store expected file hash for integrity check
                self._deaddrop_download_expected_hash = str(inner.get("file_hash", ""))
                self.display_system_message("Deaddrop download accepted by server; confirming and waiting for data...")

                # Confirm we are ready to receive the file as per spec.
                confirm_inner = {"type": MessageType.DEADDROP_ACCEPT}
                confirm_outer = self._encrypt_deaddrop_inner(json.dumps(confirm_inner).encode("utf-8"))
                send_message(self.socket, json.dumps(confirm_outer).encode("utf-8"))
            else:
                self.display_system_message("Deaddrop upload accepted by server")
        elif inner_type == MessageType.DEADDROP_DENY:
            reason = inner.get("reason", "Deaddrop request denied")
            self.display_error_message(reason)
            self._deaddrop_in_progress = False
            self._deaddrop_download_in_progress = False
        elif inner_type == MessageType.DEADDROP_REDOWNLOAD:
            # Server requests retransmission of specific chunk indexes.
            # We rely on stored chunks from the last upload invocation.
            indexes = inner.get("chunk_indexes", [])
            if not isinstance(indexes, list):
                return
            for idx in indexes:
                try:
                    i_int = int(idx)
                except (ValueError, TypeError):
                    continue
                chunk = self._deaddrop_chunks.get(i_int)
                if chunk is None:
                    continue
                ct_b64 = base64.b64encode(chunk).decode("utf-8")
                inner_msg = {
                    "type": MessageType.DEADDROP_DATA,
                    "chunk_index": i_int,
                    "ct": ct_b64,
                }
                outer_msg = self._encrypt_deaddrop_inner(json.dumps(inner_msg).encode("utf-8"))
                send_message(self.socket, json.dumps(outer_msg).encode("utf-8"))
        elif inner_type == MessageType.DEADDROP_PROVE:
            # Server is asking us to prove deaddrop password knowledge.
            # This is part of the download flow.
            salt_b64 = inner.get("salt")
            if not isinstance(salt_b64, str):
                self.display_error_message("Invalid deaddrop prove message from server")
                return
            try:
                download_salt = base64.b64decode(salt_b64, validate=True)
            except binascii.Error:
                self.display_error_message("Invalid base64 salt in deaddrop prove message")
                return

            if not self._deaddrop_password_hash:
                self.display_error_message("No stored deaddrop password hash for download")
                return

            # Derive PBKDF2-SHA3-512 hash over the Argon2id hash from _hash_deaddrop_password
            pbk = PBKDF2HMAC(
                algorithm=hashes.SHA3_512(),
                length=32,
                salt=download_salt,
                iterations=800000,
            )
            og_hash_bytes = self._deaddrop_password_hash.encode("utf-8")
            client_hash = pbk.derive(og_hash_bytes)
            inner_msg = {
                "type": MessageType.DEADDROP_PROVE,
                "hash": base64.b64encode(client_hash).decode("utf-8"),
            }
            outer_msg = self._encrypt_deaddrop_inner(json.dumps(inner_msg).encode("utf-8"))
            send_message(self.socket, json.dumps(outer_msg).encode("utf-8"))
        elif inner_type == MessageType.DEADDROP_DATA:
            # Downloaded encrypted chunk from server during deaddrop download.
            if not self._deaddrop_download_in_progress:
                # Ignore stray data
                return
            try:
                chunk_index = int(inner["chunk_index"])
                ct_b64 = str(inner["ct"])
                chunk_data = base64.b64decode(ct_b64, validate=True)
            except (KeyError, ValueError, TypeError, binascii.Error):
                self.display_error_message("Malformed deaddrop data from server")
                return

            # Stream-decrypt and write directly to disk
            self._process_deaddrop_data_streaming(chunk_index, chunk_data)
        elif inner_type == MessageType.DEADDROP_COMPLETE:
            # Deaddrop upload or download completed.
            if self._deaddrop_download_in_progress:
                self._finalise_deaddrop_download()
            else:
                self.display_system_message("Deaddrop upload completed successfully")
            self._deaddrop_in_progress = False
            self._deaddrop_download_in_progress = False

    def _derive_deaddrop_file_key(self, password: str) -> bytes:
        """
        Derive a 64-byte DoubleEncryptor key from password using SHA3-512.

        This is separate from the Argon2id-based password_hash that is sent to
        the server for authentication.
        """
        digest = hashlib.sha3_512()
        digest.update(password.encode("utf-8"))
        # Optionally also mix server identifier to tie encryption to this server
        if self.server_identifier:
            digest.update(self.server_identifier.encode("utf-8"))

        return digest.digest()

    def _hash_deaddrop_password(self, password: str) -> str:
        """
        Compute Argon2id hash of password using server identifier as salt.
        """
        self.display_system_message("Hashing deaddrop password, program may be unresponsive.")
        time.sleep(0.2) # Wait a moment to allow the display to update
        salt = self.server_identifier.encode("utf-8") if self.server_identifier else b""
        hasher = Argon2id(
            salt=salt,
            memory_cost=1024 * 1024 * 4,
            iterations=4,
            lanes=4,
            length=64
        )
        return base64.b64encode(hasher.derive(password.encode("utf-8"))).decode("utf-8")

    def deaddrop_upload(self, name: str, password: str, file_path: str) -> None:
        """Perform deaddrop upload of a file.

        This assumes that ``start_deaddrop_handshake`` has been called and the
        shared secret derived. It encrypts the file with DoubleEncryptor using a
        SHA3-512-derived key from the provided password and uploads it in chunks
        via DEADDROP_DATA messages wrapped inside DEADDROP_MESSAGE.
        """
        if not self.deaddrop_shared_secret:
            self.display_error_message("Deaddrop not initialised - handshake required")
            return

        if not os.path.isfile(file_path):
            self.display_error_message(f"File not found: {file_path}")
            return

        file_size = os.path.getsize(file_path)
        if self.deaddrop_max_size and file_size > self.deaddrop_max_size:
            self.display_error_message("File exceeds maximum deaddrop size allowed by server")
            return

        key = self._derive_deaddrop_file_key(password)
        h = HMAC(key, hashes.SHA3_512())
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        file_hash = base64.b64encode(h.finalize()).decode("utf-8")

        password_hash = self._hash_deaddrop_password(password)
        self._deaddrop_file_size = file_size
        self._deaddrop_name = name
        self._deaddrop_password_hash = password_hash

        # Send DEADDROP_UPLOAD metadata over encrypted deaddrop channel
        inner_meta = {
            "type": MessageType.DEADDROP_UPLOAD,
            "name": name,
            "file_size": file_size,
            "file_hash": file_hash,
            "file_password_hash": password_hash,
        }
        outer_meta = self._encrypt_deaddrop_inner(json.dumps(inner_meta).encode("utf-8"))
        send_message(self.socket, json.dumps(outer_meta).encode("utf-8"))

        encryptor = StreamingDoubleEncryptor(key)
        self._deaddrop_chunks.clear()

        chunk_index = 0
        file_ext = os.path.splitext(file_path)[1][:12]
        header = file_ext.encode("utf-8").ljust(12, b"\x00")
        first_nonce = hashlib.sha3_256(self.server_identifier.encode("utf-8")).digest()[:16]
        second_nonce = os.urandom(16)
        header += second_nonce
        with open(file_path, "rb") as f:
            first = True
            while True:
                if first:
                    chunk_data = f.read(SEND_CHUNK_SIZE - 28)
                    plaintext_chunk = header + chunk_data
                    first = False
                    nonce = first_nonce
                else:
                    chunk_data = f.read(SEND_CHUNK_SIZE)
                    plaintext_chunk = chunk_data
                    nonce = second_nonce
                if not chunk_data:
                    break

                ct = encryptor.encrypt(nonce, plaintext_chunk)
                ct_b64 = base64.b64encode(ct).decode("utf-8")
                inner = {
                    "type": MessageType.DEADDROP_DATA,
                    "chunk_index": chunk_index,
                    "ct": ct_b64,
                }
                outer = self._encrypt_deaddrop_inner(json.dumps(inner).encode("utf-8"))
                ok, err = send_message(self.socket, json.dumps(outer).encode("utf-8"))
                if not ok:
                    self.display_error_message(f"Failed to send chunk: {err}")
                    chunk_index += 1
                    continue

                chunk_index += 1
                if chunk_index % 50 == 0:
                    self.display_system_message(f"{shared.bytes_to_human_readable(chunk_index * 1024 * 1024)}/" +
                                                f"{shared.bytes_to_human_readable(file_size)} sent")

        # Notify completion of upload
        complete_inner = {"type": MessageType.DEADDROP_COMPLETE}
        complete_outer = self._encrypt_deaddrop_inner(json.dumps(complete_inner).encode("utf-8"))
        send_message(self.socket, json.dumps(complete_outer).encode("utf-8"))
        self.display_system_message("Deaddrop upload complete")
    
    def deaddrop_check(self, name: str) -> None:
        """Check whether a deaddrop with ``name`` exists on the server.

        This uses the existing deaddrop encrypted channel established via
        :meth:`start_deaddrop_handshake`. It deliberately does *not* start a
        new handshake, so multiple checks can be performed without
        renegotiating keys. Callers are responsible for ensuring that the
        handshake has completed successfully before invoking this method.
        """
        if not self.deaddrop_shared_secret:
            self.display_error_message("Deaddrop not initialised - handshake required")
            return

        # Remember last queried name so DEADDROP_CHECK_RESPONSE can refer to it
        self._deaddrop_name = name

        inner = {
            "type": MessageType.DEADDROP_CHECK,
            "name": name,
        }
        outer = self._encrypt_deaddrop_inner(json.dumps(inner).encode("utf-8"))
        send_message(self.socket, json.dumps(outer).encode("utf-8"))

    def deaddrop_download(self, name: str, password: str) -> None:
        """
        Initiate client-side deaddrop download flow for the given name.

        Follows deaddrop.txt: first checks existence, then proves password, and
        finally receives DoubleEncryptor-encrypted chunks which are decrypted
        locally using a SHA3-512-derived key.
        """
        if not self.deaddrop_shared_secret:
            self.display_error_message("Deaddrop not initialised - handshake required")
            return

        self._deaddrop_name = name
        self._deaddrop_password_hash = self._hash_deaddrop_password(password)
        self._deaddrop_download_in_progress = True
        # Reset old buffered approach state (no longer used) and init streaming state
        self._deaddrop_download_chunks.clear()
        self._deaddrop_download_max_index = -1
        self._deaddrop_download_expected_hash = None
        # Prepare DoubleEncryptor for subsequent decryption; we keep key/secret
        # and nonce per chunk will be reconstructed from metadata.
        key = self._derive_deaddrop_file_key(password)
        self._deaddrop_download_key = key
        self._deaddrop_download_otp_secret = key
        # Reset streaming variables
        self._deaddrop_dl_encryptor = None
        self._deaddrop_dl_next_nonce = None
        self._deaddrop_dl_expected_index = 0
        # Clean up any prior partial file for same name
        self._deaddrop_dl_part_path = None
        if self._deaddrop_dl_file:
            try:
                self._deaddrop_dl_file.close()
            except Exception:
                pass
            self._deaddrop_dl_file = None

        inner_dl = {
            "type": MessageType.DEADDROP_DOWNLOAD,
            "name": name,
        }
        outer_dl = self._encrypt_deaddrop_inner(json.dumps(inner_dl).encode("utf-8"))
        send_message(self.socket, json.dumps(outer_dl).encode("utf-8"))

    def _finalise_deaddrop_download(self) -> None:
        """
        Finalise deaddrop download: close .part file and atomically rename to final
        name by removing the .part extension. All decryption and writing occurs during
        streaming in _process_deaddrop_data_streaming.
        """
        # Close any open file handle
        if self._deaddrop_dl_file:
            try:
                self._deaddrop_dl_file.close()
            except Exception:
                pass
            finally:
                self._deaddrop_dl_file = None

        if not self._deaddrop_dl_part_path:
            self.display_error_message("No deaddrop partial file to finalise")
            return

        part_path = self._deaddrop_dl_part_path
        final_path = part_path[:-5] if part_path.lower().endswith(".part") else part_path
        try:
            # On Windows, os.replace will overwrite if exists
            os.replace(part_path, final_path)
        except Exception as exc:
            self.display_error_message(f"Failed to finalise deaddrop file: {exc}")
            return

        expected_b64 = self._deaddrop_download_expected_hash or ""
        key = self._deaddrop_download_key
        if not expected_b64:
            self.display_system_message("Deaddrop: no expected HMAC provided by server; skipped verification.")
            return
        elif key is None:
            self.display_error_message("Deaddrop: missing key for HMAC verification; file kept as-is.")
            return

        if isinstance(expected_b64, str) and expected_b64.startswith("b'") and expected_b64.endswith("'"):
            expected_b64 = expected_b64[2:-1]
        try:
            expected_hmac = base64.b64decode(expected_b64, validate=True)
        except binascii.Error:
            self.display_error_message("Deaddrop: invalid base64 expected HMAC provided by server; file kept as-is.")
            return

        h = HMAC(key, hashes.SHA3_512())
        with open(final_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        computed_hmac = h.finalize()

        if computed_hmac == expected_hmac:
            self.display_system_message("Deaddrop file integrity verified (HMAC OK).")
        else:
            self.display_error_message("Deaddrop file HMAC verification failed, file will be kept as-is."
                                       f"Computed HMAC: {base64.b64encode(computed_hmac).decode('utf-8')},"
                                       f"Expected HMAC: {base64.b64encode(expected_hmac).decode('utf-8')}")



        self.display_system_message(f"Deaddrop download complete, saved to: {final_path}")
        # Reset streaming state
        self._deaddrop_dl_encryptor = None
        self._deaddrop_dl_next_nonce = None
        self._deaddrop_dl_expected_index = 0
        self._deaddrop_dl_part_path = None

    def _process_deaddrop_data_streaming(self, chunk_index: int, chunk_data: bytes) -> None:
        """
        Stream-decrypt incoming deaddrop chunk and write plaintext to a .part file.

        First chunk (index 0) contains 12-byte extension header and 16-byte next nonce.
        It is decrypted using the initial nonce derived from server_identifier. The
        remainder of the first chunk (after 28 bytes) is written to disk, and output
        .part file is created as: [deaddrop name].[extension].part

        Subsequent chunks are decrypted with the extracted next nonce and appended.
        """
        # Enforce in-order chunks for simplicity
        if chunk_index != self._deaddrop_dl_expected_index:
            # For minimal change, just ignore unexpected chunks
            self.display_error_message(
                f"Unexpected deaddrop chunk index {chunk_index}, expected {self._deaddrop_dl_expected_index}")
            return

        if (chunk_index+1) % 100 == 0:
            size_so_far = shared.bytes_to_human_readable(self._deaddrop_dl_bytes_downloaded)
            self.display_system_message(f"Received {size_so_far} so far")

        if self._deaddrop_download_key is None:
            self.display_error_message("Deaddrop key not initialised")
            return

        if self._deaddrop_dl_encryptor is None:
            self._deaddrop_dl_encryptor = StreamingDoubleEncryptor(self._deaddrop_download_key)

        try:
            if chunk_index == 0:
                # Decrypt with initial nonce
                first_nonce = hashlib.sha3_256(self.server_identifier.encode("utf-8")).digest()[:16]
                pt = self._deaddrop_dl_encryptor.decrypt(first_nonce, chunk_data)
                if len(pt) < 28:
                    self.display_error_message("First deaddrop chunk too small to contain header")
                    return
                ext_header = pt[:12]
                self._deaddrop_dl_next_nonce = pt[12:28]
                body = pt[28:]
                self._deaddrop_dl_bytes_downloaded += len(body)

                # Build output .part path
                file_ext = ext_header.rstrip(b"\x00").decode("utf-8", errors="ignore")
                safe_name = "".join(c for c in self._deaddrop_name if c.isalnum() or c in ("-", "_")) or "deaddrop"
                if file_ext:
                    final_name = safe_name + (file_ext if file_ext.startswith(".") else ("." + file_ext))
                else:
                    final_name = safe_name
                part_path = final_name + ".part"

                # Open file for writing
                try:
                    f = open(part_path, "wb")
                except Exception as exc:
                    self.display_error_message(f"Failed to open deaddrop output file: {exc}")
                    return
                self._deaddrop_dl_file = f
                self._deaddrop_dl_part_path = part_path

                # Write body
                if body:
                    try:
                        f.write(body)
                    except Exception as exc:
                        self.display_error_message(f"Failed to write to deaddrop file: {exc}")
                        try:
                            f.close()
                        except Exception:
                            pass
                        self._deaddrop_dl_file = None
                        # Try to remove partial file
                        try:
                            os.remove(part_path)
                        except Exception:
                            pass
                        return
            else:
                # Subsequent chunks use the second nonce extracted from first chunk
                if not self._deaddrop_dl_next_nonce:
                    self.display_error_message("Missing deaddrop streaming nonce")
                    return
                if not self._deaddrop_dl_file:
                    self.display_error_message("Deaddrop output file not open")
                    return
                pt = self._deaddrop_dl_encryptor.decrypt(self._deaddrop_dl_next_nonce, chunk_data)
                self._deaddrop_dl_bytes_downloaded += len(pt)
                try:
                    self._deaddrop_dl_file.write(pt)
                except Exception as exc:
                    self.display_error_message(f"Failed to write to deaddrop file: {exc}")
                    return
        except Exception as exc:
            self.display_error_message(f"Failed to process deaddrop chunk: {exc}")
            return
        finally:
            # Increment expected index only if this chunk was the expected one
            if chunk_index == self._deaddrop_dl_expected_index:
                self._deaddrop_dl_expected_index += 1
    
    def handle_server_version_info(self, message_data: bytes) -> None:
        """Handle server version information."""
        message = json.loads(message_data)
        
        # Store server protocol version information
        self.server_protocol_version = message.get("protocol_version", "0.0.0")
        if self.server_protocol_version == "0.0.0":
            self.display_error_message("Server returned invalid protocol version information, communication may " +
                                       "still work but may be unreliable or have missing features.")
        
        self.display_system_message(f"Server Protocol Version: v{self.server_protocol_version}")
        # Parse and display server identifier if provided
        identifier = message.get("identifier", "")
        if isinstance(identifier, str) and identifier.strip():
            self.server_identifier = identifier.strip()
            self.display_system_message(f"Server Identifier: {self.server_identifier}")
        
        # Check compatibility
        if self.server_protocol_version != PROTOCOL_VERSION:
            self.display_system_message(f"Protocol version mismatch: Client v{PROTOCOL_VERSION}, " +
                                        f"Server v{self.server_protocol_version}")
            # Use local compatibility matrix since server no longer sends it
            major_server = self.server_protocol_version.split('.')[0]
            major_client = PROTOCOL_VERSION.split('.')[0]
            if major_server != major_client:
                self.display_error_message("Versions may not be compatible - communication issues possible")
    
    def on_server_disconnect(self, reason: str) -> None:
        """Hook: called when server notifies of server-initiated disconnect."""
        self.display_system_message(f"\nServer disconnected: {reason}")
        self.disconnect()
    
    def _send_file_chunks(self, transfer_id: str, file_path: str) -> None:
        """Send file chunks to peer."""
        try:
            # Get transfer info including compression setting
            transfer_info = self.pending_file_transfers[transfer_id]
            total_chunks = int(transfer_info["metadata"]["total_chunks"])
            compress = transfer_info.get("compress", True)
            
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
    
    def start_chat(self) -> None:
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
        print("  /deaddrop upload - Upload a file to deaddrop")
        print("  /deaddrop check <name> - Check if a deaddrop exists")
        print("  /deaddrop download <name> - Download a deaddrop file")
        print("  /help - Show this help message")
        print()
        
        try:
            while self.connected:
                if not (self.key_exchange_complete and self.verification_complete):
                    time.sleep(0.2)
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
                        print("  /deaddrop upload - Upload a file to deaddrop")
                        print("  /deaddrop check <name> - Check if a deaddrop exists")
                        print("  /deaddrop download <name> - Download a deaddrop file")
                        print("  /rekey - Initiate a rekey for fresh session keys")
                        print("  /help - Show this help message")
                    elif message.lower().strip() == '/deaddrop upload':
                        # Terminal deaddrop upload flow
                        try:
                            name = input("Deaddrop name: ").strip()
                            password = input("Deaddrop password: ")
                            file_path = input("File path: ").strip()
                        except (EOFError, KeyboardInterrupt):
                            print("Deaddrop upload cancelled.")
                            continue
                        if not (name and password and file_path):
                            print("Deaddrop upload aborted: missing fields")
                            continue
                        # Start handshake then upload
                        self.start_deaddrop_handshake()
                        if not self.wait_for_deaddrop_handshake(3.0):
                            print("Deaddrop handshake failed.")
                            continue
                        self.deaddrop_upload(name, password, file_path)

                    elif message.lower().startswith('/deaddrop check'):
                        parts = message.split(maxsplit=2)
                        name = parts[2] if len(parts) >= 3 else ""
                        if not name:
                            print("Usage: /deaddrop check <name>")
                            continue

                        # Start handshake only if we don't already have a
                        # deaddrop shared secret; this avoids rehandshakes on
                        # every check and allows multiple checks per session.
                        if not self.deaddrop_shared_secret:
                            self.start_deaddrop_handshake()
                            if not self.wait_for_deaddrop_handshake(3.0):
                                print("Deaddrop handshake failed.")
                                continue

                        self.deaddrop_check(name)

                    elif message.lower().startswith('/deaddrop download'):
                        parts = message.split(maxsplit=2)
                        name = parts[2] if len(parts) >= 3 else ""
                        if not name:
                            print("Usage: /deaddrop download <name>")
                            continue
                        try:
                            password = input("Deaddrop password: ")
                        except (EOFError, KeyboardInterrupt):
                            print("Deaddrop download cancelled.")
                            continue
                        if not password:
                            print("Deaddrop download aborted: missing password")
                            continue
                        self.start_deaddrop_handshake()
                        if not self.wait_for_deaddrop_handshake(3.0):
                            print("Deaddrop handshake failed.")
                            continue
                        self.deaddrop_download(name, password)

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
        # If the key exchange was complete there is a peer, notify them of disconnect
        self.end_call(notify_peer=self.key_exchange_complete and self.connected)
        self.protocol.stop_sender_thread()
        self.close_audio()
        
        if self.connected:
            shared.send_message(self.socket, json.dumps({"type": MessageType.CLIENT_DISCONNECT}).encode('utf-8'))
            
        self.connected = False
        try:
            self.socket.close()
        except Exception:
            pass
        
        # Wait for receive thread to finish cleanly
        if self.receive_thread and self.receive_thread.is_alive():
            try:
                self.receive_thread.join(timeout=1.0)
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
    client = SecureChatClient()
    
    if client.connect(host, port):
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
