from __future__ import annotations

import base64
import gzip
import json
import os
import struct
import tempfile
import typing
from pathlib import Path
from typing import Any, TYPE_CHECKING

from protocol.constants import SEND_CHUNK_SIZE, MAGIC_NUMBER_FILE_TRANSFER, MessageType
from protocol.types import FileMetadata
from protocol.crypto_classes import DoubleEncryptor
from file_utils import (
    _safe_remove,
    _cleanup_paths,
    _hash_file_hexdigest,
    _decompress_gzip_file,
)

if TYPE_CHECKING:
    from protocol.shared import SecureChatProtocol

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.exceptions import InvalidTag

from protocol.create_messages import (
    create_file_accept_message as _create_file_accept_dict,
    create_file_reject_message as _create_file_reject_dict,
)


class ProtocolFileHandler:
    """
    Handles all file and related IO for the protocol.
    """
    def __init__(self, protocol: SecureChatProtocol):
        self.protocol = protocol
        self.received_chunks: dict[str, set[int]] = {}
        self.temp_file_paths: dict[str, Path] = {}
        self.open_file_handles: dict[str, typing.IO] = {}
        self.sending_transfers: dict[str, FileMetadata] = {}
    
    def clear(self) -> None:
        self.received_chunks = {}
        # Close any open file handles
        for file_handle in self.open_file_handles.values():
            try:
                file_handle.close()
            except (OSError, ValueError):
                # Non-critical: file handle might already be closed or invalid
                pass
        self.open_file_handles = {}
        
        # Clean up any temporary files
        for temp_path in self.temp_file_paths.values():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except (OSError, PermissionError):
                pass
        self.temp_file_paths = {}
        self.sending_transfers = {}
    
    def stop_sending_transfer(self, transfer_id: str) -> None:
        """Stop tracking a sending file transfer."""
        if transfer_id in self.sending_transfers:
            del self.sending_transfers[transfer_id]
        
    @property
    def has_active_file_transfers(self) -> bool:
        """Check if any file transfers (sending or receiving) are currently active."""
        if self.received_chunks or self.open_file_handles or self.sending_transfers:
            return True
        return False
    
    def add_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes, total_chunks: int) -> bool:
        """
        Add a received file chunk and return True if file is complete.

        Instead of storing chunks in memory, this method writes them directly to a temporary file.
        It keeps track of which chunks have been received using a set of indices.
        Uses persistent file handles to avoid the performance overhead of opening/closing files for each chunk.
        """
        
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise ValueError(f"Invalid chunk index {chunk_index} for transfer with {total_chunks} chunks")
        
        if not transfer_id.isalnum():
            raise ValueError(f"Invalid transfer_id format: {transfer_id}")
        
        if len(transfer_id) > 64:
            raise ValueError(f"transfer_id too long: {len(transfer_id)} characters")
        
        # Initialise tracking structures if this is the first chunk for this transfer
        if transfer_id not in self.received_chunks:
            self.received_chunks[transfer_id] = set()
            
            try:
                temp_file = tempfile.NamedTemporaryFile(
                        mode='w+b',
                        prefix=f'transfer_{transfer_id}_',
                        suffix='.tmp',
                        delete=False,
                        )
                temp_file_path = Path(temp_file.name)
                
                # Store the path and handle
                self.temp_file_paths[transfer_id] = temp_file_path
                self.open_file_handles[transfer_id] = temp_file
            
            except OSError as e:
                raise ValueError(f"Failed to create secure temporary file: {e}")
        
        # Get the open file handle
        file_handle = self.open_file_handles[transfer_id]
        
        # Write the chunk to the temporary file at the correct position
        # Calculate the position based on chunk index and send chunk size
        # Use explicit 64-bit integer calculation to handle large files
        position = int(chunk_index) * int(SEND_CHUNK_SIZE)
        
        try:
            # Seek to the correct position with error handling for large files
            file_handle.seek(position, 0)  # 0 = SEEK_SET (absolute positioning)
            
            # Verify we're at the correct position
            actual_position = file_handle.tell()
            if actual_position != position:
                raise ValueError(f"Failed to seek to position {position}, got {actual_position}")
            
            # Write the chunk data
            bytes_written = file_handle.write(chunk_data)
            if bytes_written != len(chunk_data):
                raise ValueError(f"Failed to write complete chunk: wrote {bytes_written} of {len(chunk_data)} bytes")
            
            # Flush to ensure data is written to disk
            file_handle.flush()
        
        except (OSError, IOError) as e:
            raise ValueError(f"Failed to write chunk {chunk_index} at position {position}: {e}")
        
        # Mark this chunk as received
        self.received_chunks[transfer_id].add(chunk_index)
        
        # Check if all chunks are received
        is_complete = len(self.received_chunks[transfer_id]) == total_chunks
        
        # If transfer is complete, close the file handle
        if is_complete:
            file_handle.close()
            del self.open_file_handles[transfer_id]
        
        return is_complete
    
    def reassemble_file(self,
                        transfer_id: str,
                        output_path: str,
                        expected_hash: str,
                        compressed: bool = True
                        ) -> bool:
        """
        Finalise file transfer, optionally decompress, and verify integrity.
        """
        temp_received_path = self._close_and_get_temp_path(transfer_id)
        
        final_file_path = temp_received_path
        # Always remove the received temp file on error; also remove decompressed temp if created
        cleanup_on_error: list[Path] = [temp_received_path]
        
        try:
            if compressed:
                final_file_path = _decompress_gzip_file(temp_received_path)
                cleanup_on_error.append(final_file_path)
            
            # Verify file integrity
            if _hash_file_hexdigest(final_file_path) != expected_hash:
                raise ValueError("File integrity check failed")
            
            # Move the final file to the output path
            final_file_path.replace(output_path)
            
            # Clean up the original received file if it was a compressed container
            if compressed and os.path.exists(temp_received_path):
                _safe_remove(temp_received_path)
        
        except Exception as e:
            _cleanup_paths(cleanup_on_error)
            if isinstance(e, (OSError, IOError, gzip.BadGzipFile)):
                raise ValueError(f"File processing failed (I/O or gzip): {e}") from e
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"File processing failed (unexpected): {e}") from e
        
        # Clean up tracking data
        del self.received_chunks[transfer_id]
        del self.temp_file_paths[transfer_id]
        
        return True
    
    def _close_and_get_temp_path(self, transfer_id: str) -> Path:
        """Ensure transfer exists, close any open handle, and return the temp file path."""
        if transfer_id not in self.received_chunks or transfer_id not in self.temp_file_paths:
            raise ValueError(f"No data found for transfer {transfer_id}")
        
        if transfer_id in self.open_file_handles:
            try:
                self.open_file_handles[transfer_id].close()
            except OSError:
                pass
            del self.open_file_handles[transfer_id]
        
        temp_received_path = self.temp_file_paths[transfer_id]
        if not os.path.exists(temp_received_path):
            raise ValueError(f"Temporary file not found: {temp_received_path}")
        return temp_received_path
    
    # --- File transfer message creation and processing ---
    
    def create_file_accept_message(self, transfer_id: str) -> bytes:
        """Create a file acceptance message."""
        return self.protocol.encrypt_message(json.dumps(_create_file_accept_dict(transfer_id)))
    
    def create_file_reject_message(self, transfer_id: str, reason: str = "User declined") -> bytes:
        """Create a file rejection message."""
        return self.protocol.encrypt_message(json.dumps(_create_file_reject_dict(transfer_id, reason)))
    
    def create_file_chunk_message(self, transfer_id: str, chunk_index: int, chunk_data: bytes) -> bytes:
        """
        Create an optimised file chunk message with direct binary encryption and DH double ratchet.
        Frame layout: [1-byte magic number][4-byte counter][12-byte nonce][32-byte eph_pub][ciphertext]
        AAD covers type, counter, nonce, and dh_public_key.
        """
        proto = self.protocol
        if not proto.shared_key or not proto.send_chain_key:
            raise ValueError("No shared key or send chain key established")
        
        # Bump global message counter (shared with text messages) for unified ratchet state
        proto.message_counter += 1
        
        # Generate ephemeral X25519 key for this chunk
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
        peer_pub_bytes = proto.peer_dh_public_key_bytes
        if not peer_pub_bytes:
            raise ValueError("Missing peer DH public key for file chunk encryption")
        
        # Compute DH shared secret for this chunk and mix into send chain
        dh_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
        mixed_chain_key = proto._mix_dh_with_chain(proto.send_chain_key, dh_shared, proto.message_counter)
        
        # Derive unique message key for this chunk
        message_key = proto._derive_message_key(mixed_chain_key, proto.message_counter)
        
        # Ratchet the send chain key forward for the next message
        proto.send_chain_key = proto._ratchet_chain_key(proto.send_chain_key, proto.message_counter)
        
        # Create compact header
        header = {
            "type":        MessageType.FILE_CHUNK,
            "transfer_id": transfer_id,
            "chunk_index": chunk_index
            }
        header_json = json.dumps(header).encode('utf-8')
        
        # Encrypt header and chunk data in one operation
        nonce = os.urandom(12)
        
        # Create AAD including eph pub to authenticate ratchet key
        aad_data = {
            "type":          MessageType.FILE_CHUNK,
            "counter":       proto.message_counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(eph_pub_bytes).decode('utf-8'),
            }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Combine header length + header + chunk data for encryption
        header_len = struct.pack('!H', len(header_json))  # 2 bytes for header length
        plaintext = header_len + header_json + chunk_data
        encryptor = DoubleEncryptor(message_key, proto._hqc_secret, proto.message_counter)
        ciphertext = encryptor.encrypt(nonce, plaintext, aad)
        
        # This may or may not actually remove it from memory, but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        # Pack: counter (4 bytes) + nonce (12 bytes) + eph_pub (32 bytes) + ciphertext
        counter_bytes = struct.pack('!I', proto.message_counter)
        return MAGIC_NUMBER_FILE_TRANSFER + counter_bytes + nonce + eph_pub_bytes + ciphertext
    
    def process_file_chunk(self, encrypted_data: bytes) -> dict[Any, Any]:
        """
        Process an optimised file chunk message with binary format and DH double ratchet.
        Expects frame: [1-byte magic number][4-byte counter][12-byte nonce][32-byte eph_pub][ciphertext].
        """
        proto = self.protocol
        if not proto.shared_key or not proto.receive_chain_key:
            raise ValueError("No shared key or receive chain key established")
        if len(encrypted_data) < 1 + 4 + 12 + 32:
            raise ValueError("Invalid chunk message format")
        
        try:
            # Extract counter, nonce, peer ephemeral, and ciphertext from the message
            counter = int(struct.unpack('!I', encrypted_data[1:5])[0])
        except struct.error:
            raise ValueError("Invalid chunk message format")
        except ValueError:
            raise ValueError("Invalid counter in chunk message")
        
        nonce = encrypted_data[5:17]
        peer_eph_pub = encrypted_data[17:49]
        ciphertext = encrypted_data[49:]
        
        # Check for replay attacks or very old messages
        if counter <= proto.peer_counter:
            raise ValueError("Replay attack or out-of-order message detected. Expected > " +
                             f"{proto.peer_counter}, got {counter}")
        
        # Advance the chain key to the correct state for this message (symmetric ratchet)
        temp_chain_key = proto.receive_chain_key
        for i in range(proto.peer_counter + 1, counter):
            temp_chain_key = proto._ratchet_chain_key(temp_chain_key, i)
        
        # DH mix: use our receive private key for message-phase ratchet
        if not proto.msg_recv_private:
            raise ValueError("Local DH private key not initialized for file chunk ratchet")
        dh_shared = proto.msg_recv_private.exchange(X25519PublicKey.from_public_bytes(peer_eph_pub))
        mixed_chain_key = proto._mix_dh_with_chain(temp_chain_key, dh_shared, counter)
        
        # Derive the message key for the current message
        message_key = proto._derive_message_key(mixed_chain_key, counter)
        
        # Calculate what the new chain key state WOULD be (symmetric ratchet only)
        new_chain_key = proto._ratchet_chain_key(temp_chain_key, counter)
        
        # Create AAD including eph pub to authenticate ratchet key
        aad_data = {
            "type":          MessageType.FILE_CHUNK,
            "counter":       counter,
            "nonce":         base64.b64encode(nonce).decode('utf-8'),
            "dh_public_key": base64.b64encode(peer_eph_pub).decode('utf-8'),
            }
        aad = json.dumps(aad_data).encode('utf-8')
        
        # Decrypt the chunk payload with AAD verification
        decryptor = DoubleEncryptor(message_key, proto._hqc_secret, counter)
        try:
            plaintext = decryptor.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            message_key = b'\x00' * len(message_key)
            raise ValueError("File chunk decryption failed: InvalidTag")
        
        # Parse the decrypted header and extract chunk data
        if len(plaintext) < 2:
            raise ValueError("Invalid decrypted data: too short")
        
        try:
            header_len = struct.unpack('!H', plaintext[:2])[0]
        except struct.error:
            raise ValueError("Invalid decrypted data: header length")
        
        if len(plaintext) < 2 + header_len:
            raise ValueError("Invalid decrypted data: header length mismatch")
        
        header_json = plaintext[2:2 + header_len]
        chunk_data = plaintext[2 + header_len:]
        try:
            header = json.loads(header_json)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid decrypted data: header JSON decode failed")
        
        if header["type"] != MessageType.FILE_CHUNK:
            raise ValueError("Invalid message type in decrypted chunk")
        
        # Decryption successful, update the state
        proto.receive_chain_key = new_chain_key
        proto.peer_counter = counter
        # Store peer's latest eph public key for completeness
        proto.msg_peer_base_public = peer_eph_pub
        
        # This may or may not actually remove it from memory but it's better than nothing
        message_key = b'\x00' * len(message_key)
        del message_key
        
        return {
            "transfer_id": header["transfer_id"],
            "chunk_index": header["chunk_index"],
            "chunk_data":  chunk_data
            }
