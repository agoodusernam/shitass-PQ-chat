from __future__ import annotations

import gzip
import os
import tempfile
import typing
from pathlib import Path

from protocol.constants import SEND_CHUNK_SIZE
from protocol.types import FileMetadata
from utils.file_utils import (
    cleanup_paths,
    decompress_gzip_file,
    hash_file_hexdigest,
    safe_remove
)


class ProtocolFileHandler:
    """
    Handles all file and related IO for the protocol.
    """
    
    def __init__(self) -> None:
        self.received_chunks: dict[str, set[int]] = {}
        self.temp_file_paths: dict[str, Path] = {}
        self.open_file_handles: dict[str, typing.BinaryIO] = {}
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
                self.open_file_handles[transfer_id] = temp_file  # type: ignore
            
            except OSError as e:
                raise ValueError(f"Failed to create temporary file: {e}")
        
        # Get the open file handle
        file_handle = self.open_file_handles[transfer_id]
        
        position = chunk_index * SEND_CHUNK_SIZE
        
        try:
            file_handle.seek(position, 0)
            
            actual_position = file_handle.tell()
            if actual_position != position:
                raise ValueError(f"Failed to seek to position {position}, got {actual_position}")
            
            bytes_written = file_handle.write(chunk_data)
            if bytes_written != len(chunk_data):
                raise ValueError(f"Failed to write complete chunk: wrote {bytes_written} of {len(chunk_data)} bytes")
        
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
                        compressed: bool = True,
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
                final_file_path = decompress_gzip_file(temp_received_path)
                cleanup_on_error.append(final_file_path)
            
            # Verify file integrity
            if hash_file_hexdigest(final_file_path) != expected_hash:
                raise ValueError("File integrity check failed")
            
            # Move the final file to the output path
            final_file_path.replace(output_path)
            
            # Clean up the original received file if it was a compressed container
            if compressed and os.path.exists(temp_received_path):
                safe_remove(temp_received_path)
        
        except Exception as e:
            cleanup_paths(cleanup_on_error)
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
