from __future__ import annotations

import gzip
import os
import tempfile
import typing
from pathlib import Path

from protocol.constants import SEND_CHUNK_SIZE
from protocol.errors import (
    ErrorCode,
    ChatError,
    FileTransferError,
)
from protocol.types import FileMetadata
from utils.file_utils import (
    cleanup_paths,
    decompress_gzip_file,
    hash_file_hexdigest,
    safe_remove,
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
                pass
        self.open_file_handles = {}
        
        # Clean up any temporary files
        for temp_path in self.temp_file_paths.values():
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except (OSError, PermissionError):
                pass
        self.temp_file_paths = {}
        self.sending_transfers = {}
    
    def stop_sending_transfer(self, transfer_id: str) -> None:
        """Stop tracking a sending file transfer."""
        if transfer_id in self.sending_transfers:
            del self.sending_transfers[transfer_id]
    
    def clear_orphan_handles(self) -> None:
        """Close any open file handles that are not associated with a transfer."""
        ids_to_remove: list[str] = []
        for transfer_id, file_handle in self.open_file_handles.items():
            if transfer_id in self.sending_transfers:
                continue
            try:
                file_handle.close()
            except (OSError, ValueError):
                pass
            ids_to_remove.append(transfer_id)
        
        for transfer_id in ids_to_remove:
            del self.open_file_handles[transfer_id]
    
    @property
    def has_active_file_transfers(self) -> bool:
        """Check if any file transfers (sending or receiving) are currently active."""
        if self.received_chunks or self.open_file_handles or self.sending_transfers:
            return True
        return False
    
    def add_file_chunk(self, transfer_id: str, chunk_index: int, chunk_data: bytes, total_chunks: int, chunk_size: int = SEND_CHUNK_SIZE) -> bool:
        """
        Add a received file chunk and return True if file is complete.

        Instead of storing chunks in memory, this method writes them directly to a temporary file.
        It keeps track of which chunks have been received using a set of indices.
        Uses persistent file handles to avoid the performance overhead of opening/closing files for each chunk.
        """
        
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise FileTransferError(code=ErrorCode.FT_INVALID_CHUNK_INDEX, 
                context={"chunk_index": chunk_index, "total_chunks": total_chunks}
            )

        if not transfer_id.isalnum():
            raise FileTransferError(code=ErrorCode.FT_INVALID_TRANSFER_ID, context={"transfer_id": transfer_id, "reason": "non-alphanumeric"})

        if len(transfer_id) > 64:
            raise FileTransferError(code=ErrorCode.FT_INVALID_TRANSFER_ID, context={"length": len(transfer_id), "reason": "too long"})
        
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
                raise FileTransferError(code=ErrorCode.FT_TEMP_FILE, context={"error": str(e)}, cause=e)
        
        # Get the open file handle
        file_handle = self.open_file_handles[transfer_id]
        
        position = chunk_index * chunk_size
        
        try:
            file_handle.seek(position, 0)
            
            actual_position = file_handle.tell()
            if actual_position != position:
                raise FileTransferError(code=ErrorCode.FT_SEEK, context={"expected": position, "actual": actual_position})

            bytes_written = file_handle.write(chunk_data)
            if bytes_written != len(chunk_data):
                raise FileTransferError(code=ErrorCode.FT_WRITE, context={"written": bytes_written, "expected": len(chunk_data)})

        except (OSError, IOError) as e:
            raise FileTransferError(code=ErrorCode.FT_WRITE, 
                context={"chunk_index": chunk_index, "position": position, "error": str(e)},
                cause=e,
            )
        
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
                raise FileTransferError(code=ErrorCode.FT_SIZE_MISMATCH, 
                    context={"transfer_id": transfer_id, "reason": "integrity_hash_mismatch"}
                )
            
            # Move the final file to the output path
            final_file_path.replace(output_path)
            
            # Clean up the original received file if it was a compressed container
            if compressed and os.path.exists(temp_received_path):
                safe_remove(temp_received_path)
        
        except Exception as e:
            cleanup_paths(cleanup_on_error)
            if isinstance(e, ChatError):
                raise
            if isinstance(e, (OSError, IOError, gzip.BadGzipFile)):
                raise FileTransferError(code=ErrorCode.FT_IO, context={"transfer_id": transfer_id, "error": str(e)}, cause=e) from e
            raise FileTransferError(code=ErrorCode.FT_IO, 
                context={"transfer_id": transfer_id, "error": str(e), "kind": type(e).__name__},
                cause=e,
            ) from e
        
        # Clean up tracking data
        del self.received_chunks[transfer_id]
        del self.temp_file_paths[transfer_id]
        
        return True
    
    def _close_and_get_temp_path(self, transfer_id: str) -> Path:
        """Ensure transfer exists, close any open handle, and return the temp file path."""
        if transfer_id not in self.received_chunks or transfer_id not in self.temp_file_paths:
            raise FileTransferError(code=ErrorCode.FT_NO_ACTIVE_TRANSFER, context={"transfer_id": transfer_id})
        
        if transfer_id in self.open_file_handles:
            try:
                self.open_file_handles[transfer_id].close()
            except OSError:
                pass
            del self.open_file_handles[transfer_id]
        
        temp_received_path = self.temp_file_paths[transfer_id]
        if not os.path.exists(temp_received_path):
            raise FileTransferError(code=ErrorCode.FT_TEMP_FILE, 
                context={"transfer_id": transfer_id, "path": str(temp_received_path), "reason": "missing"}
            )
        return temp_received_path
