"""File transfer manager.

Owns outbound and inbound peer-to-peer file transfer state and frames:
metadata request / accept / reject / complete handshake, chunk assembly,
and the background chunk-sender thread.
"""
from __future__ import annotations

import os
import threading
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, Any

from SecureChatABCs.ui_base import UIBase
from config import ClientConfigHandler
from protocol.constants import MessageType
from protocol.create_messages import create_file_metadata_message
from protocol.parse_messages import process_file_metadata
from protocol.types import FileMetadata, FileTransfer
from protocol.utils import chunk_file
from utils.network_utils import send_message
from utils.threading_utils import ThreadSafeDict

if TYPE_CHECKING:
    from new_client import SecureChatClient

config = ClientConfigHandler()


class FileTransferManager:
    """Manages outgoing and incoming peer-to-peer file transfers."""

    def __init__(self, client: "SecureChatClient") -> None:
        self._client = client
        self.pending_file_transfers: ThreadSafeDict[str, FileTransfer] = ThreadSafeDict()
        self.active_file_metadata: ThreadSafeDict[str, FileMetadata] = ThreadSafeDict()
        self._last_progress_shown: dict[str, float | int] = {}

    # helpers

    @property
    def _ui(self) -> UIBase:
        return self._client.ui

    @property
    def _protocol(self):
        return self._client._protocol

    @property
    def _socket(self):
        return self._client._socket

    @property
    def _file_handler(self):
        return self._client.file_handler

    @property
    def active(self) -> bool:
        """True if any regular file transfer is in progress (outbound or inbound)."""
        return bool(self.pending_file_transfers or self.active_file_metadata)

    def clear(self) -> None:
        """Clear all in-flight transfer state (called on reset / emergency close)."""
        self.pending_file_transfers.clear()
        self.active_file_metadata.clear()
        self._last_progress_shown.clear()

    # outbound

    def send(self, file_path: Path | str, compress: bool = True) -> None:
        """Send a file to the peer by first transmitting its metadata and waiting for acceptance."""
        try:
            file_path_obj = Path(file_path) if isinstance(file_path, str) else file_path
            if not self._client.verification_complete:
                self._ui.display_error_message("Cannot send file: Key verification not complete")
                return

            if not self._client.peer_key_verified:
                self._ui.display_system_message(
                        "Warning: Sending file over an unverified connection. This is vulnerable to MitM attacks.",
                )

            metadata = create_file_metadata_message(
                    file_path_obj, compress=compress, chunk_size=config["send_chunk_size"])
            compress = metadata["compressed"]

            transfer_id = metadata["transfer_id"]
            self.pending_file_transfers[transfer_id] = FileTransfer(
                    file_path=file_path_obj,
                    metadata=metadata,
                    compress=compress,
            )
            metadata_message = deepcopy(dict(metadata))
            metadata_message["type"] = MessageType.FILE_METADATA
            self._protocol.queue_json(metadata_message)
            compression_text = "compressed" if compress else "uncompressed"
            self._ui.display_system_message(
                    f"File transfer request sent: {metadata['filename']} ({metadata['file_size']} bytes, {compression_text})",
            )

        except Exception as e:
            self._ui.display_error_message(f"Failed to send file: {e}")

    def reject(self, transfer_id: str) -> None:
        """Reject an incoming file transfer request identified by *transfer_id*."""
        self._protocol.queue_json({
            "type":        MessageType.FILE_REJECT,
            "transfer_id": transfer_id,
            "reason":      "User declined",
        })
        if transfer_id in self.active_file_metadata:
            del self.active_file_metadata[transfer_id]

    # incoming metadata / accept / reject / complete

    def handle_metadata(self, decrypted_message: dict[str, Any]) -> None:
        """Handle an incoming file transfer request: validate metadata, prompt user, send accept/reject."""
        try:
            metadata = process_file_metadata(decrypted_message)
        except KeyError as e:
            self._ui.display_error_message(str(e))
            return
        transfer_id = metadata["transfer_id"]
        if not self._client.allow_file_transfers:
            self._ui.display_system_message("File transfers are disabled. Ignoring incoming file.")
            self._protocol.queue_json({
                "type":        MessageType.FILE_REJECT,
                "transfer_id": transfer_id,
                "reason":      "User disabled file transfers",
            })
            return

        if not self._client.peer_key_verified:
            self._ui.display_system_message(
                    "Warning: Incoming file request over an unverified connection. "
                    "This is vulnerable to MitM attacks.",
            )

        self.active_file_metadata[transfer_id] = metadata

        compressed_size: int | None = (
                int(metadata["compressed_size"])
                if metadata.get("compressed", False) and "compressed_size" in metadata
                else None
        )
        result = self._ui.prompt_file_transfer(
                metadata["filename"],
                metadata["file_size"],
                metadata["total_chunks"],
                compressed_size,
        )

        if result is False or result is None:
            self._protocol.queue_json({
                "type":        MessageType.FILE_REJECT,
                "transfer_id": transfer_id,
                "reason":      "User declined",
            })
            del self.active_file_metadata[transfer_id]
        else:
            self._protocol.queue_json({
                "type":        MessageType.FILE_ACCEPT,
                "transfer_id": transfer_id,
            })
            self._protocol.send_dummy_messages = False

    def handle_accept(self, message: dict[str, Any]) -> None:
        """Peer accepted a pending transfer — start sending chunks in a background thread."""
        self._protocol.send_dummy_messages = False
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self._ui.display_error_message("Received acceptance without transfer ID")
            self._protocol.send_dummy_messages = True
            return

        with self.pending_file_transfers.lock:
            if transfer_id not in self.pending_file_transfers:
                self._ui.display_system_message("Received acceptance for unknown file transfer")
                self._protocol.send_dummy_messages = True
                return

            transfer_info = self.pending_file_transfers[transfer_id]
            file_path = transfer_info["file_path"]

        self._ui.display_system_message(
                f"File transfer accepted. Sending {transfer_info['metadata']['filename']}...")

        self._file_handler.sending_transfers[transfer_id] = transfer_info['metadata']

        threading.Thread(
                target=self._send_chunks,
                args=(transfer_id, file_path),
                daemon=True,
        ).start()

    def handle_reject(self, message: dict[str, Any]) -> None:
        """Peer rejected a pending transfer — clean up local state."""
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self._ui.display_error_message("Received rejection without transfer ID")
            return
        reason = message.get("reason", "Unknown reason")

        with self.pending_file_transfers.lock:
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                self._ui.display_system_message(f"File transfer rejected: {filename} - {reason}")
                self._file_handler.stop_sending_transfer(transfer_id)
                del self.pending_file_transfers[transfer_id]
            else:
                self._ui.display_error_message("Received rejection for unknown file transfer")

    def handle_complete(self, message: dict[str, Any]) -> None:
        """Peer acknowledged completion — clean up outgoing transfer state."""
        try:
            transfer_id = message["transfer_id"]
        except KeyError:
            self._ui.display_error_message("Dropped file complete message without transfer ID. Invalid JSON.")
            return

        if transfer_id in self.pending_file_transfers:
            filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
            self._ui.display_system_message(f"File transfer completed: {filename}")
            del self.pending_file_transfers[transfer_id]
            self._protocol.send_dummy_messages = True
        else:
            self._ui.display_error_message(f"Received file complete for unknown transfer ID: {transfer_id}")

    # inbound chunks

    def handle_chunk_binary(self, chunk_info: dict[str, Any]) -> None:
        """Store a received file chunk and reassemble once the transfer is complete."""
        transfer_id = chunk_info["transfer_id"]

        with self.active_file_metadata.lock:
            if transfer_id not in self.active_file_metadata:
                self._ui.display_error_message("Received chunk for unknown file transfer")
                return

            metadata = self.active_file_metadata[transfer_id]

        is_complete = self._file_handler.add_file_chunk(
                transfer_id,
                chunk_info["chunk_index"],
                chunk_info["chunk_data"],
                metadata["total_chunks"],
                chunk_size=config["send_chunk_size"],
        )

        received_chunks = len(self._file_handler.received_chunks.get(transfer_id, set()))
        progress = (received_chunks / metadata["total_chunks"]) * 100

        if transfer_id not in self._last_progress_shown:
            self._last_progress_shown[transfer_id] = -1

        if (progress - self._last_progress_shown[transfer_id] >= 10 or
                is_complete or
                received_chunks == 1):
            self._ui.file_download_progress(
                    transfer_id,
                    metadata["filename"],
                    received_chunks,
                    metadata["total_chunks"],
            )
            self._last_progress_shown[transfer_id] = progress

        if is_complete:
            output_path = os.path.join(os.getcwd(), metadata["filename"])

            counter = 1
            base_name, ext = os.path.splitext(metadata["filename"])
            while os.path.exists(output_path):
                output_path = os.path.join(os.getcwd(), f"{base_name}_{counter}{ext}")
                counter += 1

            try:
                compressed = metadata.get("compressed", True)
                self._file_handler.reassemble_file(
                        transfer_id, output_path, metadata["file_hash"],
                        compressed=compressed,
                )
                self._ui.on_file_transfer_complete(transfer_id, output_path)

                self._protocol.queue_json({
                    "type":        MessageType.FILE_COMPLETE,
                    "transfer_id": transfer_id,
                })

            except Exception as e:
                self._ui.display_error_message(f"File reassembly failed: {e}")

            with self.active_file_metadata.lock:
                if transfer_id in self.active_file_metadata:
                    del self.active_file_metadata[transfer_id]
            if transfer_id in self._last_progress_shown:
                del self._last_progress_shown[transfer_id]

    # outbound chunk-sender thread

    def _send_chunks(self, transfer_id: str, file_path: str) -> None:
        """Background thread: read, encrypt, and send all chunks for an accepted file transfer."""
        try:
            transfer_info = self.pending_file_transfers[transfer_id]
            total_chunks = int(transfer_info["metadata"]["total_chunks"])
            compress = transfer_info.get("compress", True)
            filename = transfer_info["metadata"]["filename"]

            chunk_generator = chunk_file(file_path, compress=compress, chunk_size=config["send_chunk_size"])
            bytes_transferred = 0

            for i, chunk in enumerate(chunk_generator):
                if transfer_id not in self.pending_file_transfers:
                    break

                result = send_message(self._socket, self._protocol.encrypt_file_chunk(transfer_id, i, chunk))
                if result is not None:
                    self._ui.display_error_message(f"File transfer failed while sending chunk {i}: {result}")
                    self._file_handler.stop_sending_transfer(transfer_id)
                    return

                bytes_transferred += len(chunk)

                update_frequency = 1 if total_chunks <= 10 else (5 if total_chunks <= 50 else 10)
                if (i + 1) % update_frequency == 0 or (i + 1) == total_chunks:
                    self._ui.file_upload_progress(
                            transfer_id,
                            filename,
                            i + 1,
                            total_chunks,
                            bytes_transferred,
                    )

            self._ui.display_system_message(f"File chunks sent successfully: {filename}")
            self._file_handler.stop_sending_transfer(transfer_id)

        except Exception as e:
            self._ui.display_error_message(f"Error sending file chunks: {e}")
            self._file_handler.stop_sending_transfer(transfer_id)
