from pathlib import Path
from typing import NotRequired, TypedDict


class FileMetadata(TypedDict):
    """
    Typed dict describing metadata about a file transfer.
    This is used to track incoming/outgoing file transfers and is shared across
    client and GUI code. It intentionally excludes the "type" field which is
    part of the on-the-wire message envelope.
    """
    transfer_id: str
    filename: str
    file_size: int
    file_hash: str
    total_chunks: int
    compressed: bool
    compressed_size: NotRequired[int]


class FileTransfer(TypedDict):
    file_path: Path
    metadata: FileMetadata
    compress: bool


class DecodeError(Exception):
    pass
