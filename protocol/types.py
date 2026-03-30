from abc import ABC
from collections.abc import Sequence
from typing import Mapping, TypeAlias, TypedDict, NotRequired

from protocol.constants import MessageType


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
    compressed_size: int
    # Optional fields used by UI layers
    save_path: NotRequired[str]


class FileTransfer(TypedDict):
    file_path: str
    metadata: FileMetadata
    compress: bool


class DoubleEncryptorBase(ABC):
    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = False):
        ...
    
    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = False):
        ...


class DecodeError(Exception):
    pass
