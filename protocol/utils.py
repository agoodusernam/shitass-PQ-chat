import gzip
import hashlib
import io
from collections import OrderedDict
from pathlib import Path
from typing import Generator

import numpy as np

from protocol.constants import (
    INCOMPRESSIBLE_EXTENSIONS, SEND_CHUNK_SIZE,
    FINGERPRINT_HASH_SIZE, FINGERPRINT_WORD_COUNT, HASH_TO_WORDS_DEFAULT,
    MAX_SANITIZED_STR_LENGTH,
)


class LRUCache:
    """
    Implements a Least Recently Used (LRU) Cache.

    This class provides a mechanism to store a fixed amount of key-value pairs
    with a limited capacity, evicting the least recently used items in order to
    maintain the constraint. The cache ensures that the most frequently accessed
    items are retained in memory, making it useful for scenarios where caching
    is needed and the data set exceeds available memory.

    :ivar _cache: Stores the key-value pairs in an ordered manner, enabling quick
        access and management of least recently used items.
    :type _cache: collections.OrderedDict[int, bytes]
    :ivar capacity: The maximum number of items that the cache can store at any
        given time.
    :type capacity: int
    """
    
    def __init__(self, capacity: int):
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self.capacity = capacity
    
    def __getitem__(self, key: int) -> bytes | None:
        if key not in self._cache:
            return None
        else:
            self._cache.move_to_end(key)
            return self._cache[key]
    
    def __setitem__(self, key: int, value: bytes) -> None:
        self._cache[key] = value
        self._cache.move_to_end(key)
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)
    
    def pop(self, key: int) -> bytes | None:
        if key in self._cache:
            value = self._cache.pop(key)
            return value
        else:
            return None


class StreamingGzipCompressor:
    """
    A streaming gzip compressor that yields compressed chunks as they're ready.

    Takes no arguments.
    """
    
    def __init__(self) -> None:
        self.buffer: io.BytesIO = io.BytesIO()
        self.compressor: gzip.GzipFile = gzip.GzipFile(fileobj=self.buffer, mode='wb', compresslevel=9)
    
    def compress_chunk(self, data: bytes) -> bytes:
        """
        Compress a chunk of data and return any available compressed output.

        :param data: The data to compress.

        :return: A compressed chunk of data, or an empty bytes object if no data is available.
        """
        if data:
            self.compressor.write(data)
        
        self.buffer.seek(0)
        compressed_data = self.buffer.read()
        
        # Reset buffer for next chunk
        self.buffer.seek(0)
        self.buffer.truncate(0)
        
        return compressed_data
    
    def finalise(self) -> bytes:
        """Finalise compression and return any remaining compressed data."""
        self.compressor.close()
        
        # Get any remaining compressed data
        self.buffer.seek(0)
        final_data = self.buffer.read()
        self.buffer.close()
        
        return final_data
    
    finalize = finalise


def decide_compression(file_path: Path, user_pref: bool = True) -> bool:
    """
    Decide whether to compress a file before sending.
    Compression is enabled only if the user prefers it AND the file is not of a
    type that's typically incompressible.
    """
    if not user_pref:
        return False
    
    return file_path.suffix not in INCOMPRESSIBLE_EXTENSIONS


def bytes_to_human_readable(size: int) -> str:
    """
    Convert a byte count to a human-readable format with appropriate units.
    
    Args:
        size (int): The number of bytes to convert.
        
    Returns:
        str: A formatted string with the size and the appropriate unit (B, KiB, MiB, or GiB).
    """
    if size < 1024:
        return f"{size} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KiB"
    if size < 1024 ** 3:
        return f"{size / 1024 ** 2:.1f} MiB"
    
    return f"{size / 1024 ** 3:.2f} GiB"


def xor_bytes(a: bytes, b: bytes) -> bytes:
    length = len(a) if len(a) > len(b) else len(b)
    equal_length = len(a) == len(b)
    # Below ~768 bytes, converting to int and back is faster than using numpy's bitwise_xor
    if length < 768:
        int_a = int.from_bytes(a, byteorder="little")
        int_b = int.from_bytes(b, byteorder="little")
        
        return (int_a ^ int_b).to_bytes(length, byteorder="little")
    
    if equal_length:
        pass
    elif len(a) < len(b):
        diff = len(b) - len(a)
        a = b'\x00' * diff + a
    else:
        diff = len(a) - len(b)
        b = b'\x00' * diff + b
    
    return np.bitwise_xor(np.frombuffer(a, dtype=np.uint8), np.frombuffer(b, dtype=np.uint8)).tobytes()


def load_wordlist(wordlist_file: Path) -> list[str]:
    """Load the wordlist from the given file path."""
    try:
        with open(wordlist_file.resolve(), 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        raise FileNotFoundError(
                f"{wordlist_file} not found. Please ensure the wordlist file is in the same directory as "
                "shared.py")


def hash_to_words(hash_bytes: bytes, wordlist: list[str], num_words: int = HASH_TO_WORDS_DEFAULT) -> list[str]:
    """Convert hash bytes to a list of words from the wordlist."""
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    
    words = []
    for i in range(num_words):
        index = (hash_int >> (i * 8)) % len(wordlist)
        words.append(wordlist[index])
    
    return words


def generate_key_fingerprint(key: bytes, wordlist_file: Path) -> str:
    """Generate a human-readable word-based fingerprint for a public key."""
    key_hash = hashlib.sha3_512(key).digest()[:FINGERPRINT_HASH_SIZE]
    wordlist = load_wordlist(wordlist_file)
    words = hash_to_words(key_hash, wordlist, num_words=FINGERPRINT_WORD_COUNT)
    return " ".join(words)


def sanitize_str(s: str) -> str:
    """Return ASCII-only str truncated to MAX_SANITIZED_STR_LENGTH chars; fallback to '?' if empty."""
    s = s.encode('ascii', errors='ignore').decode('ascii', errors='ignore')
    return s[:MAX_SANITIZED_STR_LENGTH] or "?"


def chunk_file(file_path: Path | str, compress: bool = True, chunk_size: int = SEND_CHUNK_SIZE) -> Generator[bytes, None, None]:
    """Generate file chunks for transmission one at a time.
    
    This is a streaming generator function that optionally compresses and yields chunks
    without loading the entire file into memory. This approach is memory-efficient
    for large files and provides a steady stream of data for network transmission.
    
    Args:
        file_path: Path to the file to chunk
        compress: Whether to compress the chunks (default: True)
        chunk_size: Size of each chunk (default: SEND_CHUNK_SIZE)
    """
    
    if not compress:
        # Send uncompressed chunks directly
        with open(file_path, 'rb') as original_file:
            while True:
                # Read a chunk from the original file
                file_chunk = original_file.read(chunk_size)
                if not file_chunk:
                    break
                yield file_chunk
        return

    # Use streaming compression
    compressor: StreamingGzipCompressor = StreamingGzipCompressor()
    pending_data: bytes = b""

    try:
        with open(file_path, 'rb') as original_file:
            while True:
                # Read a chunk from the original file
                file_chunk = original_file.read(chunk_size)

                if not file_chunk:
                    # End of file - finalize compression
                    final_compressed = compressor.finalise()
                    if final_compressed:
                        pending_data += final_compressed
                    break

                # Compress this chunk
                compressed_chunk = compressor.compress_chunk(file_chunk)
                if compressed_chunk:
                    pending_data += compressed_chunk

                # Yield complete chunks when we have enough data
                while len(pending_data) >= chunk_size:
                    yield pending_data[:chunk_size]
                    pending_data = pending_data[chunk_size:]
            
            # Yield any remaining data
            if pending_data:
                yield pending_data
    
    except (OSError, IOError) as e:
        try:
            compressor.finalise()
        except Exception:  # ignore finalise issues because we're already failing
            pass
        raise e
