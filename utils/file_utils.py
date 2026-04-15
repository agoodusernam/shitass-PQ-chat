import gzip
import hashlib
from pathlib import Path


def safe_remove(path: Path) -> bool:
    """Remove a file path, ignoring errors."""
    try:
        path.unlink(missing_ok=True)
        return True
    except (PermissionError, OSError):
        return False


def cleanup_paths(paths: list[Path]) -> int:
    """Best-effort removal of a list of paths."""
    removed: int = 0
    for p in paths:
        if safe_remove(p):
            removed += 1
    return removed


def hash_file_hexdigest(path: Path) -> str:
    """Return BLAKE2b(32) hex digest of the file at `path`."""
    file_hash = hashlib.blake2b(digest_size=32)
    with open(path, 'rb') as f:
        while chunk := f.read(16384):
            file_hash.update(chunk)
    return file_hash.hexdigest()


def decompress_gzip_file(src: Path) -> Path:
    """Stream-decompress `src` gzip file to `src`.decompressed and return the new path."""
    dst = Path(str(src.resolve()) + ".part")
    with open(src, 'rb') as compressed_file:
        with gzip.GzipFile(fileobj=compressed_file, mode='rb') as gzip_file:
            with open(dst, 'wb') as decompressed_file:
                while chunk := gzip_file.read(16384):
                    decompressed_file.write(chunk)
    return dst
