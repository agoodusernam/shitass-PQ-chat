from enum import IntEnum, unique
from typing import Final

# Protocol constants
PROTOCOL_VERSION: Final[str] = "8.0.0"
# Protocol compatibility is denoted by version number
# Breaking.Minor.Patch - only Breaking versions are checked for compatibility.
# Breaking version changes introduce breaking changes that are not compatible with previous versions of the same major version.
# Minor version changes may add features but remain compatible with previous minor versions of the same major version.
# Patch versions are for bug fixes and minor changes that do not affect compatibility.

# File transfer constants
SEND_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB chunks for sending
MAGIC_NUMBER_FILE_TRANSFER: Final[bytes] = b'\x89'
MAGIC_NUMBER_DEADDROPS: Final[bytes] = b'\x45'

# Incompressible file types where compression is wasteful
INCOMPRESSIBLE_EXTENSIONS: Final[set[str]] = {
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".lz4", ".7z", ".rar", ".hc", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".svgz",
    ".mp3", ".ogg", ".flac", ".aac", ".wav",
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mpeg", ".mpg",
    ".pdf", ".dmg", ".apk", ".jar",
}


@unique
class MessageType(IntEnum):
    NONE = -1
    # Key Exchange
    # Server to client
    INITIATE_KEY_EXCHANGE = 1
    
    KEY_EXCHANGE_RESET = 3
    # Client to client (multi-step key exchange)
    KE_DSA_RANDOM = 4  # Step 3/6: ML-DSA public key + client random
    KE_MLKEM_PUBKEY = 5  # Step 8: ML-KEM public key (signed)
    KE_MLKEM_CT_KEYS = 6  # Step 10: ML-KEM ciphertext + encrypted HQC/X25519 pubkeys
    KE_X25519_HQC_CT = 7  # Step 13: encrypted X25519 pubkey + encrypted HQC ciphertext
    KE_VERIFICATION = 8  # Step 15/16: key verification hash
    
    # Messaging
    ENCRYPTED_MESSAGE = 10
    DELIVERY_CONFIRMATION = 11
    DUMMY_MESSAGE = 12
    TEXT_MESSAGE = 13
    
    # File Transfer
    FILE_METADATA = 20
    FILE_ACCEPT = 21
    FILE_REJECT = 22
    FILE_CHUNK = 23
    FILE_COMPLETE = 24
    
    # Voice Call
    VOICE_CALL_INIT = 30
    VOICE_CALL_ACCEPT = 31
    VOICE_CALL_REJECT = 32
    VOICE_CALL_DATA = 33
    VOICE_CALL_END = 34
    
    # Server-to-Client Control
    SERVER_FULL = 40
    SERVER_VERSION_INFO = 41
    SERVER_DISCONNECT = 42
    ERROR = 43
    KEEP_ALIVE = 44
    
    # Client-to-Server Control
    CLIENT_DISCONNECT = 50
    KEEP_ALIVE_RESPONSE = 51
    
    # Client-to-Client Control
    EMERGENCY_CLOSE = 60
    EPHEMERAL_MODE_CHANGE = 61
    KEY_VERIFICATION = 62
    NICKNAME_CHANGE = 63
    REKEY = 64
    
    # Dead drop functionality
    DEADDROP_START = 70
    DEADDROP_KE_RESPONSE = 71
    
    DEADDROP_CHECK = 72
    DEADDROP_CHECK_RESPONSE = 73
    
    DEADDROP_UPLOAD = 74
    
    DEADDROP_DOWNLOAD = 75
    DEADDROP_REDOWNLOAD = 76
    
    DEADDROP_ACCEPT = 77
    DEADDROP_DENY = 78
    
    DEADDROP_DATA = 79
    DEADDROP_COMPLETE = 80
    DEADDROP_MESSAGE = 81
    DEADDROP_PROVE = 82
    
    @classmethod
    def _missing_(cls, value) -> "MessageType":
        return cls.NONE
