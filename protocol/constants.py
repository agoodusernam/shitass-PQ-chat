from enum import IntEnum, unique
from typing import Final

# Protocol constants
PROTOCOL_VERSION: Final[str] = "8.1.0"
# Protocol compatibility is denoted by version number
# Breaking.Minor.Patch - only Breaking versions are checked for compatibility.
# Breaking version changes introduce breaking changes that are not compatible with the previous major version.
# Minor version changes may add or change features but remain largely compatible with previous minor versions of the same major version.
# Patch versions are for bug fixes and minor changes that do not affect compatibility.

# File transfer constants
SEND_CHUNK_SIZE: Final[int] = 1024 * 1024  # 1 MiB chunks for sending
MAGIC_NUMBER_FILE_TRANSFER: Final[bytes] = b"\x89"
MAGIC_NUMBER_DEADDROPS: Final[bytes] = b"\x45"

# Cryptographic size constants
NONCE_SIZE: Final[int] = 12  # bytes, for ChaCha20-Poly1305 and AES-GCM-SIV nonces
CTR_NONCE_SIZE: Final[int] = 16  # bytes, for AES-CTR / deaddrop chunk nonces
PAD_SIZE: Final[int] = 512 * 8 # bits, for PKCS7 padding
CLIENT_RANDOM_SIZE: Final[int] = 32  # bytes, for key exchange client randoms
DOUBLE_KEY_SIZE: Final[int] = 64  # bytes, for double-encryptor keys (32 AES + 32 ChaCha)
single_key_size: float = DOUBLE_KEY_SIZE / 2
if not single_key_size.is_integer():
    raise ValueError("DOUBLE_KEY_SIZE must be divisible by 2 without remainder")
SINGLE_KEY_SIZE: Final[int] = DOUBLE_KEY_SIZE // 2
HKDF_KEY_LENGTH: Final[int] = 64  # bytes, output length for HKDF key derivations
DEADDROP_KDF_KEY_LENGTH: Final[int] = 32  # bytes, output length for deaddrop KDF derivations
VERIFICATION_HASH_SIZE: Final[int] = 32  # bytes, truncated verification hash
BLAKE2B_DIGEST_SIZE: Final[int] = 32  # bytes, digest size for BLAKE2b file hashing
TRANSFER_ID_LENGTH: Final[int] = 32  # characters, hex transfer ID truncation length
FINGERPRINT_HASH_SIZE: Final[int] = 32  # bytes, truncated hash for key fingerprint generation
FINGERPRINT_WORD_COUNT: Final[int] = 8  # number of words in a key fingerprint
HASH_TO_WORDS_DEFAULT: Final[int] = 16  # default number of words for hash_to_words

# Deaddrop constants
DEADDROP_SALT_SIZE: Final[int] = 32  # bytes, salt for deaddrop download PBKDF2
DEADDROP_PBKDF2_ITERATIONS: Final[int] = 800_000  # iterations for deaddrop download hash
DEADDROP_FILE_EXT_HEADER_SIZE: Final[int] = 12  # bytes, file extension header in deaddrop chunks
DEADDROP_HKDF_SALT_SIZE: Final[int] = 32  # bytes, salt for deaddrop file key HKDF
MISSING_CHUNKS_LIMIT: Final[int] = 20000
DEADDROP_MIN_CHUNK_SIZE: Final[int] = 2048  # bytes, minimum chunk size for deaddrop
DEADDROP_MAX_CHUNKS: Final[int] = 1024 * 1024 # max amount of chunks that can be in a deaddrop upload (to prevent mem exhaustion)

# Nickname / sanitisation limits
MAX_SANITIZED_STR_LENGTH: Final[int] = 32

# Struct / frame layout sizes
MAGIC_SIZE: Final[int] = 1  # bytes, magic number prefix
COUNTER_SIZE: Final[int] = 4  # bytes, message counter (uint32)
# Yes, this is TECHNICALLY a vulnerability since it COULD overflow
# However, that would only occur after 4 billion messages in one session,
# as such, this is a reasonable tradeoff for simplicity.
HEADER_LENGTH_SIZE: Final[int] = 2  # bytes, file chunk header length prefix (uint16)
DEADDROP_LENGTH_PREFIX_SIZE: Final[int] = 4  # bytes, length prefix in deaddrop data

# Computed frame offsets for file chunk: [magic][counter][nonce][eph_pub][ciphertext]
FILE_CHUNK_COUNTER_OFFSET: Final[int] = MAGIC_SIZE
FILE_CHUNK_NONCE_OFFSET: Final[int] = MAGIC_SIZE + COUNTER_SIZE
FILE_CHUNK_EPH_PUB_OFFSET: Final[int] = MAGIC_SIZE + COUNTER_SIZE + NONCE_SIZE
FILE_CHUNK_CIPHERTEXT_OFFSET: Final[int] = MAGIC_SIZE + COUNTER_SIZE + NONCE_SIZE + SINGLE_KEY_SIZE

# Computed frame offsets for deaddrop data: [magic][nonce][ciphertext]
DEADDROP_NONCE_OFFSET: Final[int] = MAGIC_SIZE
DEADDROP_CIPHERTEXT_OFFSET: Final[int] = MAGIC_SIZE + NONCE_SIZE

# Network constants
MAX_MESSAGE_SIZE: Final[int] = 64 * 1024 * 1024  # 64 MiB

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
    KE_DSA_RANDOM = 4
    KE_MLKEM_PUBKEY = 5
    KE_MLKEM_CT_KEYS = 6
    KE_X25519_HQC_CT = 7
    KE_VERIFICATION = 8
    
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
