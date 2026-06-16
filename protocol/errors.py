"""Unified exception hierarchy and error reporting for the chat stack.

Codes (:class:`ErrorCode`) carry the specific identity of an error. Exception
classes only group errors by broad subsystem; many codes share one class. Raise
sites pass ``code=ErrorCode.SOMETHING`` to override the class default.

Descriptions live in ``protocol/error_descriptions.json`` (hex-string keys,
e.g. ``"0x111"``). The UI receives ``(code, severity, context)`` via
:func:`dispatch_error` and resolves the description itself via :func:`describe`.
"""
import json
from enum import IntEnum
from pathlib import Path
from typing import Any, Final


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    ERROR = 2
    CRITICAL = 3


# ---------------------------------------------------------------------------
# Bit layout helpers
# ---------------------------------------------------------------------------
SYSTEM_SHIFT: Final[int] = 8
SUBSYSTEM_SHIFT: Final[int] = 4
NIBBLE_MASK: Final[int] = 0xF
CODE_MASK: Final[int] = 0xFFF


def split_code(code: int) -> tuple[int, int, int]:
    """Return ``(system, subsystem, subsubsystem)`` nibbles for *code*."""
    return (
        (code >> SYSTEM_SHIFT) & NIBBLE_MASK,
        (code >> SUBSYSTEM_SHIFT) & NIBBLE_MASK,
        code & NIBBLE_MASK,
    )


def format_code(code: int) -> str:
    """Format *code* as the canonical ``"0xABC"`` JSON key."""
    return f"0x{code & CODE_MASK:03X}"


class ErrorCode(IntEnum):
    # Generic
    UNKNOWN = 0xFFF

    # --- Protocol bases (0x1xx) ---
    PROTOCOL = 0x100
    CRYPTO = 0x110
    RATCHET = 0x120
    MESSAGE = 0x130
    CHUNK = 0x140

    # Protocol crypto (0x11x)
    PADDING = 0x111
    KEY_SIZE = 0x112
    KEY_NOT_READABLE = 0x113
    DECODE = 0x115

    # Protocol ratchet (0x12x)
    CHAIN_KEY_MISSING = 0x121
    COUNTER_UNEXPECTED = 0x122
    COUNTER_TOO_FAR = 0x123
    DH_KEY_MISSING = 0x124

    # Protocol message (0x13x)
    MESSAGE_DECODE = 0x131
    MESSAGE_FIELD_MISSING = 0x132
    MESSAGE_VERIFY = 0x133
    MESSAGE_DECRYPT = 0x134
    MESSAGE_TYPE = 0x135

    # Protocol chunk (0x14x)
    CHUNK_FORMAT = 0x141
    CHUNK_COUNTER = 0x142
    CHUNK_DECRYPT = 0x143
    CHUNK_HEADER = 0x144
    CHUNK_JSON = 0x145

    # --- Transport (0x2xx) ---
    TRANSPORT = 0x200
    SOCKET_SEND = 0x211
    SOCKET_RECV = 0x212
    CONNECTION_CLOSED = 0x213
    FRAME_TOO_LARGE = 0x221
    RATE_LIMITED = 0x223

    # --- Key exchange (0x3xx) ---
    KEY_EXCHANGE = 0x300
    KE_MLKEM_SIG = 0x311
    KE_MLKEM_CT_SIG = 0x312
    KE_X25519_HQC_SIG = 0x313
    KE_MISSING_PRIVATE_KEY = 0x321
    KE_MISSING_PEER_KEY = 0x322
    KE_VERIFICATION = 0x323
    KE_STATE = 0x320

    REKEY = 0x330
    REKEY_ABORTED = 0x331
    REKEY_VERIFY = 0x333

    # --- File transfer (0x4xx) ---
    FILE_TRANSFER = 0x400
    FT_INVALID_TRANSFER_ID = 0x411
    FT_INVALID_CHUNK_INDEX = 0x412
    FT_TEMP_FILE = 0x421
    FT_SEEK = 0x422
    FT_WRITE = 0x423
    FT_IO = 0x420
    FT_NO_ACTIVE_TRANSFER = 0x431
    FT_SIZE_MISMATCH = 0x432

    # --- Deaddrop (0x5xx) ---
    DEADDROP = 0x500
    DD_UPLOAD_REJECTED = 0x511
    DD_AUTH = 0x521
    DD_NOT_FOUND = 0x522
    DD_DECRYPT = 0x523
    DD_KE_FAILED = 0x531

    # --- Server (0x7xx) ---
    SERVER = 0x700
    SRV_DD_QUOTA = 0x721
    SRV_DD_IO = 0x722
    SRV_DD_AUTH = 0x723
    SRV_IDENTIFIER_MISSING = 0x731

    # --- Config (0x8xx) ---
    CONFIG = 0x800
    CFG_INVALID_VALUE = 0x821

    # --- UI / validation (0x9xx) ---
    UI = 0x900
    UNKNOWN_FIELD = 0x911


_SEVERITY_BY_CODE: Final[dict[int, Severity]] = {
    ErrorCode.RATE_LIMITED: Severity.WARNING,
    ErrorCode.KE_MLKEM_SIG: Severity.CRITICAL,
    ErrorCode.KE_MLKEM_CT_SIG: Severity.CRITICAL,
    ErrorCode.KE_X25519_HQC_SIG: Severity.CRITICAL,
    ErrorCode.KE_VERIFICATION: Severity.CRITICAL,
    ErrorCode.REKEY_VERIFY: Severity.CRITICAL,
    ErrorCode.SRV_IDENTIFIER_MISSING: Severity.CRITICAL,
}


_DESCRIPTIONS_PATH: Final[Path] = Path(__file__).with_name("error_descriptions.json")
_descriptions_cache: dict[str, str] | None = None


def _load_descriptions() -> dict[str, str]:
    global _descriptions_cache
    if _descriptions_cache is None:
        with _DESCRIPTIONS_PATH.open("r", encoding="utf-8") as f:
            _descriptions_cache = json.load(f)
    return _descriptions_cache


def describe(code: int) -> str:
    """Return the human description for *code*, or a fallback if missing."""
    table = _load_descriptions()
    return table.get(format_code(code), table.get("0xFFF", "Unknown error."))


class ChatError(Exception):
    """
    Base class for all chat-stack errors.

    Subclasses set :attr:`code` to a class-level default. Raise sites pass
    ``code=ErrorCode.SOMETHING`` to attach a specific code without needing a
    bespoke subclass. ``severity`` defaults from
    :data:`_SEVERITY_BY_CODE`; per-instance ``severity=`` overrides it.
    """

    code: int = int(ErrorCode.UNKNOWN)

    def __init__(
        self,
        message: str | None = None,
        *,
        code: int | None = None,
        context: dict[str, Any] | None = None,
        severity: Severity | None = None,
        cause: BaseException | None = None,
    ) -> None:
        if code is not None:
            self.code = int(code)
        self.context: dict[str, Any] = dict(context) if context else {}
        if severity is None:
            severity = _SEVERITY_BY_CODE.get(self.code, Severity.ERROR)
        self.severity: Severity = severity
        if cause is not None:
            self.__cause__ = cause
        super().__init__(message or describe(self.code))

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={format_code(self.code)}, "
            f"severity={self.severity.name}, context={self.context!r})"
        )


class ProtocolError(ChatError):
    code = int(ErrorCode.PROTOCOL)


class CryptoError(ProtocolError):
    code = int(ErrorCode.CRYPTO)


class RatchetError(ProtocolError):
    code = int(ErrorCode.RATCHET)


class MessageError(ProtocolError):
    code = int(ErrorCode.MESSAGE)


class ChunkError(ProtocolError):
    code = int(ErrorCode.CHUNK)


class TransportError(ChatError):
    """Network transport layer. Named ``TransportError`` rather than
    ``ConnectionError`` to avoid shadowing the Python builtin."""

    code = int(ErrorCode.TRANSPORT)


class ConnectionClosedError(TransportError):
    """Special-cased: callers catch this by type to detect peer disconnect."""

    code = int(ErrorCode.CONNECTION_CLOSED)


class KeyExchangeError(ChatError):
    code = int(ErrorCode.KEY_EXCHANGE)


class RekeyError(KeyExchangeError):
    code = int(ErrorCode.REKEY)


class FileTransferError(ChatError):
    code = int(ErrorCode.FILE_TRANSFER)


class DeaddropError(ChatError):
    code = int(ErrorCode.DEADDROP)


class ServerError(ChatError):
    code = int(ErrorCode.SERVER)


class ConfigError(ChatError):
    code = int(ErrorCode.CONFIG)


class UIError(ChatError):
    code = int(ErrorCode.UI)


def dispatch_error(sink: Any, exc: BaseException) -> None:
    """Forward *exc* to *sink* (an object exposing ``on_error``).

    Non-:class:`ChatError` exceptions are wrapped as :class:`ChatError` with
    the generic ``UNKNOWN`` code so the sink contract stays uniform.
    """
    if not isinstance(exc, ChatError):
        wrapped = ChatError(str(exc) or type(exc).__name__, cause=exc)
        wrapped.context = {"original_type": type(exc).__name__}
        exc = wrapped
    on_error = getattr(sink, "on_error", None)
    if on_error is None:
        return
    on_error(exc.code, exc.severity, dict(exc.context) if exc.context else None)
