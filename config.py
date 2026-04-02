"""
Unified configuration module.

Provides a single ConfigHandler class that manages all application settings —
both static constants (voice, security, server) and runtime user preferences —
persisted as a single JSON file.

Usage::

    from config.config import ConfigHandler
    cfg = ConfigHandler()
    cfg["own_nickname"]            # runtime pref (str)
    cfg["voice_rate"]              # static constant (int)
    cfg.save()                     # persist to disk
"""
import json
from pathlib import Path
from typing import Any, Literal, TypedDict, get_type_hints, overload

__all__ = ["ConfigHandler"]

# ---------------------------------------------------------------------------
# Typed schema
# ---------------------------------------------------------------------------

class ConfigDict(TypedDict):
    # ---- Runtime user preferences ----------------------------------------
    notification_sound: bool
    system_notifications: bool
    auto_display_images: bool
    allow_voice_calls: bool
    allow_file_transfer: bool
    delivery_receipts: bool
    peer_nickname_change: bool
    own_nickname: str

    # ---- File paths (stored as strings in JSON, exposed as Path) ----------
    message_notif_sound_file: str
    ringtone_file: str
    wordlist_file: str
    deaddrop_file_location: str

    # ---- Voice settings ---------------------------------------------------
    voice_send_frequency: float
    voice_rate: int
    voice_channels: int
    voice_format: int

    # ---- Security settings ------------------------------------------------
    send_dummy_packets: bool
    max_dummy_packet_size: int
    rekey_interval: int

    # ---- Server settings --------------------------------------------------
    max_unexpected_msgs: int
    deaddrop_max_size: int
    deaddrop_enabled: bool


# Keys whose public type is Path (stored as str in JSON)
_PATH_KEYS: frozenset[str] = frozenset({
    "message_notif_sound_file",
    "ringtone_file",
    "wordlist_file",
    "deaddrop_file_location",
})

# Literal type aliases for overloaded __getitem__ / __setitem__
BoolKeys = Literal[
    "notification_sound",
    "system_notifications",
    "auto_display_images",
    "allow_voice_calls",
    "allow_file_transfer",
    "delivery_receipts",
    "peer_nickname_change",
    "send_dummy_packets",
    "deaddrop_enabled",
]
StrKeys = Literal["own_nickname"]
PathKeys = Literal[
    "message_notif_sound_file",
    "ringtone_file",
    "wordlist_file",
    "deaddrop_file_location",
]
IntKeys = Literal[
    "voice_rate",
    "voice_channels",
    "voice_format",
    "max_dummy_packet_size",
    "rekey_interval",
    "max_unexpected_msgs",
    "deaddrop_max_size",
]
FloatKeys = Literal["voice_send_frequency"]
ConfigKey = BoolKeys | StrKeys | PathKeys | IntKeys | FloatKeys

# Default config file location (relative to project root)
_DEFAULT_CONFIG_FILE = Path("config.json")


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def _create_default_config() -> ConfigDict:
    return ConfigDict(
        # Runtime user preferences
        notification_sound=True,
        system_notifications=True,
        auto_display_images=True,
        allow_voice_calls=True,
        allow_file_transfer=True,
        delivery_receipts=True,
        peer_nickname_change=True,
        own_nickname="",
        # File paths
        message_notif_sound_file="resources/notification_sound.wav",
        ringtone_file="resources/ringtone.wav",
        wordlist_file="resources/wordlist.txt",
        deaddrop_file_location="deaddrop_files",
        # Voice settings
        voice_send_frequency=100.0,
        voice_rate=44100,
        voice_channels=1,
        voice_format=8,
        # Security settings
        send_dummy_packets=True,
        max_dummy_packet_size=512,
        rekey_interval=480,
        # Server settings
        max_unexpected_msgs=10,
        deaddrop_max_size=1024 * 1024 * 1024 * 10,
        deaddrop_enabled=True,
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_CONFIG_TYPES: dict[str, type] = {}  # populated lazily


def _get_config_types() -> dict[str, type]:
    global _CONFIG_TYPES
    if not _CONFIG_TYPES:
        _CONFIG_TYPES = get_type_hints(ConfigDict)
    return _CONFIG_TYPES


def _validate(config: ConfigDict) -> None:
    """Raise ValueError/TypeError if any config value is out of range or wrong type."""
    for key, expected_type in _get_config_types().items():
        value = config[key]  # type: ignore[literal-required]
        # bool must be checked before int since bool is a subclass of int
        if expected_type is int and isinstance(value, bool):
            raise TypeError(
                f"Config key '{key}' must be int, got bool"
            )
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Config key '{key}' must be {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )

    if config["max_dummy_packet_size"] <= 0:
        raise ValueError("max_dummy_packet_size must be a positive integer")
    if config["voice_send_frequency"] <= 0:
        raise ValueError("voice_send_frequency must be positive")
    if config["voice_rate"] <= 0:
        raise ValueError("voice_rate must be positive")
    if config["voice_channels"] not in (1, 2):
        raise ValueError("voice_channels must be 1 (mono) or 2 (stereo)")
    if config["voice_format"] not in (1, 2, 4, 8, 16, 32):
        raise ValueError("voice_format must be a valid PyAudio format constant")
    if config["max_unexpected_msgs"] <= 0:
        raise ValueError("max_unexpected_msgs must be a positive integer")
    if config["deaddrop_max_size"] <= 0:
        raise ValueError("deaddrop_max_size must be a positive integer")
    if config["rekey_interval"] < 5:
        raise ValueError("rekey_interval must be at least 5")


# ---------------------------------------------------------------------------
# ConfigHandler
# ---------------------------------------------------------------------------

class ConfigHandler:
    """
    Manages all application configuration in a single JSON file.

    Path-typed keys (``message_notif_sound_file``, ``ringtone_file``,
    ``wordlist_file``, ``deaddrop_file_location``) are stored as plain
    strings in JSON but returned as :class:`pathlib.Path` objects.
    """

    def __init__(self, config_file: Path = _DEFAULT_CONFIG_FILE) -> None:
        self._config_file: Path = config_file
        self._config: ConfigDict = _create_default_config()
        self._ensure_exists()
        self._load()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_exists(self) -> None:
        if not self._config_file.exists():
            self.save()

    def _load(self) -> None:
        with open(self._config_file, "r", encoding="utf-8") as f:
            raw: dict[Any, Any] = json.load(f)
        self._merge(raw)

    def _merge(self, raw: dict[Any, Any]) -> None:
        """Merge *raw* JSON dict into the current config, validating types."""
        type_hints = _get_config_types()
        for key, value in raw.items():
            if not isinstance(key, str):
                raise ValueError(f"Config key {key!r} is not a string")
            if key not in type_hints:
                print(f"Warning: unknown config key {key!r}, skipping")
                continue
            expected_type = type_hints[key]
            # JSON numbers: int values are acceptable for float fields
            if expected_type is float and isinstance(value, int) and not isinstance(value, bool):
                value = float(value)
            # bool must be checked before int since bool is a subclass of int
            if expected_type is int and isinstance(value, bool):
                raise TypeError(
                    f"Config key '{key}' must be int, got bool"
                )
            if not isinstance(value, expected_type):
                raise TypeError(
                    f"Config key '{key}' must be {expected_type.__name__}, "
                    f"got {type(value).__name__}"
                )
            self._config[key] = value  # type: ignore[literal-required]
        _validate(self._config)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @overload
    def __getitem__(self, key: BoolKeys) -> bool: ...
    @overload
    def __getitem__(self, key: StrKeys) -> str: ...
    @overload
    def __getitem__(self, key: PathKeys) -> Path: ...
    @overload
    def __getitem__(self, key: IntKeys) -> int: ...
    @overload
    def __getitem__(self, key: FloatKeys) -> float: ...

    def __getitem__(self, key: ConfigKey) -> bool | str | Path | int | float:
        if not isinstance(key, str):
            raise TypeError("Config keys must be strings")
        value = self._config[key]  # type: ignore[literal-required]
        if key in _PATH_KEYS:
            return Path(value)  # type: ignore[arg-type]
        return value  # type: ignore[return-value]

    @overload
    def __setitem__(self, key: BoolKeys, value: bool) -> None: ...
    @overload
    def __setitem__(self, key: StrKeys, value: str) -> None: ...
    @overload
    def __setitem__(self, key: PathKeys, value: Path | str) -> None: ...
    @overload
    def __setitem__(self, key: IntKeys, value: int) -> None: ...
    @overload
    def __setitem__(self, key: FloatKeys, value: float) -> None: ...

    def __setitem__(self, key: ConfigKey, value: bool | str | Path | int | float) -> None:
        type_hints = _get_config_types()
        if key not in type_hints:
            raise KeyError(f"Unknown config key '{key}'")
        if key in _PATH_KEYS:
            if not isinstance(value, (str, Path)):
                raise TypeError(f"Config key '{key}' must be a str or Path")
            self._config[key] = str(value)  # type: ignore[literal-required]
            return
        expected_type = type_hints[key]
        if expected_type is int and isinstance(value, bool):
            raise TypeError(f"Config key '{key}' must be int, got bool")
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Config key '{key}' must be {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
        self._config[key] = value  # type: ignore[literal-required]

    def save(self) -> tuple[bool, str]:
        """Persist the current config to disk."""
        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_file, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=4)
            return True, ""
        except PermissionError:
            return False, "Insufficient permissions to write config file"
        except Exception as e:
            return False, str(e)

    def reload(self) -> tuple[bool, str]:
        """Re-read the config file from disk."""
        if not self._config_file.exists():
            return False, "Config file does not exist"
        try:
            self._load()
            return True, ""
        except json.JSONDecodeError:
            return False, "Config file is not valid JSON"
        except Exception as e:
            return False, str(e)

    @property
    def voice_chunk(self) -> int:
        """Derived value: samples per voice send chunk."""
        return round(self._config["voice_rate"] * (1.0 / self._config["voice_send_frequency"]))

    def __str__(self) -> str:
        return json.dumps(self._config, indent=4)
