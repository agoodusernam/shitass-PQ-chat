"""
Configuration module with separate client and server configs.

Provides ClientConfigHandler and ServerConfigHandler classes that manage
their respective settings, persisted as separate JSON files.

Usage::

    from config import ClientConfigHandler, ServerConfigHandler
    client_cfg = ClientConfigHandler()
    client_cfg["own_nickname"]
    client_cfg.save()

    server_cfg = ServerConfigHandler()
    server_cfg["max_unexpected_msgs"]
    server_cfg.save()
"""
import json
from pathlib import Path
from typing import Any, Literal, TypeAlias, TypedDict, get_type_hints, overload

__all__ = ["ClientConfigHandler", "ServerConfigHandler"]


class ClientConfigDict(TypedDict):
    # Runtime user preferences
    notification_sound: bool
    system_notifications: bool
    auto_display_images: bool
    allow_voice_calls: bool
    allow_file_transfer: bool
    delivery_receipts: bool
    peer_nickname_change: bool
    own_nickname: str
    theme: str

    # File paths (stored as strings in JSON, exposed as Path)
    message_notif_sound_file: str
    ringtone_file: str
    wordlist_file: str

    # Voice settings
    voice_send_frequency: float
    voice_rate: int
    voice_channels: int
    voice_format: int

    # Security settings
    send_dummy_packets: bool
    max_dummy_packet_size: int
    rekey_interval: int

    # Network / transfer settings
    send_chunk_size: int
    max_message_size: int
    max_nickname_length: int


# Keys whose public type is Path (stored as str in JSON)
_CLIENT_PATH_KEYS: frozenset[str] = frozenset({
    "message_notif_sound_file",
    "ringtone_file",
    "wordlist_file",
})

# Literal type aliases for overloaded __getitem__ / __setitem__
ClientBoolKeys = Literal[
    "notification_sound",
    "system_notifications",
    "auto_display_images",
    "allow_voice_calls",
    "allow_file_transfer",
    "delivery_receipts",
    "peer_nickname_change",
    "send_dummy_packets",
]
ClientStrKeys = Literal["own_nickname", "theme"]
ClientPathKeys = Literal[
    "message_notif_sound_file",
    "ringtone_file",
    "wordlist_file",
]
ClientIntKeys = Literal[
    "voice_rate",
    "voice_channels",
    "voice_format",
    "max_dummy_packet_size",
    "rekey_interval",
    "send_chunk_size",
    "max_message_size",
    "max_nickname_length",
]
ClientFloatKeys = Literal["voice_send_frequency"]
ClientConfigKey: TypeAlias = ClientBoolKeys | ClientStrKeys | ClientPathKeys | ClientIntKeys | ClientFloatKeys


def _create_default_client_config() -> ClientConfigDict:
    return ClientConfigDict(
            # Runtime user preferences
            notification_sound=True,
            system_notifications=True,
            auto_display_images=True,
            allow_voice_calls=True,
            allow_file_transfer=True,
            delivery_receipts=True,
            peer_nickname_change=True,
            own_nickname="",
            theme="dark",
            # File paths
            message_notif_sound_file="resources/notification_sound.wav",
            ringtone_file="resources/ringtone.wav",
            wordlist_file="resources/wordlist.txt",
            # Voice settings
            voice_send_frequency=100.0,
            voice_rate=44100,
            voice_channels=1,
            voice_format=8,
            # Security settings
            send_dummy_packets=True,
            max_dummy_packet_size=512,
            rekey_interval=2048,
            # Network / transfer settings
            send_chunk_size=1024 * 1024,
            max_message_size=64 * 1024 * 1024,
            max_nickname_length=32,
    )


_CLIENT_CONFIG_TYPES: dict[str, type] = {}


def _get_client_config_types() -> dict[str, type]:
    global _CLIENT_CONFIG_TYPES
    if not _CLIENT_CONFIG_TYPES:
        _CLIENT_CONFIG_TYPES = get_type_hints(ClientConfigDict)
    return _CLIENT_CONFIG_TYPES


def _validate_client(config: ClientConfigDict) -> None:
    """Raise ValueError/TypeError if any client config value is out of range or wrong type."""
    for key, expected_type in _get_client_config_types().items():
        value = config[key]  # type: ignore[literal-required]
        if expected_type is int and isinstance(value, bool):
            raise TypeError(
                    f"Config key '{key}' must be int, got bool",
            )
        if not isinstance(value, expected_type):
            raise TypeError(
                    f"Config key '{key}' must be {expected_type.__name__}, "
                    f"got {type(value).__name__}",
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
    if config["rekey_interval"] < 5:
        raise ValueError("rekey_interval must be at least 5")
    if config["send_chunk_size"] < 1024:
        raise ValueError("send_chunk_size must be at least 1024 bytes")
    if config["max_message_size"] < 1024:
        raise ValueError("max_message_size must be at least 1024 bytes")
    if config["max_nickname_length"] < 1:
        raise ValueError("max_nickname_length must be at least 1")


class ServerConfigDict(TypedDict):
    max_unexpected_msgs: int
    deaddrop_max_size: int
    deaddrop_enabled: bool
    deaddrop_file_location: str
    wordlist_file: str
    missing_chunks_limit: int
    deaddrop_max_chunks: int
    deaddrop_min_chunk_size: int
    max_message_size: int


_SERVER_PATH_KEYS: frozenset[str] = frozenset({
    "deaddrop_file_location",
    "wordlist_file",
})

ServerBoolKeys = Literal["deaddrop_enabled"]
ServerPathKeys = Literal[
    "deaddrop_file_location",
    "wordlist_file",
]
ServerIntKeys = Literal[
    "max_unexpected_msgs",
    "deaddrop_max_size",
    "missing_chunks_limit",
    "deaddrop_max_chunks",
    "deaddrop_min_chunk_size",
    "max_message_size",
]
ServerConfigKey: TypeAlias = ServerBoolKeys | ServerPathKeys | ServerIntKeys


def _create_default_server_config() -> ServerConfigDict:
    return ServerConfigDict(
            max_unexpected_msgs=10,
            deaddrop_max_size=1024 * 1024 * 1024 * 10,
            deaddrop_enabled=True,
            deaddrop_file_location="deaddrop_files",
            wordlist_file="resources/wordlist.txt",
            missing_chunks_limit=20000,
            deaddrop_max_chunks=1024 * 1024,
            deaddrop_min_chunk_size=2048,
            max_message_size=64 * 1024 * 1024,
    )


_SERVER_CONFIG_TYPES: dict[str, type] = {}


def _get_server_config_types() -> dict[str, type]:
    global _SERVER_CONFIG_TYPES
    if not _SERVER_CONFIG_TYPES:
        _SERVER_CONFIG_TYPES = get_type_hints(ServerConfigDict)
    return _SERVER_CONFIG_TYPES


def _validate_server(config: ServerConfigDict) -> None:
    """Raise ValueError/TypeError if any server config value is out of range or wrong type."""
    for key, expected_type in _get_server_config_types().items():
        value = config[key]  # type: ignore[literal-required]
        if expected_type is int and isinstance(value, bool):
            raise TypeError(
                    f"Config key '{key}' must be int, got bool",
            )
        if not isinstance(value, expected_type):
            raise TypeError(
                    f"Config key '{key}' must be {expected_type.__name__}, "
                    f"got {type(value).__name__}",
            )
    
    if config["max_unexpected_msgs"] <= 0:
        raise ValueError("max_unexpected_msgs must be a positive integer")
    if config["deaddrop_max_size"] <= 0:
        raise ValueError("deaddrop_max_size must be a positive integer")
    if config["missing_chunks_limit"] < 1:
        raise ValueError("missing_chunks_limit must be at least 1")
    if config["deaddrop_max_chunks"] < 1:
        raise ValueError("deaddrop_max_chunks must be at least 1")
    if config["deaddrop_min_chunk_size"] < 1:
        raise ValueError("deaddrop_min_chunk_size must be at least 1")
    if config["max_message_size"] < 1024:
        raise ValueError("max_message_size must be at least 1024 bytes")


class _BaseConfigHandler:
    """Common logic shared by client and server config handlers."""
    
    _path_keys: frozenset[str]
    instance = None
    
    def __init__(
            self,
            config_file: Path,
            default_factory: Any,
            type_getter: Any,
            validator: Any,
            path_keys: frozenset[str],
    ) -> None:
        self._config_file: Path = config_file
        self._config = default_factory()
        self._type_getter = type_getter
        self._validator = validator
        self._path_keys = path_keys
        self._ensure_exists()
        self._load()
    
    def _ensure_exists(self) -> None:
        if not self._config_file.exists():
            self.save()
    
    def _load(self) -> None:
        with open(self._config_file, "r", encoding="utf-8") as f:
            raw: dict[Any, Any] = json.load(f)
        self._merge(raw)
    
    def _merge(self, raw: dict[Any, Any]) -> None:
        """Merge *raw* JSON dict into the current config, validating types."""
        type_hints = self._type_getter()
        for key, value in raw.items():
            if not isinstance(key, str):
                raise ValueError(f"Config key {key!r} is not a string")
            if key not in type_hints:
                print(f"Warning: unknown config key {key!r}, skipping")
                continue
            expected_type = type_hints[key]
            if expected_type is float and isinstance(value, int) and not isinstance(value, bool):
                value = float(value)
            if expected_type is int and isinstance(value, bool):
                raise TypeError(
                        f"Config key '{key}' must be int, got bool",
                )
            if not isinstance(value, expected_type):
                raise TypeError(
                        f"Config key '{key}' must be {expected_type.__name__}, "
                        f"got {type(value).__name__}",
                )
            self._config[key] = value  # type: ignore[literal-required]
        self._validator(self._config)
    
    def _get(self, key: str) -> Any:
        if not isinstance(key, str):
            raise TypeError("Config keys must be strings")
        value = self._config[key]  # type: ignore[literal-required]
        if key in self._path_keys:
            return Path(value)  # type: ignore[arg-type]
        return value
    
    def _set(self, key: str, value: Any) -> None:
        type_hints = self._type_getter()
        if key not in type_hints:
            raise KeyError(f"Unknown config key '{key}'")
        if key in self._path_keys:
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
                    f"got {type(value).__name__}",
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
    
    def __str__(self) -> str:
        return json.dumps(self._config, indent=4)


# Client config

_DEFAULT_CLIENT_CONFIG_FILE = Path("client_config.json")


class ClientConfigHandler(_BaseConfigHandler):
    """
    Manages client configuration in a JSON file.

    Path-typed keys (``message_notif_sound_file``, ``ringtone_file``,
    ``wordlist_file``) are stored as plain strings in JSON but returned
    as :class:`pathlib.Path` objects.
    """
    instance = None
    
    def __new__(cls) -> "ClientConfigHandler":
        if cls.instance is None:
            cls.instance = super().__new__(cls)  # type: ignore
        return cls.instance
    
    def __init__(self, config_file: Path = _DEFAULT_CLIENT_CONFIG_FILE) -> None:
        super().__init__(
                config_file,
                _create_default_client_config,
                _get_client_config_types,
                _validate_client,
                _CLIENT_PATH_KEYS,
        )
    
    @overload
    def __getitem__(self, key: ClientBoolKeys) -> bool:
        ...
    
    @overload
    def __getitem__(self, key: ClientStrKeys) -> str:
        ...
    
    @overload
    def __getitem__(self, key: ClientPathKeys) -> Path:
        ...
    
    @overload
    def __getitem__(self, key: ClientIntKeys) -> int:
        ...
    
    @overload
    def __getitem__(self, key: ClientFloatKeys) -> float:
        ...
    
    def __getitem__(self, key: ClientConfigKey) -> bool | str | Path | int | float:
        return self._get(key)
    
    @overload
    def __setitem__(self, key: ClientBoolKeys, value: bool) -> None:
        ...
    
    @overload
    def __setitem__(self, key: ClientStrKeys, value: str) -> None:
        ...
    
    @overload
    def __setitem__(self, key: ClientPathKeys, value: Path | str) -> None:
        ...
    
    @overload
    def __setitem__(self, key: ClientIntKeys, value: int) -> None:
        ...
    
    @overload
    def __setitem__(self, key: ClientFloatKeys, value: float) -> None:
        ...
    
    def __setitem__(self, key: ClientConfigKey, value: bool | str | Path | int | float) -> None:
        self._set(key, value)
    
    @property
    def voice_chunk(self) -> int:
        """Derived value: samples per voice send chunk."""
        return round(self._config["voice_rate"] * (1.0 / self._config["voice_send_frequency"]))


# Server Config

_DEFAULT_SERVER_CONFIG_FILE = Path("server_config.json")


class ServerConfigHandler(_BaseConfigHandler):
    """
    Manages server configuration in a JSON file.

    Path-typed keys (``deaddrop_file_location``, ``wordlist_file``) are
    stored as plain strings in JSON but returned as :class:`pathlib.Path`
    objects.
    """
    instance = None
    
    def __new__(cls) -> "ServerConfigHandler":
        if cls.instance is None:
            cls.instance = super().__new__(cls)  # type: ignore
        return cls.instance
    
    def __init__(self, config_file: Path = _DEFAULT_SERVER_CONFIG_FILE) -> None:
        super().__init__(
                config_file,
                _create_default_server_config,
                _get_server_config_types,
                _validate_server,
                _SERVER_PATH_KEYS,
        )
    
    @overload
    def __getitem__(self, key: ServerBoolKeys) -> bool:
        ...
    
    @overload
    def __getitem__(self, key: ServerPathKeys) -> Path:
        ...
    
    @overload
    def __getitem__(self, key: ServerIntKeys) -> int:
        ...
    
    def __getitem__(self, key: ServerConfigKey) -> bool | Path | int:
        return self._get(key)
    
    @overload
    def __setitem__(self, key: ServerBoolKeys, value: bool) -> None:
        ...
    
    @overload
    def __setitem__(self, key: ServerPathKeys, value: Path | str) -> None:
        ...
    
    @overload
    def __setitem__(self, key: ServerIntKeys, value: int) -> None:
        ...
    
    def __setitem__(self, key: ServerConfigKey, value: bool | Path | str | int) -> None:
        self._set(key, value)
