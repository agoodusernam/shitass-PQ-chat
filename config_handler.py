"""
The config handler module provides functionality to read, write, and manage configs during runtime.
"""
import inspect
import json
import os
from typing import Any, TypedDict

__all__ = ['ConfigHandler']

class ConfigDict(TypedDict):
    notification_sound: bool
    system_notifications: bool
    auto_display_images: bool
    allow_voice_calls: bool
    allow_file_transfer: bool
    delivery_receipts: bool
    peer_nickname_change: bool
    own_nickname: str


def create_default_config() -> ConfigDict:
    """
    :return: The default configuration dictionary.
    """
    return ConfigDict(
            notification_sound=True,
            system_notifications=True,
            auto_display_images=True,
            allow_voice_calls=True,
            allow_file_transfer=True,
            delivery_receipts=True,
            peer_nickname_change=True,
            own_nickname="",
    )


class ConfigHandler:
    """
    A class to handle reading and writing configuration files.
    """
    
    def __init__(self):
        self.config_file = "config.json"
        self.config: ConfigDict = create_default_config()
        self.init_config: dict[str, Any] = {}
        self.ensure_exists()
        with open(self.config_file) as config_file:
            self.init_config = json.load(config_file)
        
        self.validate_config()
    
    def validate_config(self):
        for key, value in self.init_config.items():
            if not isinstance(key, str):
                raise ValueError(f"Config key '{key}' is not a string")
            if not isinstance(value, (int, bool, str)):
                raise ValueError(f"Config value for key '{key}' must be str, int or bool")
            
            if key in inspect.get_annotations(ConfigDict):
                try:
                    expected_type = inspect.get_annotations(ConfigDict)[key]
                except KeyError:
                    print("Unknown config key: " + key + ", skipping...")
                    continue
                if not isinstance(value, expected_type):
                    raise ValueError(f"Config value for key '{key}' must be of type {expected_type.__name__}")
                
                if not key in self.config.keys():
                    raise ValueError(f"Unknown config key '{key}'")
                
                self.config[key] = value  # type: ignore
    
    def __getitem__(self, item: str):
        if not isinstance(item, str):
            raise TypeError("Config keys must be strings")
        if not item in self.config.keys():
            return None
        return self.config[item]  # type: ignore
    
    def __setitem__(self, key: str, value: Any):
        if not isinstance(key, str):
            raise TypeError("Config keys must be strings")
        
        if not key in self.config.keys():
            raise KeyError(f"Unknown config key '{key}'")
        
        try:
            expected_type = inspect.get_annotations(ConfigDict)[key]
        except KeyError:
            print(inspect.get_annotations(ConfigDict))
            raise KeyError(f"Unknown config key '{key}'")
        
        if expected_type and not isinstance(value, expected_type):
            raise TypeError(f"Config value for key '{key}' must be of type {expected_type.__name__}")
        
        self.config[key] = value  # type: ignore
    
    def save(self) -> tuple[bool, str]:
        try:
            with open("config.json", "w") as f:
                json.dump(self.config, f, indent=4)
            return True, ""
        except PermissionError:
            return False, "Insufficient permissions to write config file"
        except Exception as e:
            return False, str(e)
    
    def ensure_exists(self) -> tuple[bool, str]:
        if not os.path.exists(self.config_file):
            return self.save()
        return True, ""
        
    def reload(self) -> tuple[bool, str]:
        if not os.path.exists(self.config_file):
            return False, "Config file does not exist"
        try:
            with open(self.config_file, "r") as f:
                self.init_config = json.load(f)
            self.validate_config()
            return True, ""
        except json.JSONDecodeError:
            return False, "Config file is not valid JSON"
        except Exception as e:
            return False, str(e)
    
    def __str__(self) -> str:
        return json.dumps(self.config, indent=4)


config = ConfigHandler()
