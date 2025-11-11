import os

__all__ = []


def ensure_config_exists():
    """Generate default configs.py if it doesn't exist."""
    if os.path.exists("configs.py"):
        return
    
    default_config = '''"""
Generated default configuration file for the secure chat application.
"""
MESSAGE_NOTIF_SOUND_FILE = "notification_sound.wav"
VOICE_SEND_FREQUENCY = 100
RINGTONE_FILE = "ringtone.wav"
SEND_DUMMY_PACKETS = True
MAX_DUMMY_PACKET_SIZE = 512
WORDLIST_FILE = "wordlist.txt"
VOICE_RATE = 44100
VOICE_CHANNELS = 1
VOICE_CHUNK = int(VOICE_RATE * (1/VOICE_SEND_FREQUENCY))
VOICE_FORMAT = 2
MAX_UNEXPECTED_MSGS = 10
'''
    
    with open("configs.py", "w") as f:
        f.write(default_config)
    
    print("Generated default configs.py")


# Ensure config exists before anything imports it
try:
    ensure_config_exists()
except PermissionError as e:
    raise PermissionError("Could not create configs.py, please create it manually or contact the developer.") from e
except OSError as e:
    raise OSError("Could not create configs.py, please create it manually or contact the developer.") from e


def validate_configs() -> None:
    """Validate configuration settings."""
    try:
        import configs
    except ImportError as e:
        raise ImportError("configs.py could not be created. Contact the developer.") from e
    
    if configs.MAX_DUMMY_PACKET_SIZE <= 0 or not isinstance(configs.MAX_DUMMY_PACKET_SIZE, int):
        raise ValueError("MAX_DUMMY_PACKET_SIZE must be a positive number")
    
    if not isinstance(configs.SEND_DUMMY_PACKETS, bool):
        raise ValueError("SEND_DUMMY_PACKETS must be a True or False")
    
    if configs.VOICE_SEND_FREQUENCY <= 0 or not isinstance(configs.VOICE_SEND_FREQUENCY, int):
        raise ValueError("VOICE_SEND_FREQUENCY must be a positive number")
    
    if configs.VOICE_RATE <= 0 or not isinstance(configs.VOICE_RATE, int):
        raise ValueError("VOICE_RATE must be a positive number")
    
    if configs.VOICE_CHANNELS not in (1, 2):
        raise ValueError("VOICE_CHANNELS must be 1 (mono) or 2 (stereo)")
    
    if configs.VOICE_CHUNK <= 0 or not isinstance(configs.VOICE_CHUNK, int):
        raise ValueError("VOICE_CHUNK must be a positive number, if you didn't change VOICE_RATE or " +
                         "VOICE_SEND_FREQUENCY, something terrible has happened.")
    
    if configs.VOICE_FORMAT not in (1, 2, 4, 8, 16, 32):
        raise ValueError("VOICE_FORMAT must be a valid PyAudio format. Refer to PyAudio documentation.")
    
    if not os.path.isfile(configs.WORDLIST_FILE):
        raise FileNotFoundError(f"Wordlist file not found: {configs.WORDLIST_FILE}")
    
    if not os.path.isfile(configs.MESSAGE_NOTIF_SOUND_FILE):
        print(f"Warning: Notification sound file not found: {configs.MESSAGE_NOTIF_SOUND_FILE}")
    
    if not os.path.isfile(configs.RINGTONE_FILE):
        print(f"Warning: Ringtone file not found: {configs.RINGTONE_FILE}")
    
    if not configs.MAX_UNEXPECTED_MSGS > 0 or not isinstance(configs.MAX_UNEXPECTED_MSGS, int):
        raise ValueError("MAX_UNEXPECTED_MSGS must be a positive number")


validate_configs()
