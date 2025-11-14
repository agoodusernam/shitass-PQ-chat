"""
Here are some general settings for the application.
Each setting has a comment explaining what it does and its default value below it.

These are settings that are not intended to be changed during runtime.
They can be changed during runtime, but it may not work as expected.

You may also delete the file entirely to reset to defaults.
Note that the generated file will not include comments and may be ordered and formatted differently.
"""
from typing import Final

false = no = off = No = Off = False
true = yes = on = Yes = On = True

### CLIENT CONFIG
## GENERAL SETTINGS
MESSAGE_NOTIF_SOUND_FILE: Final[str] = "notification_sound.wav"
# The file to play for message notifications.
# Must be a WAV file, may be a relative or absolute path.
# Path must be surrounded by quotes. (" or ')
# Default: "notification_sound.wav"


## VOICE SETTINGS
VOICE_SEND_FREQUENCY: Final[float] = 100
# How many times per second to send voice data.
# Keep between 10 and 200 for a smooth experience
# Default: 100
# Range: 1 - 1000

RINGTONE_FILE: Final[str] = "ringtone.wav"
# The file to play for incoming calls.
# Must be a WAV file, may be a relative or absolute path.
# Path must be surrounded by quotes. (" or ')
# Default: "ringtone.wav"

## SECURITY SETTINGS
SEND_DUMMY_PACKETS: Final[bool] = True
# Whether to send dummy packets when idle to obfuscate traffic patterns.
# Must be True or False
# Default: True

MAX_DUMMY_PACKET_SIZE: Final[int] = 512
# Maximum size of dummy packets in bytes.
# Default: 512
# Range: 1 - 2048
# Ignored if SEND_DUMMY_PACKETS is False

WORDLIST_FILE: Final[str] = "wordlist.txt"
# The file containing the wordlist for generating human-readable key fingerprints.
# Must be a text file with one word per line, may be a relative or absolute path.
# Path must be surrounded by quotes. (" or ')
# Default: "wordlist.txt"

REKEY_INTERVAL: Final[int] = 480
# Base number of messages between automatic rekeys.
# Each client will choose a random interval around this value at runtime.
# Default: 480
# Range: 1 - 10000


## ADVANCED SETTINGS
# Don't change these unless you know what you're doing

# VOICE
VOICE_RATE: Final[int] = 44100  # Sampling rate in Hz
VOICE_CHANNELS: Final[int] = 1
VOICE_CHUNK: Final[int] = int(VOICE_RATE * (1 / VOICE_SEND_FREQUENCY))
VOICE_FORMAT: Final[int] = 8
"""
unsigned 8-bit integer: 32
8-bit integer: 16
16-bit integer: 8
24-bit integer: 4
32-bit integer: 2
32-bit float: 1
Default: 8 (16-bit integer)
See pyaudio documentation for more details.
"""

### SERVER CONFIG
MAX_UNEXPECTED_MSGS: Final[int] = 10
# Maximum number of unexpected messages a client can send before being disconnected.
# Default: 10

DEADDROP_FILE_LOCATION: Final[str] = "/deaddrop_files"
# Directory where deaddrop files are stored.
# Must be a relative or absolute path.
# Path must be surrounded by quotes. (" or ')
# Default: "/deaddrop_files"

DEADDROP_MAX_SIZE: Final[int] = 1024 * 1024 * 1024 * 10
# Maximum size of deaddrop files in bytes
# Default: 10 GiB

DEADDROP_ENABLED: Final[bool] = True
# Whether deaddrop is enabled.
# Must be True or False
# Default: False
