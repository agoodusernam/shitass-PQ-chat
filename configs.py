from typing import Final

# VOICE SETTINGS
VOICE_FORMAT: Final[int] = 2  # 32 bit integer PCM
VOICE_CHANNELS: Final[int] = 1
VOICE_RATE: Final[int] = 44100
VOICE_CHUNK: Final[int] = int(VOICE_RATE * 0.01)  # 10ms chunks
RINGTONE_FILE: Final[str] = "ringtone.wav"

# SECURITY SETTINGS
SEND_DUMMY_PACKETS: Final[bool] = True
