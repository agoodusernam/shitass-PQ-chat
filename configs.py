from typing import Final

# VOICE SETTINGS
VOICE_FORMAT: Final[int] = 2  # 32 bit integer PCM
AUDIO_FORMAT: Final[int] = VOICE_FORMAT
VOICE_CHANNELS: Final[int] = 1
VOICE_RATE: Final[int] = 44100
VOICE_SAMPLERATE: Final[int] = VOICE_RATE
VOICE_CHUNK: Final[int] = int(VOICE_RATE * 0.01)  # 10ms chunks
VOICE_CHUNK_SIZE = VOICE_CHUNK
RINGTONE_FILE: Final[str] = "ringtone.wav"
VOICE_RINGING_FILE: Final[str] = RINGTONE_FILE

# SECURITY SETTINGS
SEND_DUMMY_PACKETS: Final[bool] = True