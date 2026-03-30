"""
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
