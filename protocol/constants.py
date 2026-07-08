"""Constants for the PQCP protocol."""
from enum import IntEnum, unique


@unique
class MessageType(IntEnum):
    """The message types for the PQCP protocol."""
    # Server control
    SERVER_HELLO = 0
    # Key Exchange
    KEX_START = 10
    KEX_INIT = 11
    KEX_INIT_REPLY = 12
    KEX_KEM = 13
    KEX_KEM_REPLY = 14
    KEX_DONE = 15
    KEX_VERIFY = 16
    KEX_VERIFY_REPLY = 17

    KEX_ABORT = 30
    KEX_FAIL = 31
    KEX_SERVER_MISMATCH = 32
    


