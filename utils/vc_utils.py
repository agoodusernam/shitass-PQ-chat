def format_rank_map() -> dict[int, int]:
    """Return a map from PyAudio format constant to a rank (higher is better)."""
    # Numeric constants for pyaudio formats
    # paFloat32 = 1, paInt32 = 2, paInt24 = 4, paInt16 = 8, paInt8 = 16, paUInt8 = 32
    return {
        32: 0,  # paUInt8
        16: 1,  # paInt8
        8:  2,  # paInt16
        4:  3,  # paInt24
        2:  4,  # paInt32
        1:  5,  # paFloat32
    }


def negotiate_audio_format(self_max: int, other_max: int) -> int:
    """
    Given this client's MAX format and the other's MAX format, return the highest
    format both support. This is the lower of the two maxima in rank order.
    """
    rank = format_rank_map()
    # Default to int16 (8) if unknown
    default_fmt = 8
    self_rank = rank.get(int(self_max), rank.get(default_fmt, 2))
    other_rank = rank.get(int(other_max), rank.get(default_fmt, 2))
    agreed_rank = min(self_rank, other_rank)
    # Find the format constant with this rank
    for fmt, r in rank.items():
        if r == agreed_rank:
            return fmt
    return default_fmt
