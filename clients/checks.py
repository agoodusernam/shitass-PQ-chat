from typing import Any

from protocol import utils
from protocol.constants import MessageType


def allowed_unverified_inner_fields() -> set[str]:
    """Whitelist superset of allowed decrypted JSON fields before verification."""
    return {
        # common
        "type", "message", "reason", "text",
        # delivery
        "confirmed_counter",
        # file transfer
        "transfer_id", "filename", "file_size", "file_hash", "total_chunks", "processed_size", "compressed",
        # rekey
        "action", "public_key", "ciphertext",
        # dummy
        "data",
        # ephemeral mode / nickname
        "mode", "owner_id", "nickname",
        # voice call (GUI/client variants may use these)
        "rate", "chunk_size", "audio_format", "audio_data"
        }


def allowed_outer_fields(msg_type: Any) -> set[str]:
    """Whitelist of allowed top-level fields for pre-verification JSON messages."""
    base = {"type", "protocol_version", "version"}
    mt = MessageType(msg_type)
    
    server_control: list[MessageType] = [MessageType.KEEP_ALIVE, MessageType.KEY_EXCHANGE_COMPLETE,
                                         MessageType.INITIATE_KEY_EXCHANGE, MessageType.SERVER_FULL,
                                         MessageType.SERVER_VERSION_INFO, MessageType.SERVER_DISCONNECT,
                                         MessageType.ERROR]
    
    match mt:
        case MessageType.SERVER_VERSION_INFO:
            # Allow server identifier in version info announcement
            return base | {"identifier"}
        case MessageType.KEY_EXCHANGE_INIT:
            return base | {"mlkem_public_key", "dh_public_key", "hqc_public_key"}
        case MessageType.KEY_EXCHANGE_RESPONSE:
            return base | {"mlkem_ciphertext", "hqc_ciphertext", "mlkem_public_key", "hqc_public_key",
                           "dh_public_key"}
        case MessageType.ENCRYPTED_MESSAGE:
            return base | {"counter", "nonce", "ciphertext", "dh_public_key", "verification"}
        case MessageType.KEY_VERIFICATION:
            return base | {"verified"}
        case MessageType.KEY_EXCHANGE_RESET:
            return base | {"message"}
        case MessageType.DEADDROP_START:
            # Plaintext handshake: may include capability fields
            return base | {"supported", "max_file_size", "mlkem_public"}
        case MessageType.DEADDROP_MESSAGE:
            # Encrypted deaddrop envelope
            return base | {"nonce", "ciphertext"}
    
    if mt in server_control:
        # Allow common server control fields
        return base | {"reason", "message", "timestamp"}
    return base


def first_unexpected_field(obj: dict[Any, Any], allowed: set[str]) -> str | None:
    """Return the first key not in allowed or None if all keys allowed."""
    for k in obj.keys():
        if k not in allowed:
            return utils.sanitize_str(k)
    return None
