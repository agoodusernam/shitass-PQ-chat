import base64
import binascii
import json
from typing import Any

from protocol.constants import PROTOCOL_VERSION
from protocol.types import FileMetadata, DecodeError


def process_file_metadata(message: dict[Any, Any]) -> FileMetadata:
    """Process a file metadata message."""
    try:
        return {
            "transfer_id":    message["transfer_id"],
            "filename":       message["filename"],
            "file_size":      message["file_size"],
            "file_hash":      message["file_hash"],
            "total_chunks":   message["total_chunks"],
            "compressed":     message.get("compressed", False),
            "processed_size": message.get("processed_size", message["file_size"])
            }
    except KeyError:
        raise KeyError("Invalid file metadata message")


def process_key_verification_message(data: bytes) -> bool:
    """Process a key verification message from peer."""
    try:
        message = json.loads(data)
        return message.get("verified", False)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DecodeError("Received invalid key verification message")


def parse_key_exchange_init(data: bytes) -> dict[str, Any]:
    """Parse a key exchange init message and return extracted fields.
    
    Returns:
        dict with keys: peer_version, mlkem_public_key, dh_public_key, hqc_public_key, version_warning
    """
    try:
        message = json.loads(data)
        peer_version = str(message["version"])
        mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
        dh_public_key = base64.b64decode(message["dh_public_key"], validate=True)
        hqc_public_key = base64.b64decode(message["hqc_public_key"], validate=True)
    except UnicodeDecodeError as e:
        raise ValueError("Key exchange init message contains invalid UTF-8 characters") from e
    except json.JSONDecodeError as e:
        raise ValueError("Key exchange init message could not be parsed") from e
    except KeyError as e:
        raise ValueError("Key exchange init message is missing required fields") from e
    except binascii.Error as e:
        raise ValueError("Key exchange init message contains invalid base64-encoded data") from e
    
    version_warning = ""
    if peer_version != "" and peer_version != PROTOCOL_VERSION:
        version_warning = (
                f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: {peer_version}. " +
                "Communication may not work properly.")
    
    return {
        "peer_version":    peer_version,
        "mlkem_public_key": mlkem_public_key,
        "dh_public_key":   dh_public_key,
        "hqc_public_key":  hqc_public_key,
        "version_warning": version_warning,
        }


def parse_key_exchange_response(data: bytes) -> dict[str, Any]:
    """Parse a key exchange response message and return extracted fields.
    
    Returns:
        dict with keys: mlkem_ciphertext, mlkem_public_key, hqc_ciphertext, hqc_public_key,
                        dh_public_key, version_warning
    
    Raises:
        DecodeError: Something was wrong with the received data
    """
    try:
        message = json.loads(data)
        mlkem_ciphertext = base64.b64decode(message["mlkem_ciphertext"], validate=True)
        mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
        hqc_ciphertext = base64.b64decode(message["hqc_ciphertext"], validate=True)
        hqc_public_key = base64.b64decode(message["hqc_public_key"], validate=True)
        dh_public_key = base64.b64decode(message["dh_public_key"], validate=True)
    except (UnicodeDecodeError, binascii.Error):
        raise DecodeError("Key exchange response decode error, UnicodeDecodeError")
    except json.JSONDecodeError:
        raise DecodeError("Key exchange response decode error, json.JSONDecodeError")
    except KeyError:
        raise DecodeError("Key exchange response decode error, KeyError")
    
    peer_version = message.get("version", None)
    version_warning = None
    if peer_version is not None and peer_version != PROTOCOL_VERSION:
        version_warning = (f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: " +
                           f"{peer_version}. Communication may not work properly.")
    
    return {
        "mlkem_ciphertext": mlkem_ciphertext,
        "mlkem_public_key": mlkem_public_key,
        "hqc_ciphertext":   hqc_ciphertext,
        "hqc_public_key":   hqc_public_key,
        "dh_public_key":    dh_public_key,
        "version_warning":  version_warning,
        }


def parse_rekey_init(message: dict[Any, Any]) -> dict[str, bytes]:
    """Parse a REKEY init payload and return extracted key material.
    
    Returns:
        dict with keys: mlkem_public_key, hqc_public_key, dh_public_key
    
    Raises:
        DecodeError: If the message cannot be decoded
    """
    try:
        mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
        hqc_public_key = base64.b64decode(message["hqc_public_key"], validate=True)
        dh_public_key = base64.b64decode(message["dh_public_key"], validate=True)
    except (binascii.Error, KeyError):
        raise DecodeError("REKEY init decode error, binascii.Error")
    
    return {
        "mlkem_public_key": mlkem_public_key,
        "hqc_public_key":   hqc_public_key,
        "dh_public_key":    dh_public_key,
        }


def parse_rekey_response(message: dict) -> dict[str, bytes]:
    """Parse a REKEY response payload and return extracted key material.
    
    Returns:
        dict with keys: mlkem_ciphertext, hqc_ciphertext, dh_public_key
    
    Raises:
        DecodeError: If the message cannot be decoded
        ValueError: If required fields are missing
    """
    try:
        mlkem_ciphertext = base64.b64decode(message.get("mlkem_ciphertext", ""), validate=True)
        hqc_ciphertext = base64.b64decode(message.get("hqc_ciphertext", ""), validate=True)
        dh_public_key = base64.b64decode(message.get("dh_public_key", ""), validate=True)
    except binascii.Error:
        raise DecodeError("REKEY response decode error, binascii.Error")
    
    if not mlkem_ciphertext:
        raise ValueError("Missing mlkem_ciphertext in REKEY response")
    if not hqc_ciphertext:
        raise ValueError("Missing hqc_ciphertext in REKEY response")
    if not dh_public_key:
        raise ValueError("Missing dh_public_key in REKEY response")
    
    return {
        "mlkem_ciphertext": mlkem_ciphertext,
        "hqc_ciphertext":   hqc_ciphertext,
        "dh_public_key":    dh_public_key,
        }
