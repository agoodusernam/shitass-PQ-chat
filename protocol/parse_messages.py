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
            "compressed_size": message.get("compressed_size", message["file_size"])
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


def parse_ke_dsa_random(data: bytes) -> dict[str, Any]:
    """Parse a KE_DSA_RANDOM message (steps 3/6).
    
    Returns:
        dict with keys: mldsa_public_key, client_random, version_warning
    """
    try:
        message = json.loads(data)
        mldsa_public_key = base64.b64decode(message["mldsa_public_key"], validate=True)
        client_random = base64.b64decode(message["client_random"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, binascii.Error) as e:
        raise DecodeError(f"KE_DSA_RANDOM decode error: {type(e).__name__}") from e
    
    peer_version = message.get("version", "")
    version_warning = ""
    if peer_version and peer_version != PROTOCOL_VERSION:
        version_warning = (
                f"WARNING: Protocol version mismatch. Local: {PROTOCOL_VERSION}, Peer: {peer_version}. "
                "Communication may not work properly.")
    
    return {
        "mldsa_public_key": mldsa_public_key,
        "client_random":    client_random,
        "version_warning":  version_warning,
        }


def parse_ke_mlkem_pubkey(data: bytes) -> dict[str, Any]:
    """Parse a KE_MLKEM_PUBKEY message (step 8)."""
    try:
        message = json.loads(data)
        mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
        mldsa_signature = base64.b64decode(message["mldsa_signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, binascii.Error) as e:
        raise DecodeError(f"KE_MLKEM_PUBKEY decode error: {type(e).__name__}") from e
    
    return {
        "mlkem_public_key": mlkem_public_key,
        "mldsa_signature":  mldsa_signature,
        }


def parse_ke_mlkem_ct_keys(data: bytes) -> dict[str, Any]:
    """Parse a KE_MLKEM_CT_KEYS message (step 10)."""
    try:
        message = json.loads(data)
        mlkem_ciphertext = base64.b64decode(message["mlkem_ciphertext"], validate=True)
        encrypted_hqc_pubkey = base64.b64decode(message["encrypted_hqc_pubkey"], validate=True)
        encrypted_x25519_pubkey = base64.b64decode(message["encrypted_x25519_pubkey"], validate=True)
        nonce1 = base64.b64decode(message["nonce1"], validate=True)
        nonce2 = base64.b64decode(message["nonce2"], validate=True)
        mldsa_signature = base64.b64decode(message["mldsa_signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, binascii.Error) as e:
        raise DecodeError(f"KE_MLKEM_CT_KEYS decode error: {type(e).__name__}") from e
    
    signed_payload = mlkem_ciphertext + encrypted_hqc_pubkey + encrypted_x25519_pubkey + nonce1 + nonce2
    
    return {
        "mlkem_ciphertext":        mlkem_ciphertext,
        "encrypted_hqc_pubkey":    encrypted_hqc_pubkey,
        "encrypted_x25519_pubkey": encrypted_x25519_pubkey,
        "nonce1":                  nonce1,
        "nonce2":                  nonce2,
        "mldsa_signature":         mldsa_signature,
        "signed_payload":          signed_payload,
        }


def parse_ke_x25519_hqc_ct(data: bytes) -> dict[str, Any]:
    """Parse a KE_X25519_HQC_CT message (step 13)."""
    try:
        message = json.loads(data)
        encrypted_x25519_pubkey = base64.b64decode(message["encrypted_x25519_pubkey"], validate=True)
        encrypted_hqc_ciphertext = base64.b64decode(message["encrypted_hqc_ciphertext"], validate=True)
        nonce1 = base64.b64decode(message["nonce1"], validate=True)
        nonce2 = base64.b64decode(message["nonce2"], validate=True)
        mldsa_signature = base64.b64decode(message["mldsa_signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, binascii.Error) as e:
        raise DecodeError(f"KE_X25519_HQC_CT decode error: {type(e).__name__}") from e
    
    signed_payload = encrypted_x25519_pubkey + encrypted_hqc_ciphertext + nonce1 + nonce2
    
    return {
        "encrypted_x25519_pubkey":  encrypted_x25519_pubkey,
        "encrypted_hqc_ciphertext": encrypted_hqc_ciphertext,
        "nonce1":                   nonce1,
        "nonce2":                   nonce2,
        "mldsa_signature":          mldsa_signature,
        "signed_payload":           signed_payload,
        }


def parse_ke_verification(data: bytes) -> dict[str, Any]:
    """Parse a KE_VERIFICATION message (steps 15/16)."""
    try:
        message = json.loads(data)
        verification_key = base64.b64decode(message["verification_key"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, binascii.Error) as e:
        raise DecodeError(f"KE_VERIFICATION decode error: {type(e).__name__}") from e
    
    return {
        "verification_key": verification_key,
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
