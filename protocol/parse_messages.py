import base64
import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.constant_time import bytes_eq

from protocol.constants import PROTOCOL_VERSION
from protocol.types import DecodeError, FileMetadata


def process_file_metadata(message: dict[Any, Any]) -> FileMetadata:
    """Process a file metadata message."""
    try:
        return {
            "transfer_id":     message["transfer_id"],
            "filename":        Path(message["filename"]).name,
            "file_size":       message["file_size"],
            "file_hash":       message["file_hash"],
            "total_chunks":    message["total_chunks"],
            "compressed":      message.get("compressed", False),
            "compressed_size": message.get("compressed_size", message["file_size"]),
        }
    except KeyError:
        raise KeyError("Invalid file metadata message")


def process_key_verification_message(data: bytes) -> bool:
    """Process a key verification message from peer."""
    try:
        message = json.loads(data)
        if not isinstance(message, dict):
            raise DecodeError("Received invalid key verification message")
        return bool(message.get("verified", False))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DecodeError("Received invalid key verification message")


def parse_ke_dsa_random(data: bytes) -> dict[str, Any]:
    """Parse a KE_DSA_RANDOM message (steps 3/6).
    
    Returns:
        dict with keys: mldsa_public_key, client_random, version_warning
    """
    try:
        message = json.loads(data)
        if not isinstance(message, dict):
            raise DecodeError("KE_DSA_RANDOM decode error: not a JSON object")
        mldsa_public_key = base64.b64decode(message["mldsa_public_key"], validate=True)
        client_random = base64.b64decode(message["client_random"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error) as e:
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
        if not isinstance(message, dict):
            raise DecodeError("KE_MLKEM_PUBKEY decode error: not a JSON object")
        mlkem_public_key = base64.b64decode(message["mlkem_public_key"], validate=True)
        mldsa_signature = base64.b64decode(message["mldsa_signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error) as e:
        raise DecodeError(f"KE_MLKEM_PUBKEY decode error: {type(e).__name__}") from e
    
    return {
        "mlkem_public_key": mlkem_public_key,
        "mldsa_signature":  mldsa_signature,
    }


def parse_ke_mlkem_ct_keys(data: bytes) -> dict[str, Any]:
    """Parse a KE_MLKEM_CT_KEYS message (step 10)."""
    try:
        message = json.loads(data)
        if not isinstance(message, dict):
            raise DecodeError("KE_MLKEM_CT_KEYS decode error: not a JSON object")
        mlkem_ciphertext = base64.b64decode(message["mlkem_ciphertext"], validate=True)
        encrypted_hqc_pubkey = base64.b64decode(message["encrypted_hqc_pubkey"], validate=True)
        encrypted_x25519_pubkey = base64.b64decode(message["encrypted_x25519_pubkey"], validate=True)
        nonce1 = base64.b64decode(message["nonce1"], validate=True)
        nonce2 = base64.b64decode(message["nonce2"], validate=True)
        mldsa_signature = base64.b64decode(message["mldsa_signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error) as e:
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
        if not isinstance(message, dict):
            raise DecodeError("KE_X25519_HQC_CT decode error: not a JSON object")
        encrypted_x25519_pubkey = base64.b64decode(message["encrypted_x25519_pubkey"], validate=True)
        encrypted_hqc_ciphertext = base64.b64decode(message["encrypted_hqc_ciphertext"], validate=True)
        nonce1 = base64.b64decode(message["nonce1"], validate=True)
        nonce2 = base64.b64decode(message["nonce2"], validate=True)
        mldsa_signature = base64.b64decode(message["mldsa_signature"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error) as e:
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


def parse_ke_verification(data: bytes, local_verification_key: bytes | None = None) -> dict[str, Any]:
    """Parse a KE_VERIFICATION message (steps 15/16).

    The peer sends HMAC(verification_key, "key-verification-v1"). If local_verification_key is
    provided, compute the expected HMAC locally and compare in constant time; on mismatch return
    an empty bytes value so the caller's bytes_eq check fails. Otherwise return the raw proof.
    """
    try:
        message = json.loads(data)
        if not isinstance(message, dict):
            raise DecodeError("KE_VERIFICATION decode error: not a JSON object")
        peer_proof = base64.b64decode(message["verification_key"], validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error) as e:
        raise DecodeError(f"KE_VERIFICATION decode error: {type(e).__name__}") from e
    
    if local_verification_key is not None:
        h = HMAC(local_verification_key, hashes.SHA3_512())
        h.update(b"key-verification-v1")
        expected_proof = h.finalize()
        # Return the expected proof on match, empty bytes on mismatch — caller uses bytes_eq
        return {"verification_key": expected_proof if bytes_eq(peer_proof, expected_proof) else b""}
    
    return {"verification_key": peer_proof}
