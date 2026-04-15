import base64
import hashlib
import json
import os
from pathlib import Path

from pqcrypto.sign import ml_dsa_87  # type: ignore[import-untyped]

from protocol.constants import MessageType, PROTOCOL_VERSION, SEND_CHUNK_SIZE
from protocol.types import FileMetadata
from protocol.utils import chunk_file, decide_compression


def create_error_message(error_text: str) -> bytes:
    """Create an error message"""
    message = {
        "type":  MessageType.ERROR,
        "error": error_text,
    }
    return json.dumps(message).encode('utf-8')


def create_reset_message() -> bytes:
    """Create a key exchange reset message."""
    message = {
        "type":    MessageType.KEY_EXCHANGE_RESET,
        "message": "Key exchange reset - other client disconnected",
    }
    return json.dumps(message).encode('utf-8')


def create_key_verification_message(verified: bool) -> bytes:
    """Create a key verification status message."""
    message = {
        "type":     MessageType.KEY_VERIFICATION,
        "verified": verified,
    }
    return json.dumps(message).encode('utf-8')


def create_ke_dsa_random(mldsa_public_key: bytes, client_random: bytes) -> bytes:
    """Create KE_DSA_RANDOM message (steps 3 and 6): ML-DSA public key + client random."""
    message = {
        "version":          PROTOCOL_VERSION,
        "type":             MessageType.KE_DSA_RANDOM,
        "mldsa_public_key": base64.b64encode(mldsa_public_key).decode('utf-8'),
        "client_random":    base64.b64encode(client_random).decode('utf-8'),
    }
    return json.dumps(message).encode('utf-8')


def create_ke_mlkem_pubkey(mlkem_public_key: bytes, mldsa_private_key: bytes) -> bytes:
    """Create KE_MLKEM_PUBKEY message (step 8): signed ML-KEM public key."""
    signature = ml_dsa_87.sign(mldsa_private_key, mlkem_public_key)
    message = {
        "type":             MessageType.KE_MLKEM_PUBKEY,
        "mlkem_public_key": base64.b64encode(mlkem_public_key).decode('utf-8'),
        "mldsa_signature":  base64.b64encode(signature).decode('utf-8'),
    }
    return json.dumps(message).encode('utf-8')


def create_ke_mlkem_ct_keys(mlkem_ciphertext: bytes, encrypted_hqc_pubkey: bytes,
                            encrypted_x25519_pubkey: bytes, nonce1: bytes, nonce2: bytes,
                            mldsa_private_key: bytes,
                            ) -> bytes:
    """Create KE_MLKEM_CT_KEYS message (step 10): ML-KEM ciphertext + encrypted HQC/X25519 pubkeys."""
    signed_payload = mlkem_ciphertext + encrypted_hqc_pubkey + encrypted_x25519_pubkey + nonce1 + nonce2
    signature = ml_dsa_87.sign(mldsa_private_key, signed_payload)
    message = {
        "type":                    MessageType.KE_MLKEM_CT_KEYS,
        "mlkem_ciphertext":        base64.b64encode(mlkem_ciphertext).decode('utf-8'),
        "encrypted_hqc_pubkey":    base64.b64encode(encrypted_hqc_pubkey).decode('utf-8'),
        "encrypted_x25519_pubkey": base64.b64encode(encrypted_x25519_pubkey).decode('utf-8'),
        "nonce1":                  base64.b64encode(nonce1).decode('utf-8'),
        "nonce2":                  base64.b64encode(nonce2).decode('utf-8'),
        "mldsa_signature":         base64.b64encode(signature).decode('utf-8'),
    }
    return json.dumps(message).encode('utf-8')


def create_ke_x25519_hqc_ct(encrypted_x25519_pubkey: bytes, encrypted_hqc_ciphertext: bytes,
                            nonce1: bytes, nonce2: bytes,
                            mldsa_private_key: bytes,
                            ) -> bytes:
    """Create KE_X25519_HQC_CT message (step 13): encrypted X25519 pubkey + encrypted HQC ciphertext."""
    signed_payload = encrypted_x25519_pubkey + encrypted_hqc_ciphertext + nonce1 + nonce2
    signature = ml_dsa_87.sign(mldsa_private_key, signed_payload)
    message = {
        "type":                     MessageType.KE_X25519_HQC_CT,
        "encrypted_x25519_pubkey":  base64.b64encode(encrypted_x25519_pubkey).decode('utf-8'),
        "encrypted_hqc_ciphertext": base64.b64encode(encrypted_hqc_ciphertext).decode('utf-8'),
        "nonce1":                   base64.b64encode(nonce1).decode('utf-8'),
        "nonce2":                   base64.b64encode(nonce2).decode('utf-8'),
        "mldsa_signature":          base64.b64encode(signature).decode('utf-8'),
    }
    return json.dumps(message).encode('utf-8')


def create_ke_verification(verification_key: bytes) -> bytes:
    """Create KE_VERIFICATION message (steps 15/16): verification hash in signed plaintext."""
    message = {
        "type":             MessageType.KE_VERIFICATION,
        "verification_key": base64.b64encode(verification_key).decode('utf-8'),
    }
    return json.dumps(message).encode('utf-8')


def create_file_accept_message(transfer_id: str) -> dict:
    """Create a file acceptance message (as a dict, to be encrypted by the caller)."""
    return {
        "type":        MessageType.FILE_ACCEPT,
        "transfer_id": transfer_id,
    }


def create_file_reject_message(transfer_id: str, reason: str = "User declined") -> dict:
    """Create a file rejection message (as a dict, to be encrypted by the caller)."""
    return {
        "type":        MessageType.FILE_REJECT,
        "transfer_id": transfer_id,
        "reason":      reason,
    }


def create_rekey_init_message(mlkem_public_key: bytes, hqc_public_key: bytes,
                              dh_public_key_bytes: bytes,
                              ) -> dict[str, str | int]:
    """Create a REKEY init payload to be sent inside an encrypted message using the old key."""
    return {
        "type":             MessageType.REKEY,
        "action":           "init",
        "mlkem_public_key": base64.b64encode(mlkem_public_key).decode('utf-8'),
        "hqc_public_key":   base64.b64encode(hqc_public_key).decode('utf-8'),
        "dh_public_key":    base64.b64encode(dh_public_key_bytes).decode('utf-8'),
    }


def create_rekey_response_message(mlkem_ciphertext: bytes, hqc_ciphertext: bytes,
                                  dh_public_key_bytes: bytes,
                                  ) -> dict[str, int | str]:
    """Create a REKEY response payload."""
    return {
        "type":             MessageType.REKEY,
        "action":           "response",
        "mlkem_ciphertext": base64.b64encode(mlkem_ciphertext).decode('utf-8'),
        "hqc_ciphertext":   base64.b64encode(hqc_ciphertext).decode('utf-8'),
        "dh_public_key":    base64.b64encode(dh_public_key_bytes).decode('utf-8'),
    }


def create_rekey_commit_message() -> dict:
    """Create a REKEY commit payload."""
    return {
        "type":   MessageType.REKEY,
        "action": "commit",
    }


def create_file_metadata_message(file_path: Path, compress: bool = True) -> FileMetadata:
    """Create a file metadata message for file transfer initiation.
    Automatically disables compression for known incompressible types.
    """
    
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Decide final compression setting based on user preference and file type
    effective_compress = decide_compression(file_path, user_pref=compress)
    
    file_size: int = os.path.getsize(file_path)
    file_name: str = file_path.name
    
    # Calculate file hash for integrity verification (of original uncompressed file)
    file_hash = hashlib.blake2b(digest_size=32)
    with open(file_path, 'rb') as f:
        while chunk := f.read(16384):
            file_hash.update(chunk)
    
    total_chunks: int = 0
    total_processed_size: int = 0
    
    try:
        for chunk in chunk_file(file_path, compress=effective_compress):
            total_chunks += 1
            total_processed_size += len(chunk)
    except (OSError, IOError) as e:
        print(f"Warning: I/O error during pre-chunking, using estimation: {e}")
        total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
        total_processed_size = file_size if not effective_compress else int(file_size * 0.85)
    except ValueError as e:
        print(f"Warning: Value error during pre-chunking, using estimation: {e}")
        total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
        total_processed_size = file_size if not effective_compress else int(file_size * 0.85)
    except Exception as e:
        print(f"Warning: Unexpected error during pre-chunking, using estimation: {e}")
        total_chunks = (file_size + SEND_CHUNK_SIZE - 1) // SEND_CHUNK_SIZE
        total_processed_size = file_size if not effective_compress else int(file_size * 0.85)
    
    # Generate unique transfer ID. It should be unique but does not have to be cryptographically secure.
    # SHA256 just happens to be fast, and its outputs are likely unique enough for this purpose.
    transfer_id: str = hashlib.sha256(f"{file_name}{file_size}{file_hash.hexdigest()}".encode(),
                                      usedforsecurity=False).hexdigest()[:32]
    
    metadata: FileMetadata = {
        "transfer_id":     transfer_id,
        "filename":        file_name,
        "file_size":       file_size,
        "file_hash":       file_hash.hexdigest(),
        "total_chunks":    total_chunks,
        "compressed":      effective_compress,
        "compressed_size": total_processed_size,
    }
    
    return metadata
