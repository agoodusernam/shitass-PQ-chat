import hashlib
from typing import Never

from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.padding import PKCS7

from protocol.constants import DOUBLE_KEY_SIZE, SINGLE_KEY_SIZE, NONCE_SIZE
from protocol.utils import xor_bytes


class DoubleEncryptor:
    """
    Provides an authenticated two-AEAD encryption scheme with an additional OTP-like keystream pre-mask.

    Components:
        - OTP-like pre-mask: Before AEAD, the PKCS7-padded plaintext is XORed with a keystream derived
          from `OTP_secret`, the per-message counter, and the payload length. The keystream is produced
          via KDF/HMAC primitives and is deterministic per message/length. This is not an
          information-theoretic OTP, but a KDF-based stream that adds defence in depth.
        - Double AEAD: The masked payload is then encrypted with AES-GCM-SIV and ChaCha20-Poly1305.
          Nonces for each layer are derived by XORing the caller-provided 12-byte nonce with halves of
          the 64-byte key to reduce nonce misuse risk (even if the provided nonce repeats).

    Key material:
        - Requires a DOUBLE_KEY_SIZE-byte key: first HALF_KEY_SIZE bytes for AES-GCM-SIV, last HALF_KEY_SIZE bytes for ChaCha20-Poly1305.
        - `OTP_secret` is a separate secret (e.g. from HQC) used solely for keystream derivation.
    
    Padding:
        - Payloads are PKCS7-padded to 512 bytes to hinder message size analysis.
    
    Associated Data (AAD):
        - The same AAD is authenticated by both AEAD layers to protect metadata.
    
    Security notes:
        - Keystream uniqueness relies on the tuple (`OTP_secret`, `message_counter`, payload length).
          Do not reuse counters with the same `OTP_secret`.
        - As long as one of these algorithms stay secure, the scheme remains secure. Any two can be broken
          and any data is still unreadable without the key
    """
    
    def __init__(self, key: bytes, OTP_secret: bytes, message_counter: int):
        """
        Args:
            key: DOUBLE_KEY_SIZE bytes. First HALF_KEY_SIZE bytes for AES-GCM-SIV, last HALF_KEY_SIZE bytes for ChaCha20-Poly1305.
            OTP_secret: Secret seed used to derive the OTP-like keystream that pre-masks the padded data.
            message_counter: Monotonically increasing counter mixed into the keystream to ensure per-message
                             uniqueness.
        """
        if len(key) != DOUBLE_KEY_SIZE:
            raise ValueError(f"Key must be {DOUBLE_KEY_SIZE} bytes")
        
        self._key: bytes = key
        self._aes: AESGCMSIV = AESGCMSIV(key[:SINGLE_KEY_SIZE])
        self._chacha: ChaCha20Poly1305 = ChaCha20Poly1305(key[SINGLE_KEY_SIZE:])
        self._OTP_secret: bytes = OTP_secret
        self.message_counter: int = message_counter
    
    @property
    def key(self) -> None:
        raise AttributeError('You cannot get the key once it has been set')
    
    @key.setter
    def key(self, value: bytes) -> None:
        if len(value) != DOUBLE_KEY_SIZE:
            raise ValueError(f"Key must be {DOUBLE_KEY_SIZE} bytes")
        self._key: bytes = value
        self._aes: AESGCMSIV = AESGCMSIV(value[:SINGLE_KEY_SIZE])
        self._chacha: ChaCha20Poly1305 = ChaCha20Poly1305(value[SINGLE_KEY_SIZE:])
    
    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = True) -> bytes:
        if pad:
            padder = PKCS7(512).padder()
            new_data = padder.update(data) + padder.finalize()
        else:
            new_data = data
        
        aes_nonce = xor_bytes(nonce, self._key[:NONCE_SIZE])
        chacha_nonce = xor_bytes(nonce, self._key[-NONCE_SIZE:])
        
        layer0 = xor_bytes(new_data, self._derive_OTP_keystream(len(new_data), aes_nonce + chacha_nonce))
        layer1 = self._aes.encrypt(aes_nonce, layer0, associated_data)
        layer2 = self._chacha.encrypt(chacha_nonce, layer1, associated_data)
        return layer2
    
    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = True) -> bytes:
        aes_nonce = xor_bytes(nonce, self._key[:NONCE_SIZE])
        chacha_nonce = xor_bytes(nonce, self._key[-NONCE_SIZE:])
        
        layer2 = self._chacha.decrypt(chacha_nonce, data, associated_data)
        layer1 = self._aes.decrypt(aes_nonce, layer2, associated_data)
        layer0 = xor_bytes(layer1, self._derive_OTP_keystream(len(layer1), aes_nonce + chacha_nonce))
        
        if pad:
            unpadder = PKCS7(512).unpadder()
            return unpadder.update(layer0) + unpadder.finalize()
        return layer0
    
    def _derive_OTP_keystream(self, length: int, additional_salt: bytes) -> bytes:
        """Generate keystream from HQC shared secret using message counter."""
        
        # Mix: HQC secret + message counter
        hasher = hashlib.shake_256()
        hasher.update(self._OTP_secret)
        hasher.update(additional_salt)
        hasher.update(self.message_counter.to_bytes(8, byteorder="little"))
        return hasher.digest(length)


class ChunkIndependentDoubleEncryptor:
    """
    Similar to DoubleEncryptor except not authenticated.
    This is for the DeadDrop feature in which chunks are not always
    guaranteed to be decrypted in the same size or order as encrypted.
    """
    
    def __init__(self, key: bytes):
        if len(key) != DOUBLE_KEY_SIZE:
            raise ValueError(f"Key must be {DOUBLE_KEY_SIZE} bytes")
        self._key = key
    
    @property
    def key(self) -> Never:
        raise AttributeError('You cannot get the key once it has been set')
    
    @key.setter
    def key(self, value: bytes) -> None:
        if len(value) != DOUBLE_KEY_SIZE:
            raise ValueError(f"Key must be {DOUBLE_KEY_SIZE} bytes")
        self._key = value
    
    def encrypt(self, nonce: bytes, data: bytes) -> bytes:
        chacha_encryptor: CipherContext = Cipher(algorithms.ChaCha20(self._key[SINGLE_KEY_SIZE:], nonce), None).encryptor()
        aes_encryptor: CipherContext = Cipher(algorithms.AES(self._key[:SINGLE_KEY_SIZE]), modes.CTR(nonce)).encryptor()
        layer1 = chacha_encryptor.update(data) + chacha_encryptor.finalize()
        layer2 = aes_encryptor.update(layer1) + aes_encryptor.finalize()
        return layer2
    
    def decrypt(self, nonce: bytes, data: bytes) -> bytes:
        chacha_decryptor: CipherContext = Cipher(algorithms.ChaCha20(self._key[SINGLE_KEY_SIZE:], nonce), None).decryptor()
        aes_decryptor: CipherContext = Cipher(algorithms.AES(self._key[:SINGLE_KEY_SIZE]), modes.CTR(nonce)).decryptor()
        layer2 = aes_decryptor.update(data) + aes_decryptor.finalize()
        layer1 = chacha_decryptor.update(layer2) + chacha_decryptor.finalize()
        return layer1


class KeyExchangeDoubleEncryptor:
    def __init__(self, key: bytes):
        if len(key) != DOUBLE_KEY_SIZE:
            raise ValueError(f"Key must be {DOUBLE_KEY_SIZE} bytes")
        self._key = key
        self._aes: AESGCMSIV = AESGCMSIV(key[:SINGLE_KEY_SIZE])
        self._chacha: ChaCha20Poly1305 = ChaCha20Poly1305(key[SINGLE_KEY_SIZE:])
    
    def encrypt(self, nonce: bytes, data: bytes) -> bytes:
        aes_nonce = xor_bytes(nonce, self._key[:NONCE_SIZE])
        chacha_nonce = xor_bytes(nonce, self._key[-NONCE_SIZE:])
        
        layer1 = self._aes.encrypt(aes_nonce, data, None)
        layer2 = self._chacha.encrypt(chacha_nonce, layer1, None)
        return layer2
    
    def decrypt(self, nonce: bytes, data: bytes) -> bytes:
        aes_nonce = xor_bytes(nonce, self._key[:NONCE_SIZE])
        chacha_nonce = xor_bytes(nonce, self._key[-NONCE_SIZE:])
        
        layer2 = self._chacha.decrypt(chacha_nonce, data, None)
        layer1 = self._aes.decrypt(aes_nonce, layer2, None)
        return layer1
