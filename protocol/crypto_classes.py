import hashlib
from typing import Never

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from protocol.constants import DOUBLE_KEY_SIZE, HKDF_KEY_LENGTH, PAD_SIZE, SINGLE_KEY_SIZE, NONCE_SIZE
from protocol.utils import xor_bytes


def _iso7816_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def _iso7816_unpad(data: bytes) -> bytes:
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO/IEC 7816-4 padding")
    return data[:i]

def _derive_nonces(nonce: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Derive AES nonce, and ChaCha nonce from the caller-provided 12-byte nonce and the 64-byte key.
    """
    return xor_bytes(nonce, key[:NONCE_SIZE]), xor_bytes(nonce, key[-NONCE_SIZE:])


class DoubleEncryptor:
    """
    Provides an authenticated two-AEAD encryption scheme with an additional OTP-like keystream pre-mask.

    Components:
        - OTP-like pre-mask: Before AEAD, the padded plaintext is XORed with a keystream derived
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
        - Payloads are ISO/IEC 7816-4 padded to a 512-byte multiple to hinder message size analysis.
    
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
    def key(self) -> Never:
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
            new_data = _iso7816_pad(data, PAD_SIZE)
        else:
            new_data = data
        
        aes_nonce, chacha_nonce = _derive_nonces(nonce, self._key)
        
        layer0 = xor_bytes(new_data, self._derive_OTP_keystream(len(new_data), aes_nonce + chacha_nonce))
        layer1 = self._aes.encrypt(aes_nonce, layer0, associated_data)
        layer2 = self._chacha.encrypt(chacha_nonce, layer1, associated_data)
        return layer2
    
    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None, pad: bool = True) -> bytes:
        aes_nonce, chacha_nonce = _derive_nonces(nonce, self._key)
        
        layer2 = self._chacha.decrypt(chacha_nonce, data, associated_data)
        layer1 = self._aes.decrypt(aes_nonce, layer2, associated_data)
        layer0 = xor_bytes(layer1, self._derive_OTP_keystream(len(layer1), aes_nonce + chacha_nonce))
        
        if pad:
            return _iso7816_unpad(layer0)
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
        # Technically, ChaCha20 requires 12 bytes of nonce + 4 bytes of counter.
        # However, we provide a complete 16 byte nonce every time which includes that 'counter' value
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
        aes_nonce, chacha_nonce = _derive_nonces(nonce, self._key)
        
        layer1 = self._aes.encrypt(aes_nonce, data, None)
        layer2 = self._chacha.encrypt(chacha_nonce, layer1, None)
        return layer2
    
    def decrypt(self, nonce: bytes, data: bytes) -> bytes:
        aes_nonce, chacha_nonce = _derive_nonces(nonce, self._key)
        
        layer2 = self._chacha.decrypt(chacha_nonce, data, None)
        layer1 = self._aes.decrypt(aes_nonce, layer2, None)
        return layer1


class _KeyDerivation:
    """
    Stateless namespace of HKDF / hash-based key-derivation helpers.
    
    Every method is a pure function of its arguments: no instance state, no class
    attributes, no hidden globals. Used by :class:`SecureChatProtocol` for both the
    initial hybrid key exchange and the rekey exchange. The ``rekey`` keyword flag on
    the session-level helpers selects the domain-separated ``info`` string so the same
    code path serves both flows.
    """
    
    @staticmethod
    def _info(tag: bytes, server_id: bytes, rekey: bool) -> bytes:
        return server_id + (b"rekey_" + tag if rekey else tag)
    
    @staticmethod
    def derive_combined_random(own_random: bytes, peer_random: bytes, server_id: bytes,
                               *, rekey: bool = False,
                               ) -> bytes:
        """HKDF-SHA-512 over the larger random, salted with the smaller, yielding the
        session-scoped combined random used in subsequent derivations."""
        smaller, larger = sorted([own_random, peer_random])
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=smaller,
                info=_KeyDerivation._info(b"comb_rand", server_id, rekey),
        )
        return hkdf.derive(larger)
    
    @staticmethod
    def derive_intermediary_key_1(mlkem_secret: bytes, combined_random: bytes,
                                  server_id: bytes, *, rekey: bool = False,
                                  ) -> bytes:
        """HKDF-SHA3-512(ML-KEM secret, salt=combined_random)."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=combined_random,
                info=_KeyDerivation._info(b"int_key_1", server_id, rekey),
        )
        return hkdf.derive(mlkem_secret)
    
    @staticmethod
    def derive_intermediary_key_2(int_key_1: bytes, dh_secret: bytes, server_id: bytes,
                                  *, rekey: bool = False,
                                  ) -> bytes:
        """HKDF-SHA3-512(int_key_1, salt=X25519_secret)."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=dh_secret,
                info=_KeyDerivation._info(b"int_key_2", server_id, rekey),
        )
        return hkdf.derive(int_key_1)
    
    @staticmethod
    def derive_otp_material(hqc_secret: bytes, combined_random: bytes, server_id: bytes,
                            *, rekey: bool = False,
                            ) -> bytes:
        """HKDF-SHA3-512(HQC secret, salt=combined_random) → OTP keystream seed."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=combined_random,
                info=_KeyDerivation._info(b"otp_material", server_id, rekey),
        )
        return hkdf.derive(hqc_secret)
    
    @staticmethod
    def derive_chain_key_root(mlkem_secret: bytes, dh_secret: bytes,
                              client_random: bytes, server_id: bytes,
                              *, rekey: bool = False,
                              ) -> bytes:
        """HKDF-SHA3-512(ML-KEM||X25519, salt=client_random) → chain key root."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=client_random,
                info=_KeyDerivation._info(b"chain_key_root", server_id, rekey),
        )
        return hkdf.derive(mlkem_secret + dh_secret)
    
    @staticmethod
    def compute_verification_pair(otp: bytes, own_chain_root: bytes, peer_chain_root: bytes,
                                  combined_random: bytes,
                                  ) -> tuple[bytes, bytes]:
        """Derive `(verification_key, key_verification_material)` from the three session
        roots, order-independent via sorting. Matches the logic shared by the initial
        KE finalizer and the rekey finalizer."""
        sorted_materials = sorted([otp, own_chain_root, peer_chain_root])
        joined = b"".join(sorted_materials)
        verification_key = hashlib.sha3_512(joined).digest()
        key_verification_material = hashlib.sha3_512(joined + combined_random).digest()[:32]
        return verification_key, key_verification_material
    
    @staticmethod
    def derive_message_key(chain_key: bytes, counter: int) -> bytes:
        """Per-message key from the current chain key and counter."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"message_key_{counter}".encode(),
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def ratchet_chain_key(chain_key: bytes, counter: int) -> bytes:
        """Advance the symmetric chain key one step."""
        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=HKDF_KEY_LENGTH,
                salt=counter.to_bytes(8, byteorder="little"),
                info=f"chain_key_{counter}".encode("utf-8"),
        )
        return hkdf.derive(chain_key)
    
    @staticmethod
    def mix_dh_with_chain(chain_key: bytes, dh_shared: bytes, counter: int) -> bytes:
        """Mix per-message DH shared secret into the chain key (Double Ratchet step)."""
        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=HKDF_KEY_LENGTH,
                salt=chain_key,
                info=b"dr_mix_" + str(counter).encode("utf-8"),
        )
        return hkdf.derive(dh_shared)
