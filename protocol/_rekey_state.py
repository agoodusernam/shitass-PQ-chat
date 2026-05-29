import base64
import binascii
import os
import secrets
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.hmac import HMAC
from pqcrypto.kem import hqc_256

from protocol.constants import (
    CLIENT_RANDOM_SIZE,
    ML_DSA_CONTEXT,
    MessageType,
    NONCE_SIZE,
)
from protocol.crypto_classes import KeyExchangeDoubleEncryptor, _KeyDerivation
from protocol.errors import (
    ErrorCode,
    KeyExchangeError,
    MessageError,
    RekeyError,
)
from protocol.utils import LRUCache

if TYPE_CHECKING:
    from protocol.shared import SecureChatProtocol


class _RekeyState:
    """
    Owns every attribute and method associated with the rekey exchange.

    Composed into :class:`SecureChatProtocol` as ``self._rekey``. All in-flight rekey
    KE state (``_rke_*``), all pending post-rekey session keys (``_pending_*``), and the
    auto-rekey counters live here. :class:`SecureChatProtocol` proxies reads/writes of
    those names via ``__getattr__`` / ``__setattr__`` so external callers keep working
    with the original attribute access.
    """
    
    def __init__(self, protocol: "SecureChatProtocol") -> None:
        self._protocol: "SecureChatProtocol" = protocol
        
        # In-flight rekey KE state
        self._rke_step: int = 0  # 0=off, 1=I am A (initiator), 2=I am B (responder)
        self._rke_client_random: bytes = b""
        self._rke_peer_client_random: bytes = b""
        self._rke_combined_random: bytes = b""
        self._rke_mldsa_pub: bytes = b""
        self._rke_mldsa_priv: MLDSA87PrivateKey | None = None
        self._rke_peer_mldsa_pub: bytes = b""
        self._rke_mlkem_shared_secret: bytes = b""
        # A-side KE state
        self._rke_mlkem_priv: MLKEM1024PrivateKey | None = None
        self._rke_dh_priv: X25519PrivateKey | None = None
        self._rke_dh_pub_bytes: bytes = b""
        self._rke_peer_hqc_pub: bytes = b""
        # B-side KE state
        self._rke_peer_mlkem_pub: MLKEM1024PublicKey | None = None
        self._rke_hqc_pub: bytes = b""
        self._rke_hqc_priv: bytes = b""
        self._rke_b_dh_priv: X25519PrivateKey | None = None
        self._rke_b_dh_pub_bytes: bytes = b""
        # Shared intermediary state
        self._rke_intermediary_key_1: bytes = b""
        
        # Pending activation state
        self.rekey_in_progress: bool = False
        self._pending_send_chain_key: bytes = b""
        self._pending_receive_chain_key: bytes = b""
        self._pending_otp_material: bytes = b""
        self._pending_verification_key: bytes = b""
        self._pending_key_verification_material: bytes = b""
        self._pending_msg_recv_private: X25519PrivateKey | None = None
        self._pending_msg_peer_base_public: bytes = b""
        self._pending_peer_dh_public_key_bytes: bytes = b""
        self.pending_message_counter: int = 0
        self.pending_peer_counter: int = 0
        
        # Automatic rekey tracking
        self.messages_since_last_rekey: int = 0
        base_interval = protocol.config["rekey_interval"]
        variation = round(base_interval * 0.1)
        self.rekey_interval: int = base_interval + (secrets.randbelow(variation + 1) - variation)
    
    def _server_id(self) -> bytes:
        return self._protocol._server_identifier.encode("utf-8")
    
    def reset_ke_state(self) -> None:
        """Clear all rekey KE protocol state (does not clear pending keys or in-progress flag)."""
        self._rke_step = 0
        self._rke_client_random = b""
        self._rke_peer_client_random = b""
        self._rke_combined_random = b""
        self._rke_mldsa_pub = b""
        self._rke_mldsa_priv = None
        self._rke_peer_mldsa_pub = b""
        self._rke_mlkem_shared_secret = b""
        self._rke_mlkem_priv = None
        self._rke_dh_priv = None
        self._rke_dh_pub_bytes = b""
        self._rke_peer_hqc_pub = b""
        self._rke_peer_mlkem_pub = None
        self._rke_hqc_pub = b""
        self._rke_hqc_priv = b""
        self._rke_b_dh_priv = None
        self._rke_b_dh_pub_bytes = b""
        self._rke_intermediary_key_1 = b""
    
    def abort(self, error_msg: str = "") -> None:
        """Abort an in-progress rekey and clear all associated state."""
        self.reset_ke_state()
        self._pending_send_chain_key = b""
        self._pending_receive_chain_key = b""
        self._pending_otp_material = b""
        self._pending_verification_key = b""
        self._pending_key_verification_material = b""
        self._pending_msg_recv_private = None
        self._pending_msg_peer_base_public = b""
        self._pending_peer_dh_public_key_bytes = b""
        self.rekey_in_progress = False
        if error_msg:
            self._protocol._forward_exc(RekeyError(code=ErrorCode.REKEY_ABORTED, context={"reason": error_msg}))
    
    def activate(self) -> None:
        """Atomically switch active session to the pending keys (if available)."""
        if not self._pending_send_chain_key:
            return
        p = self._protocol
        p.shared_key = True
        p._verification_key = self._pending_verification_key
        p._key_verification_material = self._pending_key_verification_material
        p._send_chain_key = self._pending_send_chain_key
        p._receive_chain_key = self._pending_receive_chain_key
        p._otp_material = self._pending_otp_material
        p.message_counter = 0
        p.peer_counter = 0
        self.messages_since_last_rekey = 0
        p._msg_recv_private = self._pending_msg_recv_private
        p.msg_peer_base_public = self._pending_msg_peer_base_public
        p.peer_dh_public_key_bytes = self._pending_peer_dh_public_key_bytes
        p.skipped_counters = LRUCache(1000)
        self._pending_send_chain_key = b""
        self._pending_receive_chain_key = b""
        self._pending_otp_material = b""
        self._pending_verification_key = b""
        self._pending_key_verification_material = b""
        self._pending_msg_recv_private = None
        self._pending_msg_peer_base_public = b""
        self._pending_peer_dh_public_key_bytes = b""
        self.pending_message_counter = 0
        self.pending_peer_counter = 0
        self.reset_ke_state()
        self.rekey_in_progress = False
    
    def pending_exists(self) -> bool:
        return bool(self._pending_send_chain_key)
    
    def should_auto_rekey(self) -> bool:
        return (self.messages_since_last_rekey >= self.rekey_interval
                and not self.rekey_in_progress
                and self._protocol.encryption_ready)
    
    def reset_auto_counter(self) -> None:
        self.messages_since_last_rekey = 1
    
    # derivations
    
    def _derive_combined_random(self) -> bytes:
        return _KeyDerivation.derive_combined_random(
                self._rke_client_random,
                self._rke_peer_client_random,
                self._server_id(),
                rekey=True,
        )
    
    def _derive_intermediary_key_1(self, mlkem_shared_secret: bytes) -> bytes:
        return _KeyDerivation.derive_intermediary_key_1(
                mlkem_shared_secret,
                self._rke_combined_random,
                self._server_id(),
                rekey=True,
        )
    
    def _derive_intermediary_key_2(
            self, int_key_1: bytes, dh_shared_secret: bytes,
    ) -> bytes:
        return _KeyDerivation.derive_intermediary_key_2(
                int_key_1,
                dh_shared_secret,
                self._server_id(),
                rekey=True,
        )
    
    def _finalize(
            self,
            dh_shared_secret: bytes,
            hqc_secret: bytes,
            mlkem_shared_secret: bytes,
            own_dh_priv: X25519PrivateKey,
            peer_dh_pub_bytes: bytes,
    ) -> None:
        """
        Derive and store pending session keys.
        """
        server_id = self._server_id()
        
        pending_otp = _KeyDerivation.derive_otp_material(
                hqc_secret,
                self._rke_combined_random,
                server_id,
                rekey=True,
        )
        own_chain_key = _KeyDerivation.derive_chain_key_root(
                mlkem_shared_secret,
                dh_shared_secret,
                self._rke_client_random,
                server_id,
                rekey=True,
        )
        peer_chain_key = _KeyDerivation.derive_chain_key_root(
                mlkem_shared_secret,
                dh_shared_secret,
                self._rke_peer_client_random,
                server_id,
                rekey=True,
        )
        verification_hash, key_verification_material = (
            _KeyDerivation.compute_verification_pair(
                    pending_otp,
                    own_chain_key,
                    peer_chain_key,
                    self._rke_combined_random,
            )
        )
        
        self._pending_otp_material = pending_otp
        self._pending_send_chain_key = own_chain_key
        self._pending_receive_chain_key = peer_chain_key
        self._pending_verification_key = verification_hash
        self._pending_key_verification_material = key_verification_material
        self._pending_msg_recv_private = own_dh_priv
        self._pending_msg_peer_base_public = peer_dh_pub_bytes
        self._pending_peer_dh_public_key_bytes = peer_dh_pub_bytes
    
    # protocol messages
    
    def _generate_mldsa_keypair(self) -> None:
        priv = MLDSA87PrivateKey.generate()
        self._rke_mldsa_priv = priv
        self._rke_mldsa_pub = priv.public_key().public_bytes_raw()
    
    def create_dsa_random(self, is_initiator: bool) -> dict:
        """Start a rekey: generate ephemeral ML-DSA keys + client random; return dsa_random payload."""
        self._generate_mldsa_keypair()
        self._rke_client_random = os.urandom(CLIENT_RANDOM_SIZE)
        self._rke_step = 1 if is_initiator else 2
        self.rekey_in_progress = True
        return {
            "type":             MessageType.REKEY,
            "action":           "dsa_random",
            "is_response":      False,
            "mldsa_public_key": base64.b64encode(self._rke_mldsa_pub).decode("utf-8"),
            "client_random":    base64.b64encode(self._rke_client_random).decode("utf-8"),
        }
    
    def _make_dsa_random_response(self) -> dict:
        return {
            "type":             MessageType.REKEY,
            "action":           "dsa_random",
            "is_response":      True,
            "mldsa_public_key": base64.b64encode(self._rke_mldsa_pub).decode("utf-8"),
            "client_random":    base64.b64encode(self._rke_client_random).decode("utf-8"),
        }
    
    def process_dsa_random(self, inner: dict) -> dict | None:
        """Process peer's dsa_random. Returns next outbound rekey message dict or None."""
        try:
            peer_mldsa_pub = base64.b64decode(inner["mldsa_public_key"], validate=True)
            peer_random = base64.b64decode(inner["client_random"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise MessageError(code=ErrorCode.MESSAGE_DECODE, context={"phase": "rekey", "step": "dsa_random"}, cause=e)
        
        peer_is_initiating = not inner.get("is_response", False)
        
        if self._rke_step == 0:
            self._generate_mldsa_keypair()
            self._rke_client_random = os.urandom(CLIENT_RANDOM_SIZE)
            self._rke_step = 2
            self.rekey_in_progress = True
        
        if self._rke_step == 1:
            if peer_is_initiating and peer_random > self._rke_client_random:
                self._rke_step = 2
            else:
                if self._rke_combined_random:
                    return None
                self._rke_peer_mldsa_pub = peer_mldsa_pub
                self._rke_peer_client_random = peer_random
                self._rke_combined_random = self._derive_combined_random()
                return self._create_mlkem_pubkey()
        
        if self._rke_combined_random:
            return None
        self._rke_peer_mldsa_pub = peer_mldsa_pub
        self._rke_peer_client_random = peer_random
        self._rke_combined_random = self._derive_combined_random()
        return self._make_dsa_random_response()
    
    def _create_mlkem_pubkey(self) -> dict:
        """(A) Generate ML-KEM-1024 and X25519 keypairs; return signed mlkem_pubkey payload."""
        if self._rke_mldsa_priv is None:
            raise KeyExchangeError(code=ErrorCode.KE_MISSING_PRIVATE_KEY, context={"algo": "ML-DSA", "phase": "rekey"})
        mlkem_priv = MLKEM1024PrivateKey.generate()
        mlkem_pub = mlkem_priv.public_key().public_bytes_raw()
        self._rke_mlkem_priv = mlkem_priv
        dh_priv = X25519PrivateKey.generate()
        self._rke_dh_priv = dh_priv
        self._rke_dh_pub_bytes = dh_priv.public_key().public_bytes_raw()
        signature = self._rke_mldsa_priv.sign(mlkem_pub, context=ML_DSA_CONTEXT)
        return {
            "type":             MessageType.REKEY,
            "action":           "mlkem_pubkey",
            "mlkem_public_key": base64.b64encode(mlkem_pub).decode("utf-8"),
            "mldsa_signature":  base64.b64encode(signature).decode("utf-8"),
        }
    
    def process_mlkem_pubkey(self, inner: dict) -> dict:
        """(B) Process A's mlkem_pubkey; generate B's keys, encapsulate, return mlkem_ct_keys payload."""
        if self._rke_mldsa_priv is None:
            raise KeyExchangeError(code=ErrorCode.KE_MISSING_PRIVATE_KEY, context={"algo": "ML-DSA", "phase": "rekey"})
        try:
            mlkem_pub = base64.b64decode(inner["mlkem_public_key"], validate=True)
            mldsa_sig = base64.b64decode(inner["mldsa_signature"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise MessageError(code=ErrorCode.MESSAGE_DECODE, context={"phase": "rekey", "step": "mlkem_pubkey"}, cause=e)
        
        try:
            MLDSA87PublicKey.from_public_bytes(self._rke_peer_mldsa_pub).verify(
                    mldsa_sig, mlkem_pub, context=ML_DSA_CONTEXT,
            )
        except InvalidSignature as exc:
            raise KeyExchangeError(code=ErrorCode.KE_MLKEM_SIG, context={"phase": "rekey"}, cause=exc)
        
        self._rke_peer_mlkem_pub = MLKEM1024PublicKey.from_public_bytes(mlkem_pub)
        
        hqc_pub, hqc_priv = hqc_256.generate_keypair()
        self._rke_hqc_pub = hqc_pub
        self._rke_hqc_priv = hqc_priv
        dh_priv = X25519PrivateKey.generate()
        self._rke_b_dh_priv = dh_priv
        self._rke_b_dh_pub_bytes = dh_priv.public_key().public_bytes_raw()
        
        mlkem_shared_secret, mlkem_ciphertext = self._rke_peer_mlkem_pub.encapsulate()
        self._rke_mlkem_shared_secret = mlkem_shared_secret
        
        int_key_1 = self._derive_intermediary_key_1(mlkem_shared_secret)
        self._rke_intermediary_key_1 = int_key_1
        
        encryptor = KeyExchangeDoubleEncryptor(int_key_1)
        nonce1 = os.urandom(NONCE_SIZE)
        nonce2 = os.urandom(NONCE_SIZE)
        encrypted_hqc_pubkey = encryptor.encrypt(nonce1, hqc_pub)
        encrypted_x25519_pubkey = encryptor.encrypt(nonce2, self._rke_b_dh_pub_bytes)
        
        signed_payload = mlkem_ciphertext + encrypted_hqc_pubkey + encrypted_x25519_pubkey + nonce1 + nonce2
        signature = self._rke_mldsa_priv.sign(signed_payload, context=ML_DSA_CONTEXT)
        
        return {
            "type":                    MessageType.REKEY,
            "action":                  "mlkem_ct_keys",
            "mlkem_ciphertext":        base64.b64encode(mlkem_ciphertext).decode("utf-8"),
            "encrypted_hqc_pubkey":    base64.b64encode(encrypted_hqc_pubkey).decode("utf-8"),
            "encrypted_x25519_pubkey": base64.b64encode(encrypted_x25519_pubkey).decode("utf-8"),
            "nonce1":                  base64.b64encode(nonce1).decode("utf-8"),
            "nonce2":                  base64.b64encode(nonce2).decode("utf-8"),
            "mldsa_signature":         base64.b64encode(signature).decode("utf-8"),
        }
    
    def process_mlkem_ct_keys(self, inner: dict) -> dict:
        """(A) Process B's mlkem_ct_keys; decapsulate, decrypt, finalize pending keys; return x25519_hqc_ct."""
        if self._rke_dh_priv is None:
            raise KeyExchangeError(code=ErrorCode.KE_MISSING_PRIVATE_KEY, context={"algo": "X25519", "phase": "rekey"})
        if self._rke_mldsa_priv is None:
            raise KeyExchangeError(code=ErrorCode.KE_MISSING_PRIVATE_KEY, context={"algo": "ML-DSA", "phase": "rekey"})
        try:
            mlkem_ct = base64.b64decode(inner["mlkem_ciphertext"], validate=True)
            enc_hqc_pub = base64.b64decode(inner["encrypted_hqc_pubkey"], validate=True)
            enc_x25519_pub = base64.b64decode(inner["encrypted_x25519_pubkey"], validate=True)
            nonce1 = base64.b64decode(inner["nonce1"], validate=True)
            nonce2 = base64.b64decode(inner["nonce2"], validate=True)
            mldsa_sig = base64.b64decode(inner["mldsa_signature"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise MessageError(code=ErrorCode.MESSAGE_DECODE, context={"phase": "rekey", "step": "mlkem_ct_keys"}, cause=e)
        
        signed_payload = mlkem_ct + enc_hqc_pub + enc_x25519_pub + nonce1 + nonce2
        try:
            MLDSA87PublicKey.from_public_bytes(self._rke_peer_mldsa_pub).verify(
                    mldsa_sig,
                    signed_payload,
                    context=ML_DSA_CONTEXT,
            )
        except InvalidSignature as exc:
            raise KeyExchangeError(code=ErrorCode.KE_MLKEM_CT_SIG, context={"phase": "rekey"}, cause=exc)
        
        if self._rke_mlkem_priv is None:
            raise KeyExchangeError(code=ErrorCode.KE_MISSING_PRIVATE_KEY, context={"algo": "ML-KEM", "phase": "rekey"})
        
        mlkem_shared_secret = self._rke_mlkem_priv.decapsulate(mlkem_ct)
        
        int_key_1 = self._derive_intermediary_key_1(mlkem_shared_secret)
        self._rke_intermediary_key_1 = int_key_1
        
        decryptor = KeyExchangeDoubleEncryptor(int_key_1)
        peer_hqc_pub = decryptor.decrypt(nonce1, enc_hqc_pub)
        peer_x25519_pub_bytes = decryptor.decrypt(nonce2, enc_x25519_pub)
        self._rke_peer_hqc_pub = peer_hqc_pub
        
        dh_shared_secret = self._rke_dh_priv.exchange(
                X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes))
        
        hqc_ciphertext, hqc_secret = hqc_256.encrypt(peer_hqc_pub)
        
        int_key_2 = self._derive_intermediary_key_2(int_key_1, dh_shared_secret)
        
        enc1 = KeyExchangeDoubleEncryptor(int_key_1)
        enc2 = KeyExchangeDoubleEncryptor(int_key_2)
        out_nonce1 = os.urandom(NONCE_SIZE)
        out_nonce2 = os.urandom(NONCE_SIZE)
        encrypted_x25519_pubkey = enc1.encrypt(out_nonce1, self._rke_dh_pub_bytes)
        encrypted_hqc_ciphertext = enc2.encrypt(out_nonce2, hqc_ciphertext)
        
        out_signed_payload = encrypted_x25519_pubkey + encrypted_hqc_ciphertext + out_nonce1 + out_nonce2
        signature = self._rke_mldsa_priv.sign(out_signed_payload, context=ML_DSA_CONTEXT)
        
        self._finalize(
                dh_shared_secret,
                hqc_secret,
                mlkem_shared_secret,
                self._rke_dh_priv,
                peer_x25519_pub_bytes,
        )
        
        return {
            "type":                     MessageType.REKEY,
            "action":                   "x25519_hqc_ct",
            "encrypted_x25519_pubkey":  base64.b64encode(encrypted_x25519_pubkey).decode("utf-8"),
            "encrypted_hqc_ciphertext": base64.b64encode(encrypted_hqc_ciphertext).decode("utf-8"),
            "nonce1":                   base64.b64encode(out_nonce1).decode("utf-8"),
            "nonce2":                   base64.b64encode(out_nonce2).decode("utf-8"),
            "mldsa_signature":          base64.b64encode(signature).decode("utf-8"),
        }
    
    def process_x25519_hqc_ct(self, inner: dict) -> None:
        """(B) Process A's x25519_hqc_ct; derive and store pending session keys."""
        if self._rke_b_dh_priv is None:
            raise KeyExchangeError(code=ErrorCode.KE_MISSING_PRIVATE_KEY, context={"algo": "X25519", "phase": "rekey"})
        try:
            enc_x25519_pub = base64.b64decode(inner["encrypted_x25519_pubkey"], validate=True)
            enc_hqc_ct = base64.b64decode(inner["encrypted_hqc_ciphertext"], validate=True)
            nonce1 = base64.b64decode(inner["nonce1"], validate=True)
            nonce2 = base64.b64decode(inner["nonce2"], validate=True)
            mldsa_sig = base64.b64decode(inner["mldsa_signature"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise MessageError(code=ErrorCode.MESSAGE_DECODE, context={"phase": "rekey", "step": "x25519_hqc_ct"}, cause=e)
        
        signed_payload = enc_x25519_pub + enc_hqc_ct + nonce1 + nonce2
        try:
            MLDSA87PublicKey.from_public_bytes(self._rke_peer_mldsa_pub).verify(
                    mldsa_sig,
                    signed_payload,
                    context=ML_DSA_CONTEXT,
            )
        except InvalidSignature as exc:
            raise KeyExchangeError(code=ErrorCode.KE_X25519_HQC_SIG, context={"phase": "rekey"}, cause=exc)
        
        dec1 = KeyExchangeDoubleEncryptor(self._rke_intermediary_key_1)
        peer_x25519_pub_bytes = dec1.decrypt(nonce1, enc_x25519_pub)
        
        dh_shared_secret = self._rke_b_dh_priv.exchange(
                X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes))
        
        int_key_2 = self._derive_intermediary_key_2(self._rke_intermediary_key_1, dh_shared_secret)
        
        dec2 = KeyExchangeDoubleEncryptor(int_key_2)
        hqc_ciphertext = dec2.decrypt(nonce2, enc_hqc_ct)
        hqc_secret = hqc_256.decrypt(self._rke_hqc_priv, hqc_ciphertext)
        
        self._finalize(
                dh_shared_secret,
                hqc_secret,
                self._rke_mlkem_shared_secret,
                self._rke_b_dh_priv,
                peer_x25519_pub_bytes,
        )
    
    def create_verification(self) -> dict:
        h = HMAC(self._pending_key_verification_material, hashes.SHA3_512())
        h.update(b"key-verification-v1")
        proof = h.finalize()
        return {
            "type":             MessageType.REKEY,
            "action":           "verification",
            "verification_key": base64.b64encode(proof).decode("utf-8"),
        }
    
    def process_verification(self, inner: dict) -> bool:
        try:
            peer_proof = base64.b64decode(inner["verification_key"], validate=True)
        except (KeyError, binascii.Error) as e:
            raise MessageError(code=ErrorCode.MESSAGE_DECODE, context={"phase": "rekey", "step": "verification"}, cause=e)
        
        key_material = self._pending_key_verification_material or self._protocol._key_verification_material
        if not key_material:
            raise KeyExchangeError(code=ErrorCode.KE_STATE, context={"phase": "rekey", "reason": "no_verification_material"})
        
        h = HMAC(key_material, hashes.SHA3_512())
        h.update(b"key-verification-v1")
        expected = h.finalize()
        return bytes_eq(peer_proof, expected)
