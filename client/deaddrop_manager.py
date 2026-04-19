"""Dead drop session manager.

Owns the anonymous dead drop flow: the ML-KEM handshake with the server,
PBKDF2/Argon2 key derivation, chunked upload/download, and streaming
decryption of incoming binary chunks. The rest of the client is
unaware of dead drop wire details.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from socket import socket
from typing import TYPE_CHECKING, Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pqcrypto.kem import ml_kem_1024  # type: ignore

from SecureChatABCs.ui_base import UIBase
from config import ClientConfigHandler
from protocol import constants, utils
from protocol.constants import (
    CTR_NONCE_SIZE,
    DEADDROP_CIPHERTEXT_OFFSET,
    DEADDROP_FILE_EXT_HEADER_SIZE,
    DEADDROP_HKDF_SALT_SIZE,
    DEADDROP_KDF_KEY_LENGTH,
    DEADDROP_LENGTH_PREFIX_SIZE,
    DEADDROP_NONCE_OFFSET,
    DEADDROP_PBKDF2_ITERATIONS,
    DOUBLE_KEY_SIZE,
    MessageType,
    NONCE_SIZE,
)
from protocol.crypto_classes import ChunkIndependentDoubleEncryptor
from utils.network_utils import encode_send_message, send_message

if TYPE_CHECKING:
    from new_client import SecureChatClient

config = ClientConfigHandler()


class DeaddropManager:
    """Manages a single client's dead drop session with the server."""

    def __init__(self, client: "SecureChatClient") -> None:
        self._client = client

        # Session / handshake
        self.supported: bool = False
        self.shared_secret: bytes | None = None
        self._in_progress: bool = False
        self._started: bool = False
        self._handshake_event: threading.Event = threading.Event()

        # Upload state
        self._chunks: dict[int, bytes] = {}
        self._file_size: int = 0
        self._name: str = ""
        self._password_hash: str = ""
        self._upload_accept_event: threading.Event = threading.Event()
        self._upload_accepted: bool = False

        # Download state
        self.download_in_progress: bool = False
        self._download_name: str = ""
        self._download_expected_hash: str | None = None
        self._download_chunks: dict[int, bytes] = {}
        self._download_max_index: int = -1
        self._download_key: bytes | None = None

        # Streaming download state
        self._dl_encryptor: ChunkIndependentDoubleEncryptor | None = None
        self._dl_password: str = ""
        self._dl_next_nonce: bytes | None = None
        self._dl_expected_index: int = 0
        self._dl_part_path: str | None = None
        self._dl_file: BinaryIO | None = None
        self._dl_bytes_downloaded: int = 0

    # internal accessors

    @property
    def _ui(self) -> UIBase:
        return self._client.ui

    @property
    def _socket(self) -> socket:
        return self._client._socket

    @property
    def _server_identifier(self) -> str:
        return self._client.server_identifier

    # public API

    @property
    def session_active(self) -> bool:
        return self.shared_secret is not None

    def reset(self) -> None:
        """Clear every piece of dead drop session state. Called on disconnect."""
        self.shared_secret = None
        self.supported = False
        self._in_progress = False
        self._chunks = {}
        self._file_size = 0
        self._name = ""
        self._password_hash = ""
        self.download_in_progress = False
        self._download_name = ""
        self._download_expected_hash = None
        self._download_chunks = {}
        self._download_max_index = -1
        self._download_key = None
        self._dl_encryptor = None
        self._dl_password = ""
        self._dl_next_nonce = None
        self._dl_expected_index = 0
        self._dl_part_path = None
        self._dl_file = None
        self._dl_bytes_downloaded = 0
        self._handshake_event.set()
        self._started = False
        self._upload_accept_event.set()
        self._upload_accepted = False

    def start_handshake(self) -> None:
        """Send a DEADDROP_START frame to the server to begin the key-exchange handshake."""
        if not self._client.connected:
            self._ui.display_error_message("Cannot start deaddrop - not connected")
            return
        if self._in_progress:
            self._ui.display_error_message("Deaddrop already in progress")
            return

        self.shared_secret = None
        self.supported = False
        self._handshake_event.clear()
        self._started = True

        self._ui.display_system_message("Starting deaddrop handshake")
        encode_send_message(self._socket, {"type": MessageType.DEADDROP_START})

    def wait_for_handshake(self, timeout: float = 3.0) -> bool:
        """Block until the handshake completes or *timeout* seconds elapse."""
        if not self._client.connected:
            self._ui.display_error_message("Cannot wait for deaddrop handshake - not connected")
            return False
        if not self._started:
            self._ui.display_error_message("Deaddrop handshake has not been started")
            return False
        if not self._handshake_event.wait(timeout):
            self._ui.display_error_message("Deaddrop handshake timed out")
            return False
        return bool(self.shared_secret)

    def upload(self, name: str, password: str, file_path: Path) -> None:
        """Encrypt and upload a file to the server's deaddrop store."""
        if not self.shared_secret:
            self._ui.display_error_message("Deaddrop not initialised - handshake required")
            return

        if not file_path.is_file():
            self._ui.display_error_message(f"File not found: {file_path}")
            return

        file_size = file_path.resolve().stat().st_size

        hkdf_salt = os.urandom(DEADDROP_HKDF_SALT_SIZE)
        key = self._derive_file_key(password, hkdf_salt)
        h = HMAC(key, hashes.SHA3_512())
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        file_hash = base64.b64encode(h.finalize()).decode("utf-8")

        password_hash = self._hash_password(password)
        self._file_size = file_size
        self._name = name
        self._password_hash = password_hash

        inner_meta = {
            "type":               MessageType.DEADDROP_UPLOAD,
            "name":               name,
            "file_size":          file_size,
            "file_hash":          file_hash,
            "file_password_hash": password_hash,
            "file_key_salt":      base64.b64encode(hkdf_salt).decode("utf-8"),
        }
        self._upload_accepted = False
        self._upload_accept_event.clear()
        outer_meta = self._encrypt_inner(json.dumps(inner_meta).encode("utf-8"))
        encode_send_message(self._socket, outer_meta)

        if not self._upload_accept_event.wait(timeout=10.0):
            self._ui.display_error_message("Deaddrop upload timed out waiting for server acceptance")
            return
        if not self._upload_accepted:
            return

        encryptor = ChunkIndependentDoubleEncryptor(key)
        self._chunks.clear()

        chunk_index = 0
        file_ext = os.path.splitext(file_path)[1][:DEADDROP_FILE_EXT_HEADER_SIZE]
        header = file_ext.encode("utf-8").ljust(DEADDROP_FILE_EXT_HEADER_SIZE, b"\x00")
        with open(file_path, "rb") as f:
            first = True
            while True:
                if first:
                    chunk_data = f.read(config["send_chunk_size"] - DEADDROP_FILE_EXT_HEADER_SIZE)
                    plaintext_chunk = header + chunk_data
                    first = False
                else:
                    chunk_data = f.read(config["send_chunk_size"])
                    plaintext_chunk = chunk_data
                nonce = hashlib.sha3_256(key + chunk_index.to_bytes(4, byteorder='little')).digest()[:CTR_NONCE_SIZE]
                if not chunk_data:
                    break

                ct = encryptor.encrypt(nonce, plaintext_chunk)
                payload = chunk_index.to_bytes(4, byteorder='little') + ct
                outer_nonce = os.urandom(NONCE_SIZE)
                frame = self._encrypt_chunk(payload, outer_nonce)

                result = send_message(self._socket, frame)
                if result is not None:
                    self._ui.display_error_message(f"Failed to send chunk: {result}")
                    chunk_index += 1
                    continue

                chunk_index += 1
                if chunk_index % 50 == 0:
                    self._ui.display_system_message(
                            f"{utils.bytes_to_human_readable(chunk_index * 1024 * 1024)}/"
                            f"{utils.bytes_to_human_readable(file_size)} sent",
                    )

        complete_outer = self._encrypt_inner(json.dumps({"type": MessageType.DEADDROP_COMPLETE}).encode("utf-8"))
        encode_send_message(self._socket, complete_outer)
        self._ui.display_system_message("Deaddrop upload complete")

    def check(self, name: str) -> None:
        """Ask the server whether a deaddrop entry with the given *name* exists."""
        if not self.shared_secret:
            self._ui.display_error_message("Deaddrop not initialised - handshake required")
            return
        self._name = name
        outer = self._encrypt_inner(json.dumps({
            "type": MessageType.DEADDROP_CHECK,
            "name": name,
        }).encode("utf-8"))
        encode_send_message(self._socket, outer)

    def download(self, name: str, password: str) -> None:
        """Request a deaddrop file download from the server."""
        if not self.shared_secret:
            self._ui.display_error_message("Deaddrop not initialised - handshake required")
            return

        self._name = name
        self._password_hash = self._hash_password(password)
        self._dl_password = password
        self.download_in_progress = True
        self._download_chunks.clear()
        self._download_max_index = -1
        self._download_expected_hash = None
        self._download_key = self._derive_file_key(password)
        self._dl_encryptor = None
        self._dl_next_nonce = None
        self._dl_expected_index = 0
        self._dl_part_path = None
        if self._dl_file:
            try:
                self._dl_file.close()
            except Exception:
                pass
            self._dl_file = None

        outer_dl = self._encrypt_inner(json.dumps({
            "type": MessageType.DEADDROP_DOWNLOAD,
            "name": name,
        }).encode("utf-8"))
        encode_send_message(self._socket, outer_dl)

    # server-message handlers

    def handle_start_response(self, message: dict[str, Any]) -> None:
        """Process the server's DEADDROP_START response, derive the shared secret, and reply."""
        supported = bool(message.get("supported", False))
        if not supported:
            reason = message.get("reason", "Server does not support deaddrop")
            self._ui.display_error_message(reason)
            self.shared_secret = None
            self.supported = False
            self._in_progress = False
            self._handshake_event.set()
            self._started = False
            return

        try:
            mlkem_public_b64 = str(message["mlkem_public"])
            mlkem_public = base64.b64decode(mlkem_public_b64, validate=True)
        except KeyError:
            self._ui.display_error_message("Invalid deaddrop start response: missing mlkem_public")
            self._handshake_event.set()
            self._started = False
            return
        except binascii.Error:
            self._ui.display_error_message("Invalid deaddrop start response: bad mlkem_public encoding")
            self._handshake_event.set()
            self._started = False
            return

        mlkem_ciphertext, kem_shared_secret = ml_kem_1024.encrypt(mlkem_public)

        self.shared_secret = ConcatKDFHash(
                algorithm=hashes.SHA3_512(),
                length=DEADDROP_KDF_KEY_LENGTH,
                otherinfo=b"deaddrop_key_exchange" + self._server_identifier.encode("utf-8"),
        ).derive(kem_shared_secret)

        self.supported = True

        encode_send_message(self._socket, {
            "type":     MessageType.DEADDROP_KE_RESPONSE,
            "mlkem_ct": base64.b64encode(mlkem_ciphertext).decode("utf-8"),
        })
        self._ui.display_system_message("Deaddrop handshake complete")
        self._handshake_event.set()
        self._started = False

    def handle_encrypted_message(self, outer: dict[str, Any]) -> None:
        """Decrypt and dispatch an incoming DEADDROP_MESSAGE frame from the server."""
        if not self.shared_secret:
            self._ui.display_error_message("Received deaddrop message before handshake was complete")
            return

        try:
            nonce_b64 = str(outer["nonce"])
            ct_b64 = str(outer["ciphertext"])
            nonce = base64.b64decode(nonce_b64, validate=True)
            ciphertext = base64.b64decode(ct_b64, validate=True)
        except KeyError:
            self._ui.display_error_message("Malformed deaddrop message from server")
            return
        except binascii.Error:
            self._ui.display_error_message("Invalid base64 in deaddrop message from server")
            return

        aad_raw = json.dumps({
            "type":  MessageType.DEADDROP_MESSAGE,
            "nonce": nonce_b64,
        }).encode("utf-8")

        try:
            aead = ChaCha20Poly1305(self.shared_secret)
            inner_bytes = aead.decrypt(nonce, ciphertext, aad_raw)
            inner = json.loads(inner_bytes.decode("utf-8"))
        except Exception:
            self._ui.display_error_message("Failed to decrypt deaddrop message from server")
            return

        inner_type = MessageType(int(inner.get("type", MessageType.NONE)))
        match inner_type:
            case MessageType.DEADDROP_CHECK_RESPONSE:
                self._on_check_response(inner)
            case MessageType.DEADDROP_ACCEPT:
                self._on_accept(inner)
            case MessageType.DEADDROP_DENY:
                reason = inner.get("reason", "Deaddrop request denied")
                self._ui.display_error_message(reason)
                self._in_progress = False
                self.download_in_progress = False
                self._upload_accepted = False
                self._upload_accept_event.set()
            case MessageType.DEADDROP_REDOWNLOAD:
                pass
            case MessageType.DEADDROP_PROVE:
                self._on_prove(inner)
            case MessageType.DEADDROP_DATA:
                self._on_data(inner)
            case MessageType.DEADDROP_COMPLETE:
                if self.download_in_progress:
                    self._finalise_download()
                else:
                    self._ui.display_system_message("Deaddrop upload completed successfully")
                self._in_progress = False
                self.download_in_progress = False

    def handle_binary_chunk(self, message_data: bytes) -> None:
        """Decrypt a raw binary deaddrop chunk frame and forward it to the streaming processor.

        Raises ``ValueError`` on decryption failure so the caller can mark the frame
        as unrecognised and log it.
        """
        if not self.download_in_progress or self.shared_secret is None:
            return
        aead = ChaCha20Poly1305(self.shared_secret)
        nonce = message_data[DEADDROP_NONCE_OFFSET:DEADDROP_CIPHERTEXT_OFFSET]
        ct = message_data[DEADDROP_CIPHERTEXT_OFFSET:]
        try:
            decrypted = aead.decrypt(nonce, ct, nonce)
        except InvalidTag as exc:
            raise ValueError("Deaddrop chunk decryption failed") from exc
        self._process_data_streaming(
                int.from_bytes(decrypted[:DEADDROP_LENGTH_PREFIX_SIZE], "big"),
                decrypted[DEADDROP_LENGTH_PREFIX_SIZE:],
        )

    # inner-type handlers

    def _on_check_response(self, inner: dict[str, Any]) -> None:
        exists = bool(inner.get("exists", False))
        name = self._name or inner.get("name", "")
        self._ui.on_deaddrop_check_result(name, exists)
        if exists:
            self._ui.display_system_message(f"Deaddrop '{name}' exists on server.")
        else:
            self._ui.display_error_message(f"Deaddrop '{name}' does not exist on server.")

    def _on_accept(self, inner: dict[str, Any]) -> None:
        self._in_progress = True
        if self.download_in_progress:
            self._download_expected_hash = str(inner.get("file_hash", ""))
            file_key_salt_b64 = inner.get("file_key_salt")
            if isinstance(file_key_salt_b64, str):
                try:
                    hkdf_salt = base64.b64decode(file_key_salt_b64, validate=True)
                except binascii.Error:
                    hkdf_salt = None
            else:
                hkdf_salt = None
            if hkdf_salt and self._download_key is not None:
                self._download_key = self._derive_file_key(self._dl_password, hkdf_salt)
            self._ui.display_system_message("Deaddrop download accepted by server; confirming and waiting for data...")
            confirm_outer = self._encrypt_inner(json.dumps({"type": MessageType.DEADDROP_ACCEPT}).encode("utf-8"))
            encode_send_message(self._socket, confirm_outer)
        else:
            self._upload_accepted = True
            self._upload_accept_event.set()
            self._ui.display_system_message("Deaddrop upload accepted by server")

    def _on_prove(self, inner: dict[str, Any]) -> None:
        salt_b64 = inner.get("salt")
        if not isinstance(salt_b64, str):
            self._ui.display_error_message("Invalid deaddrop prove message from server")
            return
        try:
            download_salt = base64.b64decode(salt_b64, validate=True)
        except binascii.Error:
            self._ui.display_error_message("Invalid base64 salt in deaddrop prove message")
            return

        if not self._password_hash:
            self._ui.display_error_message("No stored deaddrop password hash for download")
            return

        pbk = PBKDF2HMAC(
                algorithm=hashes.SHA3_512(),
                length=DEADDROP_KDF_KEY_LENGTH,
                salt=download_salt,
                iterations=DEADDROP_PBKDF2_ITERATIONS,
        )
        client_hash = pbk.derive(self._password_hash.encode("utf-8"))
        outer_msg = self._encrypt_inner(json.dumps({
            "type": MessageType.DEADDROP_PROVE,
            "hash": base64.b64encode(client_hash).decode("utf-8"),
        }).encode("utf-8"))
        encode_send_message(self._socket, outer_msg)

    def _on_data(self, inner: dict[str, Any]) -> None:
        if not self.download_in_progress:
            return
        try:
            chunk_index = int(inner["chunk_index"])
            ct_b64_data = str(inner["ct"])
            chunk_data = base64.b64decode(ct_b64_data, validate=True)
        except (KeyError, ValueError, TypeError, binascii.Error):
            self._ui.display_error_message("Malformed deaddrop data from server")
            return
        self._process_data_streaming(chunk_index, chunk_data)

    # key derivation

    def _derive_file_key(self, password: str, hkdf_salt: bytes | None = None) -> bytes:
        salt = hashlib.sha3_512(
                b"deaddrop-file-key-v1:" + self._server_identifier.encode("utf-8"),
        ).digest()

        argon = Argon2id(
                salt=salt,
                memory_cost=1024 * 1024 * 4,
                iterations=4,
                lanes=4,
                length=DOUBLE_KEY_SIZE,
        )
        stretched = argon.derive(password.encode("utf-8"))

        hkdf = HKDF(
                algorithm=hashes.SHA3_512(),
                length=DOUBLE_KEY_SIZE,
                salt=hkdf_salt,
                info=b"deaddrop-file-encryption-key-v1",
        )
        return hkdf.derive(stretched)

    def _hash_password(self, password: str) -> str:
        """Derive a slow Argon2id hash of the deaddrop password for server-side authentication."""
        self._ui.display_system_message("Hashing deaddrop password, program may be unresponsive.")
        salt = self._server_identifier.encode("utf-8") if self._server_identifier else b"deaddrop_pass_default_salt_v1"
        hasher = Argon2id(
                salt=salt,
                memory_cost=1024 * 1024 * 2,
                iterations=6,
                lanes=4,
                length=DOUBLE_KEY_SIZE,
        )
        return base64.b64encode(hasher.derive(password.encode("utf-8"))).decode("utf-8")

    # frame-level crypto helpers

    def _encrypt_inner(self, inner: bytes) -> dict[str, Any]:
        """Encrypt *inner* with ChaCha20-Poly1305 using the deaddrop shared secret."""
        if not self.shared_secret:
            raise ValueError("Deaddrop shared secret not established")
        nonce = os.urandom(NONCE_SIZE)
        aad_raw = json.dumps({
            "type":  MessageType.DEADDROP_MESSAGE,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
        }).encode("utf-8")
        aead = ChaCha20Poly1305(self.shared_secret)
        ciphertext = aead.encrypt(nonce, inner, aad_raw)
        return {
            "type":       MessageType.DEADDROP_MESSAGE,
            "nonce":      base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    def _encrypt_chunk(self, chunk: bytes, nonce: bytes) -> bytes:
        """Encrypt a raw binary deaddrop chunk and prepend the magic number and nonce for framing."""
        if not self.shared_secret:
            raise ValueError("Deaddrop shared secret not established")
        aead = ChaCha20Poly1305(self.shared_secret)
        ciphertext = aead.encrypt(nonce, chunk, nonce)
        return constants.MAGIC_NUMBER_DEADDROPS + nonce + ciphertext

    # streaming download

    def _rename_invalid(self, path: str | Path) -> None:
        """Rename a download whose HMAC failed (or was missing) with a ``.corrupt`` suffix."""
        path = Path(path)
        new_path = Path(str(path) + '.corrupt')
        if not new_path.exists():
            try:
                os.replace(path, new_path)
            except OSError:
                self._ui.display_error_message(f"Failed to rename corrupt file: {path}")
            return

        if new_path.is_dir():
            new_path = new_path / (path.stem + str(int(time.time())) + "".join(path.suffixes) + ".corrupt")
            try:
                os.replace(path, new_path)
            except OSError:
                self._ui.display_error_message(f"Failed to rename corrupt file: {path}")
            return

        if new_path.is_file():
            corrupt_folder_path: Path = Path('currupt_deaddrop_files').resolve()
            corrupt_folder_path.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(new_path, corrupt_folder_path / new_path.name)
            except OSError:
                self._ui.display_error_message(f"Failed to rename corrupt file: {path}")
                return
            new_path = new_path.with_name(path.stem + str(int(time.time())) + "".join(path.suffixes) + ".corrupt")
            try:
                os.replace(path, new_path)
            except OSError:
                self._ui.display_error_message(f"Failed to rename corrupt file: {path}")

    def _finalise_download(self) -> None:
        """Close the partial download file, rename it to its final name, and verify its HMAC."""
        self._dl_expected_index = 0
        self._dl_encryptor = None
        self._dl_next_nonce = None
        if self._dl_file:
            try:
                self._dl_file.close()
            except Exception:
                pass
            finally:
                self._dl_file = None

        if not self._dl_part_path:
            self._ui.display_error_message("No deaddrop partial file to finalise")
            return

        part_path = self._dl_part_path
        final_path = part_path[:-5] if part_path.lower().endswith(".part") else part_path
        try:
            os.replace(part_path, final_path)
        except Exception as exc:
            self._ui.display_error_message(f"Failed to finalise deaddrop file: {exc}")
            return

        expected_b64 = self._download_expected_hash or ""
        key = self._download_key
        if not expected_b64:
            self._ui.display_system_message("Deaddrop: no expected HMAC provided by server; skipped verification.")
            self._rename_invalid(final_path)
            self._dl_part_path = None
            return
        if key is None:
            self._ui.display_error_message("Deaddrop: missing key for HMAC verification; file kept as-is.")
            self._rename_invalid(final_path)
            self._dl_part_path = None
            return

        if isinstance(expected_b64, str) and expected_b64.startswith("b'") and expected_b64.endswith("'"):
            expected_b64 = expected_b64[2:-1]
        try:
            expected_hmac = base64.b64decode(expected_b64, validate=True)
        except binascii.Error:
            self._ui.display_error_message("Deaddrop: invalid base64 expected HMAC provided by server.")
            self._rename_invalid(final_path)
            self._dl_part_path = None
            return

        h = HMAC(key, hashes.SHA3_512())
        with open(final_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        computed_hmac = h.finalize()

        if bytes_eq(computed_hmac, expected_hmac):
            self._ui.display_system_message("Deaddrop file integrity verified (HMAC OK).")
        else:
            self._ui.display_error_message(
                    "Deaddrop file HMAC verification failed, file will be kept as-is."
                    f"Computed HMAC: {base64.b64encode(computed_hmac).decode('utf-8')},"
                    f"Expected HMAC: {base64.b64encode(expected_hmac).decode('utf-8')}",
            )
            self._rename_invalid(final_path)
            self._dl_part_path = None
            return

        self._ui.on_deaddrop_download_complete(self._name, final_path)
        self._ui.display_system_message(f"Deaddrop download complete, saved to: {final_path}")
        self._dl_part_path = None

    def _process_data_streaming(self, chunk_index: int, chunk_data: bytes) -> None:
        """Decrypt and stream-write a single deaddrop download chunk to the partial output file."""
        if chunk_index != self._dl_expected_index:
            self._ui.display_error_message(
                    f"Unexpected deaddrop chunk index {chunk_index}, expected {self._dl_expected_index}",
            )
            return

        if (chunk_index + 1) % 100 == 0:
            size_so_far = utils.bytes_to_human_readable(self._dl_bytes_downloaded)
            self._ui.display_system_message(f"Received {size_so_far} so far")

        if self._download_key is None:
            self._ui.display_error_message("Deaddrop key not initialised")
            return

        if self._dl_encryptor is None:
            self._dl_encryptor = ChunkIndependentDoubleEncryptor(self._download_key)

        try:
            nonce = hashlib.sha3_256(
                    self._download_key + chunk_index.to_bytes(4, byteorder='little'),
            ).digest()[:CTR_NONCE_SIZE]
            if chunk_index == 0:
                pt = self._dl_encryptor.decrypt(nonce, chunk_data)
                if len(pt) < DEADDROP_FILE_EXT_HEADER_SIZE:
                    self._ui.display_error_message("First deaddrop chunk too small to contain header")
                    return
                ext_header = pt[:DEADDROP_FILE_EXT_HEADER_SIZE]
                body = pt[DEADDROP_FILE_EXT_HEADER_SIZE:]
                self._dl_bytes_downloaded += len(body)

                file_ext = ext_header.rstrip(b"\x00").decode("utf-8", errors="ignore")
                file_ext = "".join(c for c in file_ext if c.isalnum() or c in ".-_") or ".bin"
                safe_name = "".join(c for c in self._name if c.isalnum() or c in ("-", "_")) or "deaddrop"
                if file_ext:
                    final_name = safe_name + (file_ext if file_ext.startswith(".") else ("." + file_ext))
                else:
                    final_name = safe_name
                part_path = final_name + ".part"

                try:
                    f = open(part_path, "wb")
                except Exception as exc:
                    self._ui.display_error_message(f"Failed to open deaddrop output file: {exc}")
                    return
                self._dl_file = f
                self._dl_part_path = part_path

                if body:
                    try:
                        f.write(body)
                    except Exception as exc:
                        self._ui.display_error_message(f"Failed to write to deaddrop file: {exc}")
                        try:
                            f.close()
                        except Exception:
                            pass
                        self._dl_file = None
                        try:
                            os.remove(part_path)
                        except Exception:
                            pass
                        return
            else:
                if not self._dl_file:
                    self._ui.display_error_message("Deaddrop output file not open")
                    return
                pt = self._dl_encryptor.decrypt(nonce, chunk_data)
                self._dl_bytes_downloaded += len(pt)
                try:
                    self._dl_file.write(pt)
                except Exception as exc:
                    self._ui.display_error_message(f"Failed to write to deaddrop file: {exc}")
                    return
        except Exception as exc:
            self._ui.display_error_message(f"Failed to process deaddrop chunk: {exc}")
            return
        finally:
            if chunk_index == self._dl_expected_index:
                self._dl_expected_index += 1
