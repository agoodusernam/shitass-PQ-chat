# Implementation Notes

This document is a companion to `docs/SPEC.md`. It describes how the Python reference implementation realises the protocol — where things live, how they connect, and where the implementation diverges from or falls short of the spec. It is not normative; the spec takes precedence.

---

## Module Map

| Concern | File(s) |
|---|---|
| Protocol state machine & crypto | `protocol/shared.py` (`SecureChatProtocol`, plus helpers `_KeyDerivation` static HKDF namespace + `_RekeyState` rekey-state container) |
| Double-AEAD + OTP encryption | `protocol/crypto_classes.py` |
| Message framing constants | `protocol/constants.py` |
| Message serialisation | `protocol/create_messages.py` |
| Message deserialisation | `protocol/parse_messages.py` |
| File transfer I/O | `protocol/file_handler.py` |
| Misc utilities (LRUCache, XOR, fingerprint) | `protocol/utils.py` |
| Transport (length-prefixed TCP) | `utils/network_utils.py` |
| Field validation allowlists | `utils/checks.py` |
| Client facade (public API, state flags, delegates to managers) | `new_client.py` (`SecureChatClient`) |
| Socket I/O, receive loop, dispatch, rate limit, keepalive | `clients/connection_manager.py` (`ConnectionManager`) |
| 16-step hybrid KE, verification, rekey, KE reset | `clients/key_exchange_manager.py` (`KeyExchangeManager`) |
| File transfer metadata, chunking, progress, send thread | `clients/file_transfer_manager.py` (`FileTransferManager`) |
| Dead drop PBKDF2 + ML-KEM handshake + chunked upload/download | `clients/deaddrop_manager.py` (`DeaddropManager`) |
| Voice call signaling + audio frames | `clients/voice_call_manager.py` (`VoiceCallManager`) |
| Server (relay + dead drop) | `server.py` (`SecureChatRequestHandler`, `DeadDropManager`) |
| UI abstraction + capability flags | `SecureChatABCs/ui_base.py` |
| UI implementations | `UIs/GUI.py`, `UIs/TUI.py`, `UIs/debug_GUI.py` |
| Configuration | `config.py` (`ClientConfigHandler`, `ServerConfigHandler`) |
| Abstract base classes | `SecureChatABCs/client_base.py`, `protocol_base.py` |

---

## Dependencies

- **`cryptography~=46.0.7`** (PyCA): X25519, AES-256-GCM-SIV, ChaCha20-Poly1305, HKDF, HMAC, PBKDF2, constant-time comparison.
- **`pqcrypto~=0.4.0`**: ML-KEM-1024, HQC-256, ML-DSA-87. The library's own documentation notes it is not production-ready; chosen as the best available Python binding. See Known Shortcomings.
- **`numpy~=2.4.4`**: Used only in `xor_bytes()` (`protocol/utils.py:137`) for payloads ≥ 768 bytes. Below that threshold, pure-Python integer arithmetic is faster.
- **`os.urandom()`**: System CSPRNG for all nonce and random generation.

---

## Transport (section 4.3)

`utils/network_utils.py` — `send_message()` / `receive_message()` implement 4-byte big-endian length-prefix framing. `MAX_MESSAGE_SIZE = 64 MiB` is enforced on receive.

---

## Key Exchange (section 7)

Implemented in `SecureChatProtocol` (`protocol/shared.py`), split into paired `create_*` / `process_*` methods:

```
create_ke_dsa_random / process_ke_dsa_random       → steps 3–7
create_ke_mlkem_pubkey / process_ke_mlkem_pubkey   → steps 8–9
create_ke_mlkem_ct_keys / process_ke_mlkem_ct_keys → steps 10–11
create_ke_x25519_hqc_ct / process_ke_x25519_hqc_ct → steps 12–14
create_ke_verification / process_ke_verification  → steps 15–16
```

**KE state machine**: `ke_step: int` attribute (initialised to `0` at `shared.py:210`). `new_client.py` dispatches to the appropriate method based on its value.

**ML-DSA key lifecycle**: generated in `_generate_dsa_keys()`, discarded in `_discard_mldsa_keys()` (`shared.py:735`) immediately after `_finalize_key_exchange()` completes. Both own and peer DSA keys are set to `b""`.

**KE encryption** (intermediary keys): uses `KeyExchangeDoubleEncryptor` (`protocol/crypto_classes.py`) — same AES-256-GCM-SIV + ChaCha20-Poly1305 double-AEAD with nonce mixing, but without the OTP layer or PKCS7 padding.

**`_finalize_key_exchange()`** (`shared.py:679`): derives OTP material, own chain key root, peer chain key root, verification key, and `_key_verification_material` (32 bytes, used for fingerprint and rekey verification). Also initialises the message-phase DH state: `_msg_recv_private` is set to the session DH private key; `msg_peer_base_public` is set to the peer's session DH public key.

---

## Message Encryption / DoubleEncryptor (section 8)

`DoubleEncryptor` (`protocol/crypto_classes.py:12`):

```
Encrypt: ISO/IEC 7816-4 pad → OTP XOR → AES-256-GCM-SIV → ChaCha20-Poly1305
Decrypt: ChaCha20-Poly1305 → AES-256-GCM-SIV → OTP XOR → ISO/IEC 7816-4 unpad
```

**Nonce hiding** (`crypto_classes.py:78`):
```python
aes_nonce    = public_nonce XOR key[0:12]    # first 12 bytes of 64-byte key
chacha_nonce = public_nonce XOR key[-12:]    # last 12 bytes of 64-byte key
```

**OTP keystream** (`_derive_OTP_keystream`): `SHAKE-256(otp_material || aes_nonce + chacha_nonce || counter_le_8)`. The nonces fed to SHAKE are the *derived* (secret) nonces, not the public wire nonce. This matches SPEC section 8.1.

**Padding**: ISO/IEC 7816-4 (bit-padding) to 512-byte multiples. Implemented manually in `crypto_classes.py` as `_iso7816_pad` / `_iso7816_unpad`: append `0x80` then `0x00` fill until length is a multiple of `PAD_SIZE = 512` bytes. The `cryptography` library's `PKCS7` cannot represent 512-byte blocks (PKCS7 pad byte = count, max 255; library also caps `block_size` at 2040 bits). The scheme still pads to 512-byte multiples so the intent of SPEC section 8.1 (size-class hiding) is preserved. If SPEC 8.1 still names the scheme "PKCS7", update SPEC to match.

**Per-message HMAC** (`encrypt_message`, `shared.py:913`): HMAC-SHA512 keyed by `_verification_key` over `{counter, nonce, dh_public_key}`. Checked *before* decryption to cheaply reject forged high-counter messages (DoS guard).

**64-byte keys**: HKDF produces 64-byte keys (`HKDF_KEY_LENGTH = 64`). The first 32 bytes are used for AES-256-GCM-SIV and the last 32 for ChaCha20-Poly1305.

---

## Double Ratchet (section 8.2–8.4)

Implemented in `encrypt_message()` / `decrypt_message()` in `shared.py`.

**Send path** (per message):
1. Generate fresh ephemeral X25519 keypair.
2. DH with peer's current DH public key.
3. `_mix_dh_with_chain(send_chain_key, dh_shared, counter)` → HKDF-SHA512 with chain key as salt.
4. `_derive_message_key(mixed_chain, counter)` → HKDF-SHA512.
5. Ratchet: `send_chain_key = _ratchet_chain_key(send_chain_key, counter)` → HKDF-SHA3-512.

**Receive path**: receiver DH uses `_msg_recv_private` (own session DH private key) against the sender's per-message ephemeral public key. On successful decryption, `msg_peer_base_public` is updated to the sender's latest ephemeral key. `_msg_recv_private` is not rotated — the sender's new ephemeral key provides the asymmetric forward secrecy.

**Out-of-order delivery**: intermediate chain states are saved into `skipped_counters: LRUCache(1000)` (`shared.py:233`). Capacity is capped to prevent memory exhaustion. File chunks do **not** use this buffer — they require strictly monotone counters.

---

## Threading Model

- **Main thread**: UI event loop.
- **Sender thread**: `_sender_loop()` in `SecureChatProtocol` (`shared.py:420`) — 250 ms tick, dequeues one item, encrypts, sends; sends dummy packets when idle and enabled.
- **Receiver thread**: `ConnectionManager.receive_loop()` (`clients/connection_manager.py`) — spawned by `SecureChatClient.connect()` — reads TCP socket, dispatches through facade methods to protocol handlers and manager handlers.
- **Keepalive timer thread**: sends `KEEP_ALIVE_RESPONSE`; tracks missed keepalives.
- **Auto-rekey timer thread**: time-based trigger; message-count trigger checked inline after each message.

**Queue semantics**: `_message_queue` is a `deque` (`shared.py:183`) protected by `_sender_lock`. Three item kinds:
- `ENCRYPT_TEXT` — text message
- `ENCRYPT_JSON` — JSON inner frame
- `ENCRYPT_JSON_THEN_SWITCH` — send JSON, then immediately call `activate_pending_keys()` after the send completes (used for rekey completion on side A)

---

## Rekeying (section 13)

Rekey state owned by `_RekeyState` (composed on `SecureChatProtocol._rekey`, same file `protocol/shared.py`). All `_rke_*` in-flight KE attributes, `_pending_*` activation attributes, and auto-rekey counters (`messages_since_last_rekey`, `rekey_interval`, `_rekey_in_progress`) live on the `_RekeyState` instance. The class owns every `create_rekey_*` / `process_rekey_*` / `activate_pending_keys` / `reset_rekey` method; `SecureChatProtocol` exposes each as a thin delegate for external callers.

`_KeyDerivation` (also in `protocol/shared.py`) is a stateless namespace class (`@staticmethod` only) covering every HKDF derivation. A single `rekey: bool` kwarg selects the domain-separated `info` string, so initial-KE and rekey-KE paths share one implementation.

**Domain separation from initial KE**: rekey HKDF `info` strings carry a `"rekey_"` prefix:
- `rekey_comb_rand`, `rekey_int_key_1`, `rekey_int_key_2`
- `rekey_otp_material`, `rekey_chain_key_root`

Implemented via `_KeyDerivation.derive_combined_random(..., rekey=True)` etc. — the `rekey=True` branch prepends `b"rekey_"` to the `info` tag.

**Key activation** (`_RekeyState.activate`, invoked via `SecureChatProtocol.activate_pending_keys`): atomically copies `_pending_*` into the protocol's active session state, resets send and receive counters to 0, and resets `skipped_counters` to a fresh `LRUCache(1000)`.

**Side A activation**: uses `ENCRYPT_JSON_THEN_SWITCH` — sends verification under old keys, then calls `activate_pending_keys()` immediately after the send returns.

**Side B activation**: activates when it receives A's verification proof after its own has been sent.

---

## File Transfer (section 9)

`protocol/file_handler.py` manages transfer state on receive. Encryption is in `encrypt_file_chunk` / `decrypt_file_chunk` in `shared.py`.

File chunks share the same ratchet counter space as text messages — a single `message_counter` — ensuring ratchet continuity across message types.

**Binary frame** (`encrypt_file_chunk`, `shared.py:1034`):
```
[0x89 magic (1 B)][counter (4 B)][nonce (12 B)][eph_pub (32 B)][ciphertext]
```
Frame offsets are constants in `protocol/constants.py`. The `0x89` magic byte (`MAGIC_NUMBER_FILE_TRANSFER`) distinguishes file frames from dead drop frames (`0x45`) before decryption.

**Compression**: streaming gzip via `StreamingGzipCompressor` (`protocol/utils.py:60`). Skipped for extensions listed in `INCOMPRESSIBLE_EXTENSIONS` (`protocol/constants.py`).

**File hash**: BLAKE2b-256 of the *original* (uncompressed) file, computed by the sender and verified by the receiver after reassembly and decompression.

**Transfer ID**: validated as alphanumeric, max 64 characters (`file_handler.py:75`).

---

## Dead Drops (section 15)

`DeadDropManager` (`server.py:56`): stores encrypted binary blobs in `deaddrop_files/` (configurable). Each dead drop is a single `.bin` file.

**Dead drop KE**: single-round ML-KEM-1024 exchange directly with the server, independent of the peer session.

**Encryption**: `ChunkIndependentDoubleEncryptor` (`crypto_classes.py:110`) — AES-CTR + ChaCha20 (unauthenticated stream ciphers, not AEAD). This is intentional: order-independent chunk decryption is incompatible with chained authentication.

**Password verification**: PBKDF2-HMAC-SHA256, 800,000 iterations, 32-byte salt (`DEADDROP_PBKDF2_ITERATIONS = 800_000`).

---

## Field Validation (section 11.2)

`utils/checks.py`:
- `allowed_outer_fields(msg_type)` — per-type allowlist for plaintext frames.
- `allowed_unverified_inner_fields()` — superset allowlist for decrypted inner JSON before session verification completes.

Both return `set[str]`. Unknown fields cause the message to be dropped silently.

---

## Traffic Shaping (section 12)

Dummy messages are enabled via `config["send_dummy_packets"]`. Size is up to `config["max_dummy_packet_size"]` (default 512 bytes) of `os.urandom()` data. Automatically disabled during file transfers and rekey (see `send_dummy_messages` property in `shared.py`).

---

## Server (section 6)

`server.py` uses `socketserver.ThreadingTCPServer` — one thread per client connection. Supports one session (max two clients). `SERVER_VERSION = 9` is an internal tracking integer, separate from `PROTOCOL_VERSION`.

Keepalive: server sends probes every ~60 s; three missed responses → `SERVER_DISCONNECT`.

---

## Session Fingerprint (section 7.5)

`_key_verification_material` = `SHA3-512(concat(sorted([otp_material, own_chain_root, peer_chain_root])) + combined_random)[:32]`

Sorting is lexicographic on raw bytes, ensuring both peers derive identical material regardless of role (`shared.py:714`).

Fingerprint display: `generate_key_fingerprint()` (`protocol/utils.py:182`) — SHA3-512 of `_key_verification_material`, first 32 bytes, converted to 8 words via `hash_to_words()` using a configurable wordlist.

---

## Known Shortcomings

### No secure memory zeroisation

Python's `bytes` are immutable; setting a variable to `b""` drops the reference but does not zero the underlying buffer. CPython's allocator provides no timing guarantees for memory reclamation. Key material — including ML-DSA keys, intermediary keys, and chain keys — may persist in RAM after the reference is dropped. `_discard_mldsa_keys()` and `_RekeyState.reset_ke_state()` make a best-effort attempt, but this cannot be fully fixed in pure Python without `ctypes`/`mmap` and manual zeroing.

### Not constant-time

Python offers no constant-time execution guarantees. Conditional branches on secret data can leak timing. The implementation uses `cryptography.hazmat.primitives.constant_time.bytes_eq` for MAC comparisons, but key derivation, padding, and JSON parsing are not constant-time.

### `pqcrypto` library not production-ready

The `pqcrypto~=0.4.0` Python bindings for ML-KEM-1024, HQC-256, and ML-DSA-87 have not been independently audited for correct implementation or side-channel resistance. The library's own documentation acknowledges this. It is used here as the best available Python binding.

### No file transfer resume

Interrupted transfers must restart from the beginning. Partial chunk tracking is not implemented.

### No out-of-order file chunk delivery

`decrypt_file_chunk()` rejects any chunk with `counter <= peer_counter` immediately. Unlike text messages, no saved-state buffer exists for file chunks.

### numpy in the encryption pipeline

`xor_bytes()` switches to `numpy.bitwise_xor` for payloads ≥ 768 bytes. This introduces a C extension into the encryption hot path, adding a dependency on numpy's memory handling behaviour.

### Server is single-session

The reference server accepts at most two simultaneous clients (one session). The spec (section 4.1) allows multi-session servers; this implementation does not support that.

### No transport anonymity

The server observes client IP addresses and connection timing. No onion routing or anonymisation layer is provided.