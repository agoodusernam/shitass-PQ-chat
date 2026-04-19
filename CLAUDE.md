# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Server
python server.py

# Client (prompts UI selection: GUI, TUI, debug_GUI)
python run_client.py
./new_gui_client.sh          # activates .venv and runs run_client.py

# Debug client (CLI, no UI)
python debug_client.py

# Tests
pytest tests/
pytest tests/test_protocol_shared.py::TestClass::test_name  # single test

# Install deps
pip install -r requirements.txt         # client (includes UI libs)
pip install -r requirements_server.txt  # server-only (crypto only)

# Lint
pylint <module>              # config at .pylintrc
```

No build step. No pre-commit hooks configured.

## Architecture

Post-quantum E2E encrypted chat. Server is a dumb relay — it routes ciphertext and manages dead drops but has zero key material knowledge.

```
UIs/ (GUI.py, TUI.py, debug_GUI.py)
  └─ SecureChatABCs/ui_base.py  (UIBase ABC)
       └─ SecureChatClient  (new_client.py, ~580 lines — facade)
            ├─ ConnectionManager   (client/connection_manager.py)    — socket I/O, receive loop, dispatch, rate limit, keepalive, server frames
            ├─ KeyExchangeManager  (client/key_exchange_manager.py)  — 16-step hybrid KE, verification, rekey, reset
            ├─ FileTransferManager (client/file_transfer_manager.py) — metadata, chunking, progress, send thread
            ├─ DeaddropManager     (client/deaddrop_manager.py)      — PBKDF2-protected async file sharing via server
            ├─ VoiceCallManager    (client/voice_call_manager.py)    — voice call signaling + audio frames
            ├─ SecureChatProtocol  (protocol/shared.py, ~2500 lines)
            │    ├─ crypto_classes.py    — DoubleEncryptor, ChunkIndependentDoubleEncryptor
            │    ├─ constants.py         — message types, frame offsets, crypto constants
            │    ├─ create_messages.py   — serialize protocol frames
            │    └─ parse_messages.py    — deserialize protocol frames
            └─ ProtocolFileHandler  (protocol/file_handler.py)

SecureChatABCs/
  ├─ client_base.py   — SecureChatClient ABC
  ├─ protocol_base.py — SecureChatProtocol ABC
  └─ ui_base.py       — UIBase ABC with capability flags

utils/
  ├─ checks.py        — field validation allowlists (outer + inner JSON)
  ├─ file_utils.py    — file helpers
  ├─ network_utils.py — length-prefixed TCP send/receive
  └─ vc_utils.py      — voice call audio helpers
```

`SecureChatClient` (new_client.py) is a thin facade: owns `SecureChatProtocol` + socket, composes the five managers above, exposes the public API consumed by UIs and tests. State probed by tests (`_protocol`, `_socket`, `_key_exchange_complete`, etc.) lives on the facade; managers access it via the facade reference.

### Manager dispatch rules

- Managers MUST call their sibling managers directly (`self._client._key_exchange.handle_reset(...)`), never bounce through facade proxies (`self._client.handle_key_exchange_reset(...)`). Facade proxies are for external callers (UIs, tests) only.
- Inside a single manager, dispatch to own methods via `self.`, not via `self._client.<same_method>`.
- When adding a new message-type case in `ConnectionManager.handle_message` or `SecureChatClient.handle_message_types`, route straight to the owning manager.
- Tests patch behaviour on the manager that owns it: `patch.object(c._connection, "handle_keepalive")`, `patch.object(c._key_exchange, "handle_dsa_random")`, `patch.object(c._file_transfer, "handle_chunk_binary")`.

`SecureChatProtocol` (protocol/shared.py) owns crypto: hybrid key exchange, Double Ratchet, message encryption/decryption, replay protection.

`server.py` has two top-level classes: `DeadDropManager` (file storage) and `SecureChatRequestHandler` (TCP handler per client).

## Versions

- `PROTOCOL_VERSION = "8.1.0"` — versioning is `Breaking.Minor.Patch`; only major version mismatches block sessions.
- `SERVER_VERSION = 9` — internal server implementation version, separate from protocol.
- Server reads/writes `identifier.txt` for its identifier string, which is mixed into all HKDF derivations.

## Key Exchange (16-step hybrid PQC)

Combines ML-KEM-1024 + HQC-256 + X25519 with ML-DSA-87 signatures. Two roles: Client A (initiator) and Client B (responder), assigned by the server.

High-level flow:
1. Both sides exchange ML-DSA public keys + 32-byte client randoms (`KE_DSA_RANDOM`).
2. A combined random is derived: `HKDF-SHA-512(larger_random, salt=smaller_random, info=server_id + 'comb_rand')`.
3. A sends ML-KEM-1024 public key (`KE_MLKEM_PUBKEY`), signed with ML-DSA.
4. B encapsulates → derives `intermediary_key_1 = HKDF-SHA3-512(ML-KEM_secret, salt=combined_random, info=server_id + 'int_key_1')` → sends ML-KEM ciphertext + encrypted HQC/X25519 public keys (`KE_MLKEM_CT_KEYS`).
5. A decapsulates, derives `intermediary_key_1`, decrypts B's keys; performs X25519 DH + HQC encapsulation → derives `intermediary_key_2 = HKDF-SHA3-512(intermediary_key_1, salt=X25519_secret, info=server_id + 'int_key_2')` → sends encrypted X25519 pubkey + HQC ciphertext (`KE_X25519_HQC_CT`).
6. Both derive final keys and exchange `KE_VERIFICATION` HMAC proofs; mismatch = abort.

All post-DSA messages are ML-DSA signed. ML-DSA keys are discarded after KE completes.

Final key derivation:
- **OTP material** (64 B): `HKDF-SHA3-512(HQC_secret, salt=combined_random, info=server_id + 'otp_material')`
- **Own chain key root** (64 B): `HKDF-SHA3-512(ML-KEM_secret || X25519_secret, salt=own_random, info=server_id + 'chain_key_root')`
- **Peer chain key root** (64 B): same but `salt=peer_random`

Full spec: `docs/SPEC.md`.

## Per-Message Encryption

1. ISO/IEC 7816-4 bit-pad plaintext to 512-byte multiple (append `0x80` then `0x00` fill). PKCS7 cannot represent a 512-byte block (pad-byte count ≤ 255), and the `cryptography` library caps `PKCS7(block_size)` at 2040 bits. Padding helpers are `_iso7816_pad` / `_iso7816_unpad` in `protocol/crypto_classes.py`.
2. XOR with SHAKE-256 keystream (OTP layer, keyed on HQC secret + secret nonces + counter).
3. Double AEAD: AES-256-GCM-SIV → ChaCha20-Poly1305 (sequential).
4. HMAC-SHA-512 over AAD (type, counter, nonce, per-message DH public key).

**Nonce hiding**: The 12-byte public nonce in the wire frame is XOR-mixed with key bytes to produce the real AEAD nonces, keeping actual nonces secret.

Double Ratchet advances per message with per-message ephemeral X25519 keypairs. LRU cache (capacity 1,000) handles out-of-order messages.

Wire format (`ENCRYPTED_MESSAGE`, type 10):
```
{"type": 10, "counter": uint32, "nonce": base64(12B), "ciphertext": base64, "dh_public_key": base64(32B), "verification": base64}
```

## Threading Model

- **Main thread**: UI event loop
- **Sender thread** (protocol): dequeues `_message_queue`, encrypts, sends every ~250 ms tick
- **Receiver thread** (client): `ConnectionManager.receive_loop()`, reads TCP socket, dispatches via `handle_message` → owning manager
- **Voice audio thread** (UI-owned): writes `VOICE_CALL_DATA` frames directly to the socket via `network_utils.send_message`, bypassing the 250 ms sender queue. Consequence: audio frames can arrive at the peer *before* a queued `VOICE_CALL_ACCEPT`. `VoiceCallManager.request()` flips `_active = True` at request time (not on accept) so inbound `VOICE_CALL_DATA` bypasses the rate limiter on the requester side.
- **Timer threads**: keepalive + auto-rekey (count threshold or time threshold)

## Rekeying

Runs the same hybrid KE as the initial handshake but over the existing encrypted channel (all rekey frames are `ENCRYPTED_MESSAGE` with `type=64` inner JSON). 6-step flow: both sides exchange DSA randoms, A sends ML-KEM pubkey, B sends encapsulated keys, A sends X25519/HQC ciphertext, both exchange verification proofs.

Race condition: if both peers initiate simultaneously, the side with the lexicographically smaller `client_random` becomes responder. Counters reset to zero after key switch.

Auto-rekey triggers: message count threshold or time threshold, both with ±10% jitter.

## Dead Drops

Anonymous async file sharing. Per-file key derivation uses Argon2id (memory_cost=4 GiB, iterations=4, lanes=4) then HKDF-SHA3-512 with a per-upload random salt. Password hash sent to server for download auth is a separate Argon2id derivation (memory_cost=2 GiB, iterations=6). Download-time challenge uses PBKDF2-HMAC-SHA3-512 over the stored password hash with a server-provided salt. Uses `ChunkIndependentDoubleEncryptor` — no chained authentication, so chunks decrypt in any order.

Server stores encrypted chunks in `deaddrop_files/` (configurable). Neither peer's session identity is exposed. Chunk limit: `DEADDROP_MAX_CHUNKS = 1,048,576` (memory exhaustion guard).

Dead drop KE uses a separate ML-KEM exchange with the server (independent of the peer session).

### Upload flow

`DeaddropManager.upload()` MUST wait on `_upload_accept_event` after sending encrypted metadata, before streaming any chunks. `_on_accept` sets the event on `DEADDROP_ACCEPT`; `DEADDROP_DENY` also sets it (with `_upload_accepted=False`) so the uploader unblocks and aborts. Streaming chunks before the server accepts the metadata cascades into spurious `"No active deaddrop upload"` errors for each chunk + the trailing `DEADDROP_COMPLETE` frame. Server error responses for metadata are intentionally generic (no leaking of name collision, quota, etc.) — the client cannot distinguish reasons.

## Field Validation

`utils/checks.py` enforces strict allowlists on all JSON messages:
- `allowed_outer_fields(msg_type)` — per-type allowlist for pre-verification (plaintext) frames.
- `allowed_unverified_inner_fields()` — superset allowlist for decrypted inner JSON before session verification completes.

Unknown fields → message dropped. This limits attack surface during the most vulnerable pre-verification phase.

## Rate Limits

- 5 messages/second per peer (client-side, excess dropped).
- Pre-verification message size limit: 33,260 bytes (size of largest KE message; lifted during file transfer/voice/rekey).
- Max message size: 64 MiB (`MAX_MESSAGE_SIZE`).
- Skipped-counter buffer: 1,000 entries (out-of-order delivery + memory exhaustion guard).

## Traffic Shaping

When encrypted and not transferring files, clients MAY send `DUMMY_MESSAGE` (type 12) packets every tick, up to `MAX_DUMMY_PACKET_SIZE = 512` bytes. Dummy messages go through full encrypt/decrypt + ratchet; counters advance normally. Disabled during file transfers.

## Configuration

`config.py` exposes singletons `ClientConfigHandler()` / `ServerConfigHandler()`. Auto-creates `config.json` on first run.

Key client options: rekey interval/count, dummy packet toggle, file paths, voice format, nickname.
Key server options: dead drop storage path + enabled flag, max dead drop size (default 10 GB), `max_unexpected_msgs`.

Server identifier stored in `identifier.txt` (auto-created; mixed into all HKDF `info` strings).

## UI Abstraction

All UIs implement `UIBase` (`SecureChatABCs/ui_base.py`). Capability flags (`FILE_TRANSFER`, `VOICE_CALLS`, `DEADDROP`, etc.) let the client adapt. When adding protocol features, check capability flags before calling UI methods.

## Testing Notes

- `tests/test_new_client.py` uses helper `_make_client()` to build a client with a MagicMock UI and a stub socket — safe to instantiate without network.
- `_full_ke_protocol_pair()` / `_inject_ready_protocol()` give tests a real post-KE protocol state for round-trip encrypt/decrypt.
- `patch("new_client.send_message")` intercepts raw sends for keepalive / KE tests.
- When adding new dispatched cases, add tests that patch the owning manager method (not the facade).

## Known Limitations

Python implementation — no constant-time guarantees. Not production-ready; timing attacks possible. Server sees metadata (IPs, padded sizes, timing). Endpoint compromise leaks keys and plaintext. Educational/research use only.