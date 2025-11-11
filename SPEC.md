Secure Chat Protocol (SCP)


## 1. Scope
This document specifies the Secure Chat Protocol (SCP) as implemented by this repository’s reference components: server.py, client.py, shared.py, and gui_client.py. SCP provides end‑to‑end encrypted, low‑latency messaging with optional file transfer, and optional extensions for ephemeral messaging and voice calls. The protocol targets two-party sessions routed by a minimal relay server.

      The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
      NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
      "OPTIONAL" in this document are to be interpreted as described in
      RFC 2119.

## 2. Normative references
- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels
- NIST SP 800‑56A (informative): Recommendation for Pair-Wise Key Establishment Schemes
- NIST SP 800‑38D (informative): AES-GCM recommendations
- RFC 8439 (informative): ChaCha20-Poly1305 for AEAD
- CRYSTALS-Kyber (informative): ML‑KEM 1024 parameter set

## 3. Terminology
- Client: An endpoint participating in a two-party session.
- Server: A simple relay that pairs two clients, forwards messages, and provides keepalives and basic control signals.
- Session: A cryptographic context established via key exchange between two clients.
- Encrypted message: An application payload protected by SCP’s message protection scheme.
- Control message: A plaintext JSON message used for server control, keepalive, key exchange signals, etc.

## 4. Protocol overview

### 4.1 Architecture
- The Server accepts up to two Clients simultaneously. Additional connections MAY be rejected via a SERVER_FULL control message.
- If the server allows more than two clients, the Server MUST set up separate sessions for each pair of clients.
- The Server acts as a router for messages between the two connected Clients and coordinates the start of key exchange.
- After a successful key exchange, Clients communicate using end‑to‑end encryption. The Server does not decrypt application data.

### 4.2 Versioning
- The protocol version is represented as a dotted string.
- The Server SHOULD send SERVER_VERSION_INFO {protocol_version} upon client connection. Clients SHOULD display a warning upon version mismatch; sessions MAY continue. Major version mismatches SHOULD be presented to the user as a risk.

#### 4.2.1 Version Compatibility
- Breaking version (X.y.z) differences MUST trigger user warnings
- Minor version (x.Y.z) differences SHOULD trigger informational notices
- Patch version (x.y.Z) differences MAY be silently ignored

### 4.3 Transport and framing
- Transport MUST be reliable and connection-oriented. TCP is RECOMMENDED.
- All messages relayed by the Server are length‑prefixed: a 4‑byte big‑endian unsigned integer indicating payload length, followed by that many bytes.
- Control messages (key exchange, server control, keepalive) are UTF‑8 JSON objects.
- ENCRYPTED_MESSAGE messages are UTF-8 JSON objects with base64-encoded ciphertext and metadata.
- FILE_CHUNK messages use an optimized binary frame format (see §9.3) for performance.
  
## 5. Message types
MessageType values are 16‑bit signed integers in the reference implementation (enumerated in shared.py). The following symbolic names and semantics are normative.

Key exchange and verification
- INITIATE_KEY_EXCHANGE (1): Server → Client. Signals a selected Client to initiate the key exchange.
- KEY_EXCHANGE_COMPLETE (2): Server → Clients. Announces that both sides reported key exchange completion; Clients SHOULD transition into the encrypted state.
- KEY_EXCHANGE_RESET (3): Server → Client. Informs the remaining Client to reset its key exchange state when its peer disconnects.
- KEY_EXCHANGE_RESPONSE (4): Client → Server (to peer). Carries KEM response and the responder’s session DH public key.
- KEY_EXCHANGE_INIT (5): Client → Server (to peer). Carries initiator’s KEM public key and session DH public key.
- KEY_VERIFICATION (62): Client ↔ Client (encrypted). Carries user confirmation of out‑of‑band key verification.

Messaging
- ENCRYPTED_MESSAGE (10): Client ↔ Client (encrypted). Carries text or structured inner messages.
- DELIVERY_CONFIRMATION (11): Client ↔ Client (encrypted). Reserved for GUI use; MAY be implemented.
- DUMMY_MESSAGE (12): Client ↔ Client (encrypted). Noise packets carrying random data to mask traffic patterns. RECOMMENDED (SHOULD).
- TEXT_MESSAGE (13): Inner type encapsulated inside ENCRYPTED_MESSAGE; carries plaintext text payload prior to encryption.

File transfer
- FILE_METADATA (20): Client ↔ Client (encrypted). Announces a proposed file transfer (name, size, hash, chunking, compression flag).
- FILE_ACCEPT (21): Client ↔ Client (encrypted). Accepts a pending file transfer by transfer_id.
- FILE_REJECT (22): Client ↔ Client (encrypted). Rejects a pending file transfer; includes reason.
- FILE_CHUNK (23): Client ↔ Client (encrypted, binary frame). Carries an encrypted chunk for an accepted transfer.
- FILE_COMPLETE (24): Client ↔ Client (encrypted). Signals that all chunks were sent/received.

Voice calls (OPTIONAL)
- VOICE_CALL_INIT (30), VOICE_CALL_ACCEPT (31), VOICE_CALL_REJECT (32), VOICE_CALL_DATA (33), VOICE_CALL_END (34): Optional extension messages used by GUI clients; implementations MAY omit.

Server control
- SERVER_FULL (40): Server → Client. Indicates the server is at capacity (two clients connected).
- SERVER_VERSION_INFO (41): Server → Client. Announces protocol_version.
- SERVER_DISCONNECT (42): Server → Client. Informs the client the server is disconnecting and SHOULD include reason.
- ERROR (43): Server → Clients. Broadcast error notification.
- KEEP_ALIVE (44): Server → Client. Liveness probe.

Client control
- CLIENT_DISCONNECT (50): Client → Server. Client intends to disconnect.
- KEEP_ALIVE_RESPONSE (51): Client → Server. Response to KEEP_ALIVE.

Client‑to‑client control (encrypted)
- EMERGENCY_CLOSE (60): Client ↔ Client. Immediate end of session.
- EPHEMERAL_MODE_CHANGE (61): Client ↔ Client. Optional toggle for ephemeral mode (OPTIONAL feature).
- NICKNAME_CHANGE (63): Client ↔ Client. Requests/announces nickname change.
- REKEY (64): Client ↔ Client. Rekey sub‑protocol messages (init/response/commit/commit_ack), encrypted.

## 6. Server behavior
- Capacity: The Server MAY allow more than two simultaneous Clients. If capacity is limited, additional connections SHOULD receive SERVER_FULL and be closed. When more than two Clients are allowed, the Server MUST create independent sessions for each communicating pair; session state MUST NOT be shared across pairs.
- Pairing and initiation: For each session between a specific pair of Clients, the Server MUST select one Client in that pair and send INITIATE_KEY_EXCHANGE to start that session’s handshake.
- Routing: For any received client message intended for a peer within a specific session (key exchange signals and all post‑exchange traffic), the Server MUST forward the bytes unchanged to the correct peer in that session.
- Version announcement: Upon connection, the Server SHOULD send SERVER_VERSION_INFO with protocol_version = PROTOCOL_VERSION.
- Keepalive: The Server SHOULD send KEEP_ALIVE roughly every 60 seconds to each connected Client. If a Client fails to respond with KEEP_ALIVE_RESPONSE to three consecutive probes, the Server SHOULD disconnect that Client with SERVER_DISCONNECT and MAY include an explanatory reason.
- Reset on peer loss: When a Client in a session disconnects, the Server MUST send KEY_EXCHANGE_RESET to its peer in that session. Other parallel sessions are unaffected.

## 7. Key exchange and session establishment

### 7.1 Cryptographic construction
- Hybrid key agreement: ML‑KEM‑1024 (Kyber) is combined with X25519 Diffie‑Hellman.
- The KEM shared secret and X25519 DH shared secret are combined via HKDF-SHA-512:
  - salt = kem_shared_secret (32 bytes)
  - info = b"hybrid kem+x25519"
  - output length = 32 bytes
- From the combined 32-byte shared secret, session-specific keys are derived using per-session salts:
  - **Per-session salt derivation**: Both parties independently compute a deterministic salt from the session's public key material:
    - Sort both ML-KEM public keys lexicographically
    - Concatenate: sorted_key_1 || sorted_key_2 || b"encryption_key_salt"
    - salt = SHA-512(concatenation)[0:32] (first 32 bytes)
  - **Encryption key** (32 bytes): HKDF-SHA-512 with the per-session salt, info=b"derive_root_encryption_mac_keys", length=32
  - **Root chain key** (64 bytes): Derived similarly with the per-session salt and info=b"chain_key_root", using HKDF-SHA3-512, length=64
- Both send_chain_key and receive_chain_key are initialized to the root chain key value (they start identical and diverge through ratcheting).

Rationale: The hybrid construction provides post‑quantum security against KEM breakage and mitigates single‑algorithm failure. Combining via HKDF ensures both secrets must be compromised to derive session keys. Per-session salts derived from public keys ensure that each session produces unique derived keys even if the same KEM/DH shared secrets were somehow reused, adding defense-in-depth. Lexicographic sorting ensures both parties compute identical salts regardless of initiator/responder roles. Separate SHA-512 and SHA3-512 derivations for encryption and chain keys provide algorithm diversity.

### 7.2 Messages
KEY_EXCHANGE_INIT (JSON):
{
  "version": string,                  // MUST be PROTOCOL_VERSION
  "type": 5,
  "public_key": base64,              // ML‑KEM public key of initiator
  "dh_public_key": base64            // X25519 session public key of initiator
}

KEY_EXCHANGE_RESPONSE (JSON):
{
  "version": string,                  // MUST be PROTOCOL_VERSION
  "type": 4,
  "ciphertext": base64,              // ML‑KEM encapsulation to initiator’s KEM key
  "public_key": base64,              // Responder’s KEM public key (for verification context)
  "dh_public_key": base64            // Responder’s X25519 session public key
}

- The initiator, upon receiving KEY_EXCHANGE_RESPONSE, decapsulates the KEM, mixes with DH(X25519) to derive the session secret, initializes encryption and ratchet state, and transitions to the encrypted state.
- The responder, upon processing KEY_EXCHANGE_INIT, encapsulates to the provided KEM public key, performs DH with the initiator’s X25519 key, derives the same secret, initializes its state, and sends KEY_EXCHANGE_RESPONSE.
- Version mismatch: If peer version differs, Clients SHOULD warn the user, but MAY continue.

### 7.3 Verification (out‑of‑band)
- After Server sends KEY_EXCHANGE_COMPLETE, Clients SHOULD display a human‑readable session fingerprint derived from the combined key material and provide a mechanism to exchange KEY_VERIFICATION {verified: bool}.

Rationale: The hybrid construction provides post‑quantum security against KEM breakage and mitigates single‑algorithm failure. The user verification step defends against active MITM at the relay.

## 8. Message protection and ratcheting

### 8.1 Primitives
- AEAD composition: A DoubleEncryptor composes AES‑GCM‑SIV and ChaCha20‑Poly1305 sequentially under keys derived from HKDF. Nonces are XOR‑mixed with secret material.
- Padding: Plaintext is padded to a multiple of 512 bytes (PKCS7) prior to encryption to hinder traffic analysis.
- Additional MAC: A separate HMAC‑SHA‑512 over selected metadata further authenticates fields (e.g., counters and per‑message DH keys) to mitigate CPU‑exhaustion attacks on high counters.

### 8.2 Counters and AAD
- Each message increments a sender counter (uint32). The receiver maintains a peer_counter.
- The receiver MUST reject messages with counter ≤ peer_counter unless it has saved chain state for that counter (out-of-order delivery).
- Implementations SHOULD support limited out-of-order message delivery by saving intermediate chain states for skipped counters.
- A bounded buffer (RECOMMENDED: 1000 entries) SHOULD be used to store skipped counter states to prevent memory exhaustion.
- For ENCRYPTED_MESSAGE and FILE_CHUNK, AAD includes type, counter, nonce, and the sender's per‑message X25519 public key.

### 8.3 ENCRYPTED_MESSAGE format (JSON)
Outer (after encryption, sent as bytes):
{
  "type": 10,
  "counter": uint32,
  "nonce": base64(12 bytes),
  "ciphertext": base64,
  "dh_public_key": base64(32 bytes),
  "verification": base64(HMAC‑SHA‑512)
}

Inner (plaintext JSON, examples):
- Text: {"type": 13, "text": string}
- File metadata: see §9.1
- Control: e.g., {"type": 60} for EMERGENCY_CLOSE, {"type": 64, ...} for REKEY

### 8.4 State updates
- Send path: Mix DH(ephemeral, peer base) into the send chain, derive per‑message key, ratchet send chain forward.
- Receive path: Advance a temp chain from receive_chain_key up to the counter, mix DH(peer ephemeral, own receive private), derive per‑message key, verify/decrypt, then commit the receive_chain_key to the new state and update peer_counter.

## 9. File transfer
Implementations SHOULD support file transfer as specified here. Compression is OPTIONAL; see §9.4.

### 9.1 Metadata (encrypted JSON inside ENCRYPTED_MESSAGE)
{
  "type": 20,
  "transfer_id": string (<= 64, alnum),
  "filename": string,
  "file_size": int,
  "file_hash": hex(blake2b‑256),        // hash of original file
  "total_chunks": int,
  "compressed": bool,
  "processed_size": int                 // size of the data stream after (optional) compression
}

- The sender MUST generate a transfer_id that is unique within the session and contains only alphanumeric characters (maximum 64 characters).
- The sender SHOULD derive transfer_id deterministically from file metadata to enable idempotent retries.
- The receiver MUST validate required fields, that transfer_id is alphanumeric and ≤ 64 characters, and that file_size and total_chunks are reasonable values.

### 9.2 Acceptance / rejection (encrypted JSON)
- FILE_ACCEPT {"type": 21, "transfer_id": string}
- FILE_REJECT {"type": 22, "transfer_id": string, "reason": string}

### 9.3 Chunk data (binary frame)
Frame layout:
[ counter(4) | nonce(12) | sender_ephemeral_dh(32) | ciphertext(variable) ]

Ciphertext plaintext layout (before encryption):
[ header_len(2) | header_json | chunk_bytes ]

Header JSON:
{
  "type": 23,
  "transfer_id": string,
  "chunk_index": int
}

- The receiver MUST verify AAD (type/counter/nonce/dh_public_key), decrypt, parse header_json, and associate chunk_bytes with transfer_id, chunk_index.
- Recommended chunk size is SEND_CHUNK_SIZE = 1 MiB. Implementations MAY use different sizes when interoperable.
- The receiver SHOULD write chunks to a temporary file at offset chunk_index * SEND_CHUNK_SIZE and track received indices; upon completion it SHOULD verify the final file hash and move to the destination path atomically. If compressed=true, it SHOULD decompress before final verification and move.

### 9.4 Compression
- The sender MAY compress the file stream before chunking. The metadata.compressed flag MUST reflect the decision.
- Implementations SHOULD avoid compressing known incompressible types (e.g., .zip, .png, .mp3); a non‑normative list is provided in shared.py.

## 10. Keepalive and liveness
- The Server SHOULD send KEEP_ALIVE every ~60 seconds to each Client.
- Clients MUST respond with KEEP_ALIVE_RESPONSE promptly upon receipt.
- If three consecutive responses are missed, the Server SHOULD disconnect the Client and SHOULD notify with SERVER_DISCONNECT.

## 11. Rate limits and field validation
### 11.1 Message throttling
- Clients SHOULD apply rate limits of at least 5 messages per second per peer. Excess messages SHOULD be dropped.
- Clients SHOULD reject single messages larger than 8,192 bytes from unverified peers, unless an allowed high‑volume activity (file transfer, voice call, or rekey) is in progress.

### 11.2 Field validation
- For plaintext outer JSON prior to encryption being established or verification complete, Clients SHOULD enforce an allow‑list of fields per message type and drop messages containing unexpected fields.
- For decrypted inner JSON, Clients SHOULD enforce a superset allow‑list of fields for known message categories and drop messages with unexpected fields.

Rationale: Conservative validation limits attack surface and reduces parsing risks from untrusted peers during the most vulnerable phases (pre‑verification).

## 12. Traffic shaping and intervals
### 12.1 Defined send interval
- Clients SHOULD send at a regular interval (e.g., every 250 ms tick) from a background sender loop. When no application data is pending, Clients SHOULD consider sending dummy messages (§12.2) to preserve a consistent traffic pattern.

### 12.2 Dummy messages
- When encryption is active and no file transfer is in progress, Clients SHOULD send DUMMY_MESSAGE packets at the defined interval containing random data up to a configurable limit (default MAX_DUMMY_PACKET_SIZE = 512 bytes).
- Dummy messages MUST be indistinguishable from normal encrypted messages on the wire (i.e., encrypted under the same scheme with plausible AAD and counters).
- Dummy messages MUST increment the sender's message counter in the same sequence as application messages to maintain ratchet state consistency.
- Receivers MUST process dummy messages through the full decryption and ratcheting pipeline but MAY discard the plaintext after successful verification.

Rationale: Regular intervals and dummy traffic hinder traffic analysis by flattening observable timing and size patterns. Counter sharing prevents adversaries from distinguishing dummy traffic by observing counter gaps.

## 13. Rekeying
- Rekeying messages (type REKEY=64) MUST be sent inside ENCRYPTED_MESSAGE and follow a three‑step flow: {action: "init"} → {action: "response"} → {action: "commit"} → {action: "commit_ack"}.
- Upon successful commit, both sides MUST activate pending keys atomically after sending an encrypted "encrypt_json_then_switch" instruction to avoid ambiguity.

## 14. Error handling and disconnects
- Server errors SHOULD be broadcast using ERROR {error: string}. Clients SHOULD surface the message to the user.
- The Server MAY send SERVER_DISCONNECT {reason} prior to closing a connection.
- Clients MAY send EMERGENCY_CLOSE inside ENCRYPTED_MESSAGE to immediately terminate peer communication; implementations SHOULD send it without queue delay.

## 15. Optional features
- Ephemeral mode: EPHEMERAL_MODE_CHANGE (61) MAY be implemented to instruct peers/GUI to apply ephemeral retention rules. Protocol behavior remains identical on the wire.
- Voice calls: VOICE_CALL_* (30–34) MAY be implemented for real‑time audio. These messages MUST be sent inside ENCRYPTED_MESSAGE when used.

## 16. Conformance
A conformant SCP implementation MUST:
- Implement transport framing (§4.3) with length-prefixed messages.
- Implement Server capacity rules (§6) with at least two-client support and keepalive (§10).
- Implement the hybrid KEM+X25519 key exchange (§7) with version announcement.
- Implement message protection and Double Ratchet (§8) with per-message ephemeral DH.
- Implement ENCRYPTED_MESSAGE messaging (§8.3) with counter-based replay protection.
- Support KEY_VERIFICATION signaling and fingerprint display (§7.3).
- Support REKEY (§13) and EMERGENCY_CLOSE.
- Enforce counter monotonicity with support for bounded out-of-order delivery (§8.2).

A conformant implementation SHOULD:
- Implement file transfer (§9) with binary chunk framing.
- Implement rate limiting and field validation (§11).
- Implement traffic shaping with regular send intervals and dummy messages (§12).
- Support compression for file transfers (§9.4) with automatic detection of incompressible types.

A conformant implementation MAY:
- Implement ephemeral mode and voice call extensions (§15).
- Support more than two simultaneous clients with independent session management (§6).

## 17. Security considerations
- Post‑quantum and classical hybridization reduces the risk of single‑algorithm compromise; combining KEM and DH via HKDF binds secrets and ensures both are required to fail for a full break.
- Padding to 512 bytes and dummy traffic defend against size and timing analysis; these do not eliminate all side channels, but increase cost for an adversary.
- Separate HMAC over counters and per‑message DH public keys reduces the feasibility of CPU‑exhaustion via forged high counters without early rejection.
- Replay protection via counters and ratchet advancement is mandatory; implementations MUST reject stale counters.
- Keys and sensitive state SHOULD be overwritten after use where practical (best‑effort erasure).
- The Double Ratchet mechanism with per-message X25519 ephemeral keys provides forward secrecy: compromise of long-term keys does not expose past messages. Breaking secrecy of message N requires both: (1) the chain key state at counter N, and (2) the ephemeral DH private key for message N.
- Implementations SHOULD limit the skipped counter buffer to prevent memory exhaustion attacks where an adversary sends messages with very high counter values.

## 18. Privacy considerations
- The Server observes only metadata needed to route and maintain liveness (connection timing, message sizes, connection tuples). Payloads are end‑to‑end encrypted.
- Server implementations SHOULD minimize operational logs and avoid storing connection metadata (IP addresses, message sizes, timestamps, session durations) beyond immediate operational needs.
- Server implementations MUST NOT log message content, counters, nonces, key exchange material, or any cryptographic state under any circumstances.
- Server implementations SHOULD NOT persist connection logs to disk; in-memory operational state is preferred.
- Both clients and servers SHOULD consider memory-resident operations over persistent storage where feasible to reduce forensic exposure.

## 19. Interoperability notes
- PROTOCOL_VERSION mismatches SHOULD be surfaced as warnings; minor version differences MAY interoperate when message schemas are unchanged.
- File chunk size MAY vary; receivers SHOULD accept any size and write chunks at the indicated index boundaries when SEND_CHUNK_SIZE is known to both parties.

## 20. Implementation notes (non-normative)

### 20.1 Memory management
- Implementations SHOULD overwrite cryptographic key material with zeros before deallocation where possible
- File chunk buffers SHOULD be limited in size; use streaming I/O rather than loading entire files

### 20.2 Error handling
- Cryptographic failures (MAC verification, decryption) SHOULD be indistinguishable to external observers to avoid oracle attacks
- Connection errors during file transfer SHOULD allow resume via partial chunk tracking

### 20.3 Performance considerations
- Dummy traffic generation SHOULD be disabled during large file transfers to conserve bandwidth
- Implementations MAY batch multiple small messages into a single send interval

## 21. Appendix A: Wire examples (non‑normative)
A.1 ENCRYPTED_MESSAGE (text)
{
  "type": 10,
  "counter": 42,
  "nonce": "base64...",
  "ciphertext": "base64...",
  "dh_public_key": "base64...",
  "verification": "base64..."
}
Inner plaintext (example): {"type": 13, "text": "Hello"}

A.2 FILE_CHUNK frame
| 00 00 00 2A | <12b nonce> | <32b eph pub> | <ciphertext bytes...>