Secure Chat Protocol (SCP)


## 1. Scope
This document specifies the Secure Chat Protocol (SCP) as implemented by this repository’s reference components: server.py, client.py, shared.py, and gui_client.py. SCP provides end‑to-end encrypted, low‑latency messaging with optional file transfer, and optional extensions for ephemeral messaging and voice calls. The protocol targets two-party sessions routed by a minimal relay server.

      The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
      NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
      "OPTIONAL" in this document are to be interpreted as described in
      RFC 2119.

## 2. Normative references
- RFC 2119: Keywords for use in RFCs to Indicate Requirement Levels
- NIST SP 800‑56A (informative): Recommendation for Pair-Wise Key Establishment Schemes
- NIST SP 800‑38D (informative): AES-GCM recommendations
- RFC 8439 (informative): ChaCha20-Poly1305 for AEAD
- CRYSTALS-Kyber (informative): ML‑KEM 1024 parameter set
- HQC (informative): Hamming Quasi-Cyclic KEM, HQC‑256 parameter set
- FIPS 202 (informative): SHA‑3 and SHAKE‑256

## 3. Terminology
- Client: An endpoint participating in a two-party session.
- Server: A simple relay that pairs two clients, forwards messages, and provides keepalives and basic control signals.
- Session: A cryptographic context established via key exchange between two clients.
- Encrypted message: An application payload protected by SCP’s message protection scheme.
- Control message: A plaintext JSON message used for server control, keepalive, key exchange signals, etc.

## 4. Protocol overview

### 4.1 Architecture
- The Server accepts up to two Clients simultaneously for a single session. Additional connections MAY be rejected via a SERVER_FULL control message.
- **Multi-client extensions**: If a server implementation allows more than two simultaneous clients, it MUST create completely independent sessions for each pair of clients. Each session operates as follows:
  - **Session isolation**: Clients in different sessions MUST NOT be aware of each other's existence. Client A communicating with Client B has no knowledge of Client C or Client D in a separate session.
  - **Independent state**: Each session maintains its own key exchange state, encryption keys, message counters, and routing state. Session state MUST NOT be shared across pairs.
  - **Separate key exchanges**: When Client A and Client B form one session, and Client C and Client D form another, each pair performs an independent key exchange. The server initiates key exchange separately for each session.
  - **Message routing**: The server routes messages only between the two clients in the same session. Messages from Client A are delivered only to Client B, never to Client C or Client D.
  - **Capacity limits**: If a server supports N total clients, it can support N/2 concurrent sessions. Implementations SHOULD document their capacity limits.
  
  **Example**: A server allowing four simultaneous clients can operate two independent sessions: {Client A ↔ Client B} and {Client C ↔ Client D}. Client A can only communicate with Client B and is unaware of the existence of Clients C and D.

- The Server acts as a router for messages between the two connected Clients in a session and coordinates the start of key exchange for that session.
- After a successful key exchange, Clients communicate using end‑to‑end encryption. The Server MUST NOT attempt to decrypt application data.

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
- FILE_CHUNK messages use an optimised binary frame format (see §9.3) for performance.
  
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
- DUMMY_MESSAGE (12): Client ↔ Client (encrypted). Noise packets carrying random data to mask traffic patterns. RECOMMENDED.
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
- SERVER_DISCONNECT (42): Server → Client. Informs the client the server is disconnecting and SHOULD include a reason.
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
- **Capacity**: The Server MAY allow more than two simultaneous Clients across multiple sessions. If capacity is limited to a single session, additional connections beyond two SHOULD receive SERVER_FULL and be closed. 
  - **Multi-session servers**: When more than two Clients are allowed, the Server MUST create independent sessions for each communicating pair. Each session consists of exactly two clients who can only communicate with each other.
  - **Session state isolation**: Session state (key exchange progress, routing tables, keepalive tracking) MUST NOT be shared across sessions. Each session is completely independent.
  - **Client pairing**: Implementations MAY use different pairing strategies (first-come-first-served pairing, explicit room/session IDs, etc.) but MUST ensure clients are aware only of their paired peer, never of other sessions.

- **Pairing and initiation**: For each session between a specific pair of Clients, the Server MUST select one Client in that pair and send INITIATE_KEY_EXCHANGE to start that session's handshake.
- **Routing**: For any received client message intended for a peer within a specific session (key exchange signals and all post‑exchange traffic), the Server MUST forward the bytes unchanged to the correct peer in that session. The Server MUST NOT route messages across session boundaries.
- **Version announcement**: Upon connection, the Server SHOULD send SERVER_VERSION_INFO with protocol_version = PROTOCOL_VERSION.
- **Keepalive**: The Server SHOULD send KEEP_ALIVE roughly every 60 seconds to each connected Client in all sessions. If a Client fails to respond with KEEP_ALIVE_RESPONSE to three consecutive probes, the Server SHOULD disconnect that Client with SERVER_DISCONNECT and MAY include an explanatory reason.
- **Reset on peer loss**: When a Client in a session disconnects, the Server MUST send KEY_EXCHANGE_RESET to its peer in that session. Other parallel sessions MUST be unaffected by the disconnect.

## 7. Key exchange and session establishment

### 7.1 Cryptographic construction
- Hybrid key agreement: ML‑KEM‑1024 (Kyber) and HQC‑256 KEMs are used alongside X25519 Diffie‑Hellman.
- Session secrets:
  - ML‑KEM shared secret and X25519 DH shared secret are combined via HKDF‑SHA‑512 to produce the session shared secret used for AEAD keys:
    - salt = mlkem_shared_secret (32 bytes)
    - info = b"hybrid kem+x25519"
    - output length = 32 bytes
  - HQC shared secret is retained separately and used to derive a per‑message one‑time keystream for an OTP‑style XOR layer (see §8.1).
- From the combined 32‑byte session shared secret, session-specific keys are derived using per-session salts:
  - **Per-session salt derivation**: Both parties independently compute a deterministic salt from the session's public key material:
    ```
    Algorithm: Derive per-session salt
    Input: mlkem_pk_initiator, mlkem_pk_responder (ML-KEM-1024 public keys, 1568 bytes each)
           hqc_pk_initiator, hqc_pk_responder (HQC-256 public keys, variable length)
           x25519_pk_initiator, x25519_pk_responder (X25519 public keys, 32 bytes each)
    Output: salt (32 bytes)
    
    1. Create a list: keys = [mlkem_pk_initiator, mlkem_pk_responder,
                               hqc_pk_initiator, hqc_pk_responder,
                               x25519_pk_initiator, x25519_pk_responder]
    2. Sort keys lexicographically by comparing bytes:
       - Treat each key as a byte sequence
       - Compare byte-by-byte (0x00 < 0x01 < ... < 0xFF)
       - Shorter sequences sort before longer sequences if all compared bytes are equal
    3. Concatenate sorted keys: combined = keys[0] || keys[1] || ... || keys[5]
    4. Append context string: material = combined || b"encryption_key_salt"
    5. Compute hash: salt = SHA‑512(material)[0:32] (first 32 bytes of SHA-512 digest)
    ```
    
    **Implementation note**: Lexicographic sorting ensures both initiator and responder compute identical salts regardless of role. The sorted order is deterministic based on the byte representation of public keys.
    
  - **Encryption key** (32 bytes): HKDF‑SHA‑512(ikm=session_shared_secret, salt=per_session_salt, info=b"derive_root_encryption_mac_keys", length=32)
  - **Root chain key** (64 bytes): HKDF‑SHA3‑512(ikm=session_shared_secret, salt=per_session_salt, info=b"chain_key_root", length=64)
- Both send_chain_key and receive_chain_key are initialised to the root chain key value (they start identical and diverge through ratcheting).

Rationale: The hybrid construction provides post‑quantum security against KEM breakage and mitigates single‑algorithm failure. Combining ML‑KEM with X25519 via HKDF ensures both secrets must be compromised to derive session AEAD keys. Retaining an independent HQC secret to drive an OTP‑style XOR layer adds defence‑in‑depth for ciphertext confidentiality even if an AEAD layer is weakened. Per-session salts derived from public keys ensure uniqueness of derived keys. Lexicographic sorting ensures both parties compute identical salts regardless of initiator/responder roles. Separate SHA‑512 and SHA3‑512 derivations for encryption and chain keys provide algorithm diversity.

### 7.2 Messages
KEY_EXCHANGE_INIT (JSON):
{
  "version": string,                  // MUST be PROTOCOL_VERSION
  "type": 5,
  "mlkem_public_key": base64,        // ML‑KEM public key of initiator
  "hqc_public_key": base64,          // HQC‑256 public key of initiator (for OTP keystream secret)
  "dh_public_key": base64            // X25519 session public key of initiator
}

KEY_EXCHANGE_RESPONSE (JSON):
{
  "version": string,                  // MUST be PROTOCOL_VERSION
  "type": 4,
  "mlkem_ciphertext": base64,        // ML‑KEM encapsulation to initiator’s ML‑KEM key
  "mlkem_public_key": base64,        // Responder’s ML‑KEM public key (for verification context)
  "hqc_ciphertext": base64,          // HQC encapsulation to initiator’s HQC key
  "hqc_public_key": base64,          // Responder’s HQC public key (for verification context)
  "dh_public_key": base64            // Responder’s X25519 session public key
}

- The initiator, upon receiving KEY_EXCHANGE_RESPONSE, decapsulates ML‑KEM and HQC ciphertexts, mixes the ML‑KEM shared secret with DH(X25519) via HKDF to derive the session secret, sets the HQC shared secret aside for the OTP keystream, initialises encryption and ratchet state, and transitions to the encrypted state.
- The responder, upon processing KEY_EXCHANGE_INIT, encapsulates to the provided ML‑KEM and HQC public keys, performs DH with the initiator’s X25519 key, derives the same secrets, initialises its state, and sends KEY_EXCHANGE_RESPONSE.
- Version mismatch: If the peer version differs, Clients SHOULD warn the user, but MAY continue.

### 7.3 Verification (out‑of‑band)
- After Server sends KEY_EXCHANGE_COMPLETE, Clients SHOULD display a human‑readable session fingerprint derived from the combined key material and provide a mechanism to exchange KEY_VERIFICATION {verified: bool}.
- The fingerprint MUST be computed from a deterministic, order‑independent combination of both parties’ public keys, including ML‑KEM public keys, X25519 session public keys, and HQC public keys (e.g. lexicographic sort then concatenate before hashing to words). This ensures both parties see the same fingerprint regardless of initiator/responder roles.

Rationale: The hybrid construction provides post‑quantum security against KEM breakage and mitigates single‑algorithm failure. The user verification step defends against active MITM at the relay, and inclusion of all public keys (ML‑KEM, X25519, HQC) binds the full handshake context.

## 8. Message protection and ratcheting

### 8.1 Primitives
- AEAD composition: A DoubleEncryptor composes AES‑GCM‑SIV and ChaCha20‑Poly1305 sequentially under keys derived from HKDF. Nonces are XOR‑mixed with secret material derived from the ratchet chain, ensuring the actual nonce used internally by the AEAD ciphers is hidden from adversaries. Although a nonce value appears in the wire format (§8.3), the true AEAD nonce is secret and not public knowledge. This prevents known-nonce attacks against ChaCha20-Poly1305 and AES-GCM-SIV, as an adversary observing network traffic cannot determine the actual nonce values used in the encryption operations.
  - **Nonce mixing**: The DoubleEncryptor derives secret nonces for each AEAD cipher by XORing the public nonce with portions of the encryption key:
    - AES-GCM-SIV nonce (12 bytes): `aes_nonce = public_nonce XOR encryption_key[0:12]` (first 12 bytes of the 64-byte encryption key)
    - ChaCha20-Poly1305 nonce (12 bytes): `chacha_nonce = public_nonce XOR encryption_key[-12:]` (last 12 bytes of the 64-byte encryption key)
  - The public nonce (12 random bytes) is transmitted in the message (§8.3), but the actual nonces provided to the AEAD primitives remain secret because the encryption key is never transmitted and is derived independently by both parties from the shared secret.
- OTP layer from HQC secret: In addition to the double AEAD, an OTP‑style XOR layer is applied using a per‑message keystream derived from the HQC shared secret and the message counter. The keystream is generated as SHAKE‑256(hqc_secret || counter_be_32) and truncated to the ciphertext length. Encryption applies XOR before the AEAD layers; decryption removes the XOR after AEAD decryption. This layer adds confidentiality even if an AEAD layer is weakened. Implementations MUST use the exact same counter value as in the message AAD to derive the keystream.
- Padding: Plaintext is padded to a multiple of 512 bytes (PKCS7) prior to encryption to hinder traffic analysis.
- Additional MAC: A separate HMAC‑SHA‑512 over selected metadata further authenticates fields (e.g. counters and per‑message DH keys) to mitigate CPU‑exhaustion attacks on high counters.

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
- Control: e.g. {"type": 60} for EMERGENCY_CLOSE, {"type": 64, ...} for REKEY

### 8.4 State updates
- Send path: Mix DH(ephemeral, peer base) into the send chain, derive per‑message key, ratchet the send chain forward.
- Receive path: Advance a temp chain from receive_chain_key up to the counter, mix DH(peer ephemeral, own receive private), derive per‑message key, verify/decrypt, then commit the receive_chain_key to the new state and update peer_counter.

## 9. File transfer
Implementations MAY support file transfer as specified here. Compression is OPTIONAL; see §9.4.

### 9.1 Metadata (encrypted JSON inside ENCRYPTED_MESSAGE)
{
  "type": 20,
  "transfer_id": string (<= 64, alnum),
  "filename": string,
  "file_size": int,
  "file_hash": hex(blake2b‑256),        // hash of the original file
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
- Implementations SHOULD avoid compressing known incompressible types (e.g. zip, png, mp3).

## 10. Keepalive and liveness
- The Server SHOULD send KEEP_ALIVE every ~60 seconds to each Client.
- Clients MUST respond with KEEP_ALIVE_RESPONSE promptly upon receipt.
- If three consecutive responses are missed, the Server SHOULD disconnect the Client and MAY notify with SERVER_DISCONNECT.

## 11. Rate limits and field validation
### 11.1 Message throttling
- Clients MAY apply rate limits of at least five messages per second per peer. Excess messages SHOULD be dropped.
- Clients MAY reject single messages larger than 33.260 bytes from unverified peers, unless an allowed high‑volume activity (file transfer, voice call, or rekey) is in progress.
- Client MUST NOT reject messages <= 33.260 bytes due to their size. That is the size of the KEY_EXCHANGE_RESPONSE message.

### 11.2 Field validation
- For plaintext outer JSON, Clients SHOULD enforce an allow‑list of fields per message type and drop messages containing unexpected fields.
- For decrypted inner JSON, Clients SHOULD enforce a superset allow‑list of fields for known message categories and drop messages with unexpected fields.

Rationale: Conservative validation limits attack surface and reduces parsing risks from untrusted peers during the most vulnerable phases (pre‑verification).

## 12. Traffic shaping and intervals
### 12.1 Defined send interval
- Clients MAY send at a regular interval (e.g. every 250 ms tick) from a background sender loop. When no application data is pending, Clients MAY consider sending dummy messages (§12.2) to preserve a consistent traffic pattern.

### 12.2 Dummy messages
- When encryption is active and no file transfer is in progress, Clients MAY send DUMMY_MESSAGE packets at the defined interval containing random data up to a configurable limit (default MAX_DUMMY_PACKET_SIZE = 512 bytes).
- Dummy messages MUST be indistinguishable from normal encrypted messages on the wire (i.e. encrypted under the same scheme with plausible AAD and counters).
- Dummy messages MUST increment the sender's message counter in the same sequence as application messages to maintain ratchet state consistency.
- Receivers MUST process dummy messages through the full decryption and ratcheting pipeline but SHOULD discard the plaintext after successful verification.

Rationale: Regular intervals and dummy traffic hinder traffic analysis by flattening observable timing and size patterns. Counter sharing prevents adversaries from distinguishing dummy traffic by observing counter gaps.

## 13. Rekeying
- Rekeying messages (type REKEY=64) MUST be sent inside ENCRYPTED_MESSAGE and follow a three‑step flow: {action: "init"} → {action: "response"} → {action: "commit"}. A fourth {action: "commit_ack"} step MAY be used by implementations that desire explicit acknowledgement.
- Upon successful commit, both sides MUST activate pending keys atomically after sending an encrypted "encrypt_json_then_switch" instruction to avoid ambiguity.

13.1 REKEY message schemas (inner JSON)
- Init (sender → peer):
  {
    "type": 64,
    "action": "init",
    "mlkem_public_key": base64,
    "hqc_public_key": base64,
    "dh_public_key": base64
  }
- Response (responder → sender):
  {
    "type": 64,
    "action": "response",
    "mlkem_ciphertext": base64,
    "hqc_ciphertext": base64,
    "dh_public_key": base64
  }
- Commit (sender → responder):
  {
    "type": 64,
    "action": "commit"
  }
- Commit ack (OPTIONAL):
  {
    "type": 64,
    "action": "commit_ack"
  }

13.2 Rekey semantics
- The responder MUST derive pending keys from ML‑KEM and X25519 (as in §7.1) and set the HQC secret aside for the OTP keystream (as in §8.1). Active keys MUST NOT change until commit is processed.
- After processing the response, the initiator MUST derive pending keys and then send commit. Both sides MUST switch to the pending keys atomically after the next encrypted instruction ("encrypt_json_then_switch").
- After switching, message counters MUST reset to zero on both sides.

13.3 Automatic rekeying (OPTIONAL)
- Implementations MAY initiate rekeying automatically. Triggers MAY include:
  - Message count threshold (e.g. after N messages, possibly with randomised jitter per session), and/or
  - Time‑based threshold (e.g. every T minutes of active messaging).
- When automatic rekeying is enabled, peers SHOULD avoid synchronised rekeys by applying random jitter around the base threshold.
- If a peer rejects or ignores REKEY, the initiator SHOULD back off and MAY retry later, or allow manual rekey.

## 14. Error handling and disconnects
- Server errors SHOULD be broadcast using ERROR {error: string}. Clients SHOULD surface the message to the user.
- The Server MAY send SERVER_DISCONNECT {reason} before closing a connection.
- Clients MAY send EMERGENCY_CLOSE inside ENCRYPTED_MESSAGE to immediately terminate peer communication; implementations SHOULD send it without queue delay.

## 15. Optional features
- Ephemeral mode: EPHEMERAL_MODE_CHANGE (61) MAY be implemented to instruct peers/GUI to apply ephemeral retention rules. Protocol behaviour remains identical on the wire.
- Voice calls: VOICE_CALL_* (30–34) MAY be implemented for real‑time audio. These messages MUST be sent inside ENCRYPTED_MESSAGE when used.

## 16. Conformance
A conformant SCP implementation MUST:
- Implement transport framing (§4.3) with length-prefixed messages.
- Implement Server capacity rules (§6) with at least two-client support and keepalive (§10).
- Implement the hybrid KEM+X25519 key exchange (§7) with version announcement.
- Implement message protection and Double Ratchet (§8) with per-message ephemeral DH.
- Implement ENCRYPTED_MESSAGE messaging (§8.3) with counter-based replay protection.
- Support KEY_VERIFICATION signalling and fingerprint display (§7.3).
- Support REKEY (§13) and EMERGENCY_CLOSE.
- Enforce counter monotonicity with support for bounded out-of-order delivery (§8.2).

A conformant implementation SHOULD:
- Implement rate limiting and field validation (§11).
- Implement traffic shaping with regular send intervals and dummy messages (§12).

A conformant implementation MAY:
- Implement file transfer (§9) with binary chunk framing. 
- Support compression for file transfers (§9.4) with automatic detection of incompressible types.
- Implement ephemeral mode and voice call extensions (§15).
- Support more than two simultaneous clients with independent session management (§6).

## 17. Trust and threat model

### 17.1 Trust assumptions
The protocol relies on the following trust assumptions:
- **Endpoint security**: Both communicating parties maintain secure endpoints (devices, operating systems, application environment) that are not compromised. The protocol cannot protect against compromised endpoints that leak keys, plaintext, or metadata.
- **Server relay fidelity**: The server is trusted to faithfully relay messages between clients without modification, dropping, or injection. The server is NOT trusted with confidentiality or authenticity of message content, but it MUST correctly forward encrypted payloads.
- **Out-of-band verification**: Both parties perform the fingerprint verification step (§7.3) correctly over an authenticated out-of-band channel (e.g. in-person comparison, authenticated video call, trusted messenger).
- **Cryptographic primitives**: ML-KEM-1024 (Kyber), HQC-256, X25519, ChaCha20-Poly1305, AES-GCM-SIV, HMAC-SHA-512, HKDF-SHA-512, HKDF-SHA3-512, BLAKE2b, SHAKE-256, and SHA-512 remain cryptographically secure against the adversary's computational capabilities.

### 17.2 Security guarantees
Under the trust assumptions above, the protocol provides:
- **Authenticity**: Messages are authenticated end-to-end. Any attempt to forge or modify messages in transit will be detected and rejected by the AEAD verification (ChaCha20-Poly1305 and AES-GCM-SIV) and the additional HMAC-SHA-512 verification layer.
- **Confidentiality**: Message content is protected by double AEAD encryption and an additional OTP-style XOR layer derived from HQC-256, and is not accessible to the server or network observers, assuming the underlying ciphers remain secure.
- **Forward secrecy**: Compromise of key material does not expose past session messages. Each message uses an ephemeral X25519 key mixed into the ratchet chain; an adversary must obtain both the chain state at counter N and the ephemeral DH private key for message N to decrypt that message.
- **Post-quantum security**: The triple-hybrid key exchange (ML-KEM-1024 + HQC-256 + X25519) provides resilience against future quantum attackers. To compromise session keys, an adversary must break all three algorithms, including both post-quantum KEMs.
- **Plausible deniability**: After a conversation, either party can forge transcripts that appear authentic (due to symmetric keys and lack of non-repudiable signatures), preventing cryptographic proof of authorship to third parties.

### 17.3 Threat model

#### 17.3.1 Adversary capabilities
The protocol is designed to resist the following adversary capabilities:
- **Passive network observer**: Can observe all traffic between clients and server (timing, sizes, connection metadata) but cannot decrypt content.
- **Active network attacker**: Can intercept, modify, drop, replay, delay, or inject messages on the network. Such modifications are detected and rejected by cryptographic authentication.
- **Malicious or compromised server**: Can observe encrypted message metadata (sizes, timing, connection tuples), attempt to drop or reorder messages, or attempt message injection. Cannot decrypt content, forge authenticated messages, or perform undetected modification. If the server drops or modifies messages, clients will detect the tampering (authentication failure) or session disruption, but communication cannot continue without a faithful relay.
- **Retrospective attacker with quantum computer**: An adversary who records traffic today and later obtains a quantum computer must break ML-KEM-1024, HQC-256, and X25519 to recover session keys. Breaking only one or two of these algorithms (e.g., X25519 via Shor's algorithm) is insufficient.
- **Traffic analysis attacker**: An adversary observing encrypted traffic patterns to infer metadata (message frequency, size, conversation structure). Mitigated by padding (§8.1), dummy messages (§12.2), and regular send intervals (§12.1).

#### 17.3.2 Out-of-scope attacks
The protocol does NOT protect against:
- **Endpoint compromise**: If an endpoint is compromised (malware, physical access, OS vulnerability), the adversary can extract keys, plaintext, and metadata directly. Endpoint security is the responsibility of the user.
- **Man-in-the-middle during key exchange**: If the out-of-band fingerprint verification (§7.3) is not performed, or is performed over a channel controlled by the attacker, the adversary can establish separate sessions with each party and relay messages (MITM). Fingerprint verification is REQUIRED to prevent this attack.
- **Compromised cryptographic primitives**: If the core primitives (ML-KEM-1024, HQC-256, X25519, ChaCha20-Poly1305, AES-GCM-SIV, HMAC, HKDF, SHA-512, SHAKE-256) are fundamentally broken, security guarantees may fail. The hybrid and layered construction provides defence-in-depth but does not guarantee security if multiple primitives fail simultaneously. However, HQC-256 must be broken in addition to other failures to compromise message confidentiality (see §17.6).
- **Side-channel attacks**: Timing attacks, power analysis, cache attacks, and other side-channel vectors against implementations are not explicitly mitigated by the protocol specification. Implementations SHOULD use constant-time cryptographic libraries where available.
- **Denial of service**: A malicious server or network attacker can always deny service by dropping connections or messages. Availability is not guaranteed.
- **Social engineering and user errors**: The protocol cannot prevent users from accepting malicious files, sharing keys, verifying fingerprints incorrectly, or using compromised out-of-band channels.

### 17.4 Limitations and caveats
- **Server dependency**: Communication requires a functioning, cooperative server. A malicious or failing server can deny service but cannot break confidentiality or authenticity (assuming cryptographic primitives hold).
- **Metadata exposure**: The server observes connection metadata (IP addresses, connection timing, message timing and sizes, session duration). Implementations SHOULD consider using Tor or VPNs for network-layer anonymity if metadata privacy is critical.
- **Traffic analysis resistance**: While dummy messages and padding significantly increase the difficulty of traffic analysis, they do not provide perfect resistance. Sophisticated adversaries with long-term observation capabilities may still infer some patterns (e.g. distinguishing file transfers from text messages by volume over time, identifying conversation start/end times). Users requiring strong traffic analysis resistance should consider additional operational security measures.
- **Forward secrecy limitations**: Forward secrecy protects past messages if keys are compromised in the future. However, if an adversary compromises an endpoint in real-time, they can capture messages as they are decrypted. Forward secrecy does not protect against active, ongoing compromise.
- **Key verification requirement**: Security against active MITM attacks is CONDITIONAL on users performing the fingerprint verification step correctly. If users skip verification or perform it incorrectly, the protocol degrades to server-trust.
- **Implementation vulnerabilities**: This specification describes the protocol; actual security depends on correct, secure implementation. Implementation bugs, weak random number generation, improper key storage, or side-channel leakage can undermine protocol-level security guarantees.
- **Quantum algorithm advances**: While ML-KEM-1024 and HQC-256 are currently believed to be quantum-resistant, unexpected advances in quantum algorithms or cryptanalysis could weaken these assumptions. However, the triple-hybrid construction (§17.6) ensures that ML-KEM-1024, HQC-256, AND X25519 must all be broken simultaneously to compromise session key security. Even if two algorithms are broken, the third provides full protection. Additionally, HQC-256 must be broken to compromise message confidentiality regardless of other algorithm failures.
- **Memory exhaustion attacks**: Despite bounded skipped-message buffers (§8.2), an adversary sending many out-of-order messages can still consume memory and CPU resources. Implementations SHOULD enforce strict rate limits (§11.1) and resource quotas.

### 17.5 Recommended operational security practices
To maximise security under the trust and threat model:
- Perform fingerprint verification (§7.3) for every new session over a trusted, authenticated out-of-band channel
- Use the latest version of the protocol and implementation to benefit from security updates
- Run clients and servers on hardened, up-to-date operating systems
- Consider using Tor or VPNs to protect connection metadata from network observers
- Enable dummy message transmission (§12.2) to hinder traffic analysis
- Regularly rekey sessions (§13) to limit the impact of potential key compromise
- Do not reuse the same server for highly sensitive communications if the server operator is not fully trusted
- Use encrypted, ephemeral storage on endpoints where feasible to reduce forensic exposure
- Implement and enforce rate limits (§11.1) to protect against resource exhaustion

### 17.6 Cryptographic resilience and defence-in-depth
The protocol is designed with layered cryptographic defences such that breaking a single algorithm in each cryptographic layer does NOT compromise security. An adversary must break BOTH algorithms AND HQC in each hybrid construction simultaneously to succeed:

#### 17.6.1 Hybrid key exchange resilience
**Construction**: The session key is derived by combining ML-KEM-1024, HQC-256, and X25519 shared secrets (§7.1). The ML-KEM shared secret serves as HKDF salt, X25519 is mixed via HKDF for session key derivation, and HQC is retained separately to derive per-message OTP keystreams. All three secrets are cryptographically bound in the key derivation process.

**Security property**: To recover session keys and decrypt messages, an adversary must break ALL THREE:
- ML-KEM-1024 (post-quantum KEM), AND
- HQC-256 (post-quantum KEM with OTP layer), AND
- X25519 (classical elliptic curve Diffie-Hellman)

**Attack scenarios**:
- **Quantum computer breaks X25519**: If a quantum adversary (present or future) breaks X25519 using Shor's algorithm, but ML-KEM-1024 and HQC-256 remain secure, the session key cannot be recovered and messages cannot be decrypted. The adversary must still solve both the ML-KEM-1024 and HQC-256 problems, which are believed to be quantum-resistant.
- **Cryptanalytic break of ML-KEM-1024**: If ML-KEM-1024 is broken by unexpected cryptanalytic advances, but X25519 and HQC-256 remain secure, the session key derivation is still protected by X25519, and message content is still protected by the HQC-derived OTP layer. The adversary must break both remaining algorithms.
- **Cryptanalytic break of HQC-256**: If HQC-256 is broken, the OTP layer is compromised, but the adversary must still break ML-KEM-1024 and X25519 to derive session keys and access the AEAD-encrypted ciphertexts. Both AEAD layers remain secure.
- **Two algorithms broken**: If any two of the three algorithms are broken (e.g., X25519 + ML-KEM-1024), the third algorithm still provides full protection. For message confidentiality, HQC-256 provides the OTP layer that protects content even if both ML-KEM-1024 and X25519 are compromised.
- **Partial breaks**: Even if one or two algorithms are weakened (but not fully broken), the unweakened algorithm(s) provide full-strength protection.

**Rationale**: This triple-hybrid construction provides "defence-in-depth" quantum-hedge security. Communications remain secure against future quantum computers breaking X25519 (via two post-quantum KEMs), while also remaining secure if one post-quantum KEM is unexpectedly broken (via the other PQ KEM and classical ECDH). All three must fail for session establishment to be compromised. Additionally, HQC's role in the OTP layer means that even if session key derivation is partially compromised, message confidentiality is preserved as long as HQC remains secure.

#### 17.6.2 Double encryption resilience
**Construction**: Each message is encrypted with a DoubleEncryptor that applies AES-256-GCM-SIV and ChaCha20-Poly1305 sequentially (§8.1). Additionally, an OTP-style XOR layer derived from the HQC-256 shared secret is applied before the AEAD layers. Plaintext is first XORed with a per-message keystream (SHAKE-256 of HQC secret + counter), then encrypted with one AEAD cipher, then encrypted again with the second AEAD cipher. All three layers use independent key material.

**Security property**: To decrypt a message, an adversary must break ALL THREE:
- HQC-256 (for the OTP keystream), AND
- ChaCha20-Poly1305, AND
- AES-256-GCM-SIV

**Attack scenarios**:
- **AES broken**: If AES-256-GCM-SIV is broken (e.g. due to advances in AES cryptanalysis, side-channel attacks on AES hardware, or quantum attacks on AES via Grover's algorithm), the adversary still faces the full security of ChaCha20-Poly1305 and the HQC-derived OTP layer. Two layers of protection remain.
- **ChaCha20 broken**: If ChaCha20-Poly1305 is broken (e.g. cryptanalytic advances), AES-256-GCM-SIV and the HQC OTP layer still protect the message content. Two layers of protection remain.
- **HQC broken**: If HQC-256 is broken and the OTP keystream is recovered, the adversary still faces both AEAD layers (ChaCha20-Poly1305 and AES-256-GCM-SIV). Both must be broken to access plaintext.
- **Two layers broken**: If any two of the three layers are broken (e.g., AES-GCM-SIV + ChaCha20-Poly1305), the third layer still provides full confidentiality and authenticity. If both AEAD layers are broken, the HQC OTP layer preserves confidentiality. If HQC and one AEAD are broken, the remaining AEAD provides full protection.
- **Partial breaks**: If one or two layers are weakened but not completely broken, the unweakened layer(s) still provide full confidentiality and authenticity guarantees.

**Rationale**: This triple-layered encryption (OTP + double AEAD) defends against algorithm-specific attacks 
(cryptanalysis, implementation vulnerabilities, side-channels) and provides diversity in cryptographic design 
(OTP, stream cipher, block cipher, different internal structures). 
An adversary must develop successful attacks against three independent, well-studied cryptographic constructions. 
Additionally, the protocol's nonce-hiding mechanism (§8.1) ensures that the actual nonces used by the AEAD ciphers 
remain secret preventing known-nonce attacks against ChaCha20-Poly1305 and AES-GCM-SIV even if other aspects of the protocol are compromised.

#### 17.6.3 Combined resilience
The protocol's defence-in-depth approach applies at both the key exchange layer and the message encryption layer:
- **Key exchange**: The hybrid construction now combines THREE algorithms: ML-KEM-1024, HQC-256, and X25519. An adversary who breaks one or even two key exchange algorithms still cannot derive session keys.
- **Message encryption**: An adversary who breaks one encryption algorithm still cannot decrypt messages.
- **Triple algorithm requirement**: To compromise content security, an adversary must break at least THREE algorithms in total. HQC-256 MUST always be broken for any successful attack.

**Security degradation scenarios**:
- **Single algorithm break**: No security loss. Communication remains fully secure.
- **Two algorithms broken**:
  - If ML-KEM-1024 and X25519 are both broken, content stays secure (HQC-256 protects the OTP layer).
  - If ML-KEM-1024, X25519, AES-GCM-SIV, and ChaCha20-Poly1305 are all broken, content stays secure (HQC-256 still protects via the OTP layer).
  - An adversary must break at least three algorithms: AES-GCM-SIV + ChaCha20-Poly1305 + HQC-256, OR ML-KEM-1024 + X25519 + HQC-256.
- **HQC-256 requirement**: HQC-256 MUST always be broken to compromise content security, regardless of which other algorithms are broken. This is because:
  - The HQC shared secret drives a per-message OTP-style XOR layer (§8.1) applied to all ciphertexts.
  - Even if both AEAD layers (AES-GCM-SIV and ChaCha20-Poly1305) are broken, the OTP layer derived from HQC provides confidentiality.
  - Even if key exchange is compromised (ML-KEM-1024 and X25519 both broken), the OTP keystream derived from the HQC secret remains secure and protects message content.

**Attack resistance analysis**:
- **Quantum attack + classical cryptanalysis**: If a quantum computer breaks both X25519 and AES-256 (via Grover's algorithm), the adversary still needs to break ML-KEM-1024, ChaCha20-Poly1305, and HQC-256. At minimum, HQC-256 must be broken to access plaintext.
- **Multiple classical breaks**: If cryptanalytic advances break ML-KEM-1024, X25519, and ChaCha20-Poly1305, the adversary still faces AES-256-GCM-SIV and HQC-256. HQC-256 must be broken to decrypt content.
- **AEAD layer compromise**: If both AES-GCM-SIV and ChaCha20-Poly1305 are broken, the OTP layer from HQC-256 preserves confidentiality. To recover plaintext, the adversary must also break at least one key exchange algorithm (to derive the HQC shared secret) or directly break HQC-256 itself.

**Rationale**: The addition of HQC-256 as a third key exchange mechanism with an independent OTP layer significantly strengthens the protocol's defence-in-depth. By requiring HQC-256 to be broken in all attack scenarios, the protocol ensures that even catastrophic multi-algorithm failures (e.g., quantum computers breaking both classical and one post-quantum algorithm) do not compromise message confidentiality. This triple-hybrid construction with mandatory HQC protection provides unprecedented resilience against single-point cryptographic failures.

This multi-layer hybrid approach with three key exchange algorithms and two AEAD layers significantly increases the difficulty for adversaries and provides resilience against single-algorithm failures, unexpected cryptanalytic advances, implementation vulnerabilities, and future quantum computers.

## 18. Security considerations
- Post‑quantum and classical hybridisation reduces the risk of single‑algorithm compromise; combining KEM and DH via HKDF binds secrets and ensures both are required to fail for a full break.
- Padding to 512 bytes and dummy traffic defend against size and timing analysis; these do not eliminate all side channels but increase the cost for an adversary.
- Separate HMAC over counters and per‑message DH public keys reduce the feasibility of CPU‑exhaustion via forged high counters without early rejection.
- Replay protection via counters and ratchet advancement is mandatory; implementations MUST reject stale counters.
- Keys and sensitive state SHOULD be overwritten after use where practical (best‑effort erasure).
- The Double Ratchet mechanism with per-message X25519 ephemeral keys provides forward secrecy: compromise of long-term keys does not expose past messages. Breaking secrecy of message N requires both: (1) the chain key state at counter N, and (2) the ephemeral DH private key for message N.
- Implementations SHOULD limit the skipped counter buffer to prevent memory exhaustion attacks where an adversary sends messages with very high counter values.

## 19. Privacy considerations
- The Server observes only metadata needed to route and maintain liveness (connection timing, message sizes, connection tuples). Payloads are end‑to-end encrypted.
- Server implementations SHOULD minimise operational logs and avoid storing connection metadata (IP addresses, message sizes, timestamps, session durations) beyond immediate operational needs.
- Server implementations MUST NOT log message content, counters, nonces, key exchange material, or any cryptographic state under any circumstances.
- Server implementations SHOULD NOT persist connection logs to disk; in-memory operational state is preferred.
- Both clients and servers SHOULD consider memory-resident operations over persistent storage where feasible to reduce forensic exposure.

## 20. Interoperability notes
- PROTOCOL_VERSION mismatches SHOULD be surfaced as warnings; minor version differences MAY interoperate when message schemas are unchanged.
- File chunk size MAY vary; receivers SHOULD accept any size and write chunks at the indicated index boundaries when SEND_CHUNK_SIZE is known to both parties.

## 21. Implementation notes (non-normative)

### 21.1 Memory management
- Implementations SHOULD overwrite cryptographic key material with zeros before deallocation where possible
- File chunk buffers SHOULD be limited in size; use streaming I/O rather than loading entire files

### 21.2 Error handling
- Cryptographic failures (MAC verification, decryption) SHOULD be indistinguishable to external observers to avoid oracle attacks
- Connection errors during file transfer SHOULD allow resume via partial chunk tracking

### 21.3 Performance considerations
- Dummy traffic generation SHOULD be disabled during large file transfers to conserve bandwidth
- Implementations MAY batch multiple small messages into a single send interval

## 22. Appendix A: Wire examples (non‑normative)
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
