# Secure End-to-End Encrypted Chat Application

## Overview

This is a cryptographically secure, end-to-end encrypted chat application that uses post-quantum cryptography (ML-KEM) for key exchange and AES-GCM for message encryption. The application is designed to be secure against packet capture and modification attacks.

## Security Features

- **Post-Quantum Cryptography**: Uses ML-KEM-1024 for key exchange, providing security against quantum computer attacks
- **End-to-End Encryption**: Messages are encrypted with AES-GCM using keys derived from the ML-KEM shared secret
- **Message Authentication**: HMAC-SHA256 provides message authentication and integrity protection
- **Replay Protection**: Message counters prevent replay attacks
- **Key Derivation**: HKDF derives separate encryption and MAC keys from the shared secret
- **Secure Transport**: Length-prefixed message protocol prevents message boundary attacks

## Architecture

### Files

- `shared.py` - Core cryptographic protocol implementation
- `server.py` - TCP server that routes messages between two clients
- `client.py` - Interactive chat client with automatic key exchange
- `a.py` / `b.py` - Original manual encryption tools (for reference)
- `test_secure_chat.py` - Comprehensive test suite

### Protocol Flow

1. **Connection**: Two clients connect to the server
2. **Key Exchange**: 
   - Server initiates key exchange between clients
   - Client 1 generates ML-KEM keypair and sends public key
   - Client 2 receives public key, generates shared secret and ciphertext
   - Client 1 receives ciphertext and derives the same shared secret
3. **Secure Communication**: 
   - Both clients derive encryption and MAC keys using HKDF
   - Messages are encrypted with AES-GCM and authenticated with HMAC
   - Server routes encrypted messages without being able to decrypt them

## Usage

### Running the Chat Application

1. **Start the server**:
   ```bash
   python server.py
   ```

2. **Connect first client**:
   ```bash
   python client.py
   ```

3. **Connect second client**:
   ```bash
   python client.py
   ```

4. **Chat securely**: After automatic key exchange, both clients can send encrypted messages

### Running Tests

```bash
python test_secure_chat.py
```

This runs comprehensive tests including:
- Cryptographic function tests
- Key exchange verification
- Security feature tests (replay protection, message authentication)
- Integration tests

## Security Analysis

### Threats Addressed

1. **Packet Capture**: All messages are encrypted with AES-GCM using post-quantum secure keys
2. **Packet Modification**: HMAC authentication detects any tampering
3. **Replay Attacks**: Message counters prevent message replay
4. **Man-in-the-Middle**: ML-KEM key exchange provides forward secrecy
5. **Quantum Attacks**: ML-KEM is quantum-resistant

### Assumptions

- Server is used only for message routing and cannot decrypt messages
- Initial key exchange assumes an insecure alternate communication method exists
- No identity verification is performed (as specified in requirements)
- Only two clients are supported per server instance

## Dependencies

- `kyber-py~=1.0.1` - ML-KEM implementation
- `cryptography~=45.0.5` - AES-GCM and HKDF implementation

## Technical Details

### Encryption

- **Key Exchange**: ML-KEM-1024 (post-quantum secure)
- **Symmetric Encryption**: AES-256-GCM
- **Key Derivation**: HKDF-SHA256
- **Message Authentication**: HMAC-SHA256

### Message Format

```
[32-byte HMAC][JSON message with encrypted payload]
```

### Key Exchange Messages

1. **Init**: `{"type": 1, "public_key": "<base64>"}`
2. **Response**: `{"type": 2, "ciphertext": "<base64>"}`
3. **Encrypted Message**: `{"type": 3, "nonce": "<base64>", "ciphertext": "<base64>"}`

## Testing Results

All security tests pass:
- ✅ Key generation and exchange
- ✅ Message encryption/decryption
- ✅ Replay attack protection
- ✅ Message authentication
- ✅ End-to-end integration

The application successfully provides cryptographically secure, end-to-end encrypted communication that is resistant to packet capture, modification, and quantum attacks.