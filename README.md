# Post-Quantum E2E Encrypted Chat

> [!CAUTION]
> **This should NOT be used for anything important.**
>
> This is an educational project and has not been designed to be secure
> against any form of side-channel attack. The intended use of this project
> is for learning and experimenting with PQC and end-to-end encryption concepts.

An end-to-end encrypted chat application using post-quantum cryptography (ML-KEM-1024, HQC-256) for key exchange and double AEAD encryption (AES-256-GCM-SIV + ChaCha20-Poly1305) for message protection.

## Features

-   **Quantum-Resistant Key Exchange**: Utilises ML-KEM-1024 and HQC-256 (NIST PQC standards) alongside X25519 to protect against future quantum computer attacks through hybrid cryptography.
-   **End-to-End Encryption**: Messages are encrypted on the client-side using a double AEAD construction (ChaCha20-Poly1305 and AES-256-GCM-SIV) with an additional OTP-style XOR layer derived from the HQC secret.
The server only routes encrypted data and cannot read message contents.
-   **Forward Secrecy**: Per-message ephemeral X25519 keys are mixed into a ratcheting chain, ensuring compromise of long-term keys does not expose past messages.
-   **Message Integrity & Authentication**: HMAC-SHA-512 and double AEAD authentication ensure messages cannot be tampered with in transit.
-   **Replay Attack Prevention**: A monotonic message counter with out-of-order delivery support prevents attackers from replaying old messages.
-   **Traffic Analysis Resistance**: Padding to 512-byte blocks and optional dummy messages obscure message patterns.
-   **Rekey Support**: Allows generation of fresh session keys without reconnecting, limiting exposure from potential key compromise.

## Getting Started

### Prerequisites

-   Python 3.9+
-   `pip` for installing dependencies

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/agoodusernam/shitass-PQ-chat.git
    cd shitass-PQ-chat
    ```

2.  Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

#### Option 1: GUI Client (Recommended)

1.  **Start the server** in a terminal window. It will wait for two clients to connect.
    ```bash
    python server.py
    ```

2.  **Start the GUI clients** - Run this command in two separate terminal windows or double-click the file:
    ```bash
    python gui_client.py
    ```

The GUI client provides a user-friendly interface with:
- Connection controls (host and port configuration)
- Real-time status updates
- Scrollable chat display area
- Message input box at the bottom
- Key verification button for enhanced security
- File transfer support with drag-and-drop
- Optional voice calling (requires PyAudio)

#### Option 2: Command-Line Client

1.  **Start the server** in a terminal window. It will wait for two clients to connect.
    ```bash
    python server.py
    ```

2.  **Start the first client** in a new terminal window.
    ```bash
    python client.py
    ```

3.  **Start the second client** in a third terminal window.
    ```bash
    python client.py
    ```

Once both clients are connected, the key exchange will complete automatically. You can then begin sending secure messages.

## Testing

To verify the cryptographic implementation and protocol security, run the test suite:

```bash
python test_secure_chat.py
```

The tests cover key exchange, encryption/decryption, message authentication, and replay protection.

## Architecture

The application consists of four main components:

-   `server.py`: The central server that listens for client connections and relays 
encrypted messages between them. It has no knowledge of the encryption keys and cannot decrypt traffic.
-   `gui_client.py`: A user-friendly GUI client built with tkinter (no additional dependencies). 
Features a chat interface with input box at the bottom and message display above.
-   `client.py`: A command-line client application for terminal-based interaction. 
Handles the same cryptographic operations as the GUI client.
-   `shared.py`: A core module containing the cryptographic protocol logic used 
by both clients and server for message handling and key exchange.

### Protocol Flow (Simplified Overview)

1.  **Connection**: Two clients connect to the server.
2.  **Key Exchange Initiation**: The server instructs the clients to begin the key exchange process.
3.  **Hybrid KEM + DH Exchange**:
    -   Client A generates ML-KEM-1024, HQC-256, and X25519 key pairs and sends public keys to Client B (via the server).
    -   Client B encapsulates secrets using Client A's ML-KEM and HQC public keys, sends the ciphertexts back along with its own public keys.
    -   Both clients perform X25519 Diffie-Hellman key exchange.
    -   Client A decapsulates the ML-KEM and HQC ciphertexts to derive the same shared secrets.
4.  **Key Derivation**:
    -   ML-KEM and X25519 shared secrets are combined using HKDF-SHA-512 to derive the session shared secret.
    -   HQC shared secret is retained separately for the OTP-style XOR layer.
    -   Per-session salts are derived from all six public keys (sorted lexicographically) using SHA-512.
    -   Session-specific encryption keys and root chain keys are derived using HKDF with per-session salts.
5.  **Fingerprint Verification**: Both clients display a session fingerprint derived from all public key material for out-of-band verification.
6.  **Secure Communication**:
    -   Messages are padded to 512-byte blocks, XORed with a keystream derived from the HQC secret and message counter.
    -   The result is encrypted with ChaCha20-Poly1305, then encrypted again with AES-256-GCM-SIV (double AEAD).
    -   Per-message X25519 ephemeral keys are mixed into the ratchet chain to provide forward secrecy.
    -   HMAC-SHA-512 authenticates message metadata (counters, ephemeral keys).

**Note**: This is a simplified overview. See `SPEC.md` for the complete protocol specification including message formats, rekeying, file transfer, and security considerations.

## Security Overview

This project is NOT intended for production use. It is an educational implementation to 
demonstrate concepts in post-quantum cryptography, end-to-end encryption, forward secrecy, and defence-in-depth cryptographic design.

**Important Security Notes**:
- This Python reference implementation may not provide constant-time guarantees and may be vulnerable to side-channel attacks.
- Endpoint security is assumed. Compromised endpoints will leak keys and plaintext.
- The server is trusted to faithfully relay messages but is NOT trusted with confidentiality.
- Out-of-band fingerprint verification (§7.3 in SPEC.md) is REQUIRED to prevent man-in-the-middle attacks.
- Before use in production, a thorough security audit and formal verification of the protocol and implementation is necessary.

### Cryptographic Details

-   **Key Exchange**: ML-KEM-1024 (Kyber), HQC-256, X25519 (hybrid construction)
-   **Symmetric Ciphers**: ChaCha20-Poly1305, AES-256-GCM-SIV (double AEAD)
-   **Additional Layer**: OTP-style XOR using SHAKE-256 keystream derived from HQC secret
-   **Key Derivation**: HKDF with SHA-512 and SHA-3-512, per-session salts from public keys
-   **Message Authentication**: HMAC-SHA-512, AEAD authentication tags
-   **Hash Functions**: SHA-512, SHA-3-512, BLAKE2b-256 (file integrity)
-   **Forward Secrecy**: Per-message X25519 ephemeral keys mixed into ratchet chain

For detailed security analysis, threat model, and cryptographic resilience properties, see §17-18 in `SPEC.md`.
