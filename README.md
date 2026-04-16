# Post-Quantum E2E Encrypted Chat

> [!CAUTION]
> **This should NOT be used for anything important.**
>
> This is an educational project and has not been designed to be secure
> against any form of side-channel attack. The intended use of this project
> is for learning and experimenting with PQC and end-to-end encryption concepts.

An end-to-end encrypted chat application using post-quantum cryptography (ML-KEM-1024, HQC-256) for key exchange and
double AEAD encryption (AES-256-GCM-SIV + ChaCha20-Poly1305) for message protection.

## Features

- **Quantum-Resistant Key Exchange**: Utilises ML-KEM-1024 and HQC-256 (NIST PQC standards) alongside X25519 to protect
  against future quantum computer attacks through hybrid cryptography.
- **End-to-End Encryption**: Messages are encrypted on the client-side using a double AEAD construction (
  ChaCha20-Poly1305 and AES-256-GCM-SIV) with an additional OTP-style XOR layer derived from the HQC secret.
  The server only routes encrypted data and cannot read message contents.
- **Forward Secrecy**: Per-message ephemeral X25519 keys are mixed into a ratcheting chain, ensuring compromise of
  long-term keys does not expose past messages.
- **Message Integrity & Authentication**: HMAC-SHA-512 and double AEAD authentication ensure messages cannot be tampered
  with in transit.
- **Replay Attack Prevention**: A monotonic message counter with out-of-order delivery support prevents attackers from
  replaying old messages.
- **Traffic Analysis Resistance**: Padding to 512-byte blocks and optional dummy messages obscure message patterns.
- **Rekey Support**: Allows generation of fresh session keys without reconnecting, limiting exposure from potential key
  compromise.
- **Dead Drop File Sharing**: Anonymously upload and download files via the server's dead drop facility without
  revealing the transfer to your peer.
- **Voice Calling**: Optional peer-to-peer voice calls (requires PyAudio).
- **Multiple UI Options**: Choose between a full GUI, a terminal UI (TUI), or a debug GUI at launch.
- **Themes**: Supports dark, light, and high-contrast themes (configured in `config.json`).
- **Spell Checking**: Built-in spell checker in the GUI client.
- **Delivery Receipts**: Optional message delivery confirmation.

## Getting Started

### Prerequisites

- Python 3.9+
- `pip` for installing dependencies

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/agoodusernam/shitass-PQ-chat.git
   cd shitass-PQ-chat
   ```

2. Install the required packages:

   **Client:**
   ```bash
   pip install -r requirements.txt
   ```

   **Server only** (lighter install, no UI dependencies):
   ```bash
   pip install -r requirements_server.txt
   ```

### Configuration

Application settings are stored in `config.json` and managed by `config.py`. Key options include:

| Option                 | Default       | Description                                          |
|------------------------|---------------|------------------------------------------------------|
| `theme`                | `"dark"`      | UI theme (`"dark"`, `"light"`, or `"high_contrast"`) |
| `notification_sound`   | `true`        | Play a sound on new messages                         |
| `system_notifications` | `true`        | Show OS-level notifications                          |
| `auto_display_images`  | `true`        | Automatically render received images inline          |
| `allow_voice_calls`    | `true`        | Enable/disable voice call support                    |
| `allow_file_transfer`  | `true`        | Enable/disable file transfers                        |
| `delivery_receipts`    | `true`        | Send and display delivery confirmations              |
| `send_dummy_packets`   | `true`        | Send dummy packets to obscure traffic patterns       |
| `rekey_interval`       | `480`         | Seconds between automatic rekeys                     |
| `deaddrop_enabled`     | `true`        | Enable the server-side dead drop facility            |
| `deaddrop_max_size`    | `10737418240` | Maximum total dead drop storage in bytes (10 GB)     |

### Running the Application

#### Starting the Server

Start the server first. It will wait for two clients to connect.

```bash
python server.py
```

The server requires only `requirements_server.txt` dependencies and has no UI.

#### Starting the Client

Run the client launcher and pick a UI when prompted:

```bash
python run_client.py
```

Available UIs:

- **GUI** — Full graphical interface built with tkinter. Recommended for most users.
- **TUI** — Simple terminal-based interface using `print`/`input`.
- **debug_GUI** — GUI with additional debug output, useful for development.

The GUI client provides:

- Connection controls (host and port configuration)
- Real-time status updates
- Scrollable chat display with inline image rendering
- Message input with built-in spell checker
- Key verification button for enhanced security
- File transfer support with drag-and-drop
- Dead drop upload/download window
- Voice calling (requires PyAudio)
- Themeable interface

## Testing

To run the test suite:

```bash
pip install pytest
python -m pytest tests/
```

The tests cover client initialisation, message routing, encryption/decryption, key exchange steps, rekeying, rate
limiting, file transfer handling, and replay protection.

## Architecture

The application is split into clearly separated layers:

- `server.py`: The central relay server. Listens for two clients, routes encrypted messages between them, and manages
  the dead drop facility. It has no knowledge of encryption keys and cannot decrypt traffic.
- `run_client.py`: The client launcher. Discovers available UIs in the `UIs/` folder and lets the user pick one at
  startup.
- `new_client.py`: Core client logic (`SecureChatClient`). Handles all networking, cryptography, protocol state, and
  background operations. Fully UI-agnostic — all user-facing interaction is delegated to a pluggable UI object.
- `UIs/`: Pluggable UI implementations (`GUI.py`, `TUI.py`, `debug_GUI.py`). Each exposes a `run(client_class)` entry
  point.
- `protocol/`: Protocol implementation — message creation/parsing, cryptographic classes, file handling, shared
  key-exchange logic, message types, and constants.
- `SecureChatABCs/`: Abstract base classes (`ClientBase`, `UIBase`, `ProtocolBase`) that define the interface contract
  between layers.
- `utils/`: Utility modules for network I/O, file operations, input validation, and voice call negotiation.
- `config.py`: Unified `ConfigHandler` that manages all static constants and runtime user preferences, persisted to
  `config.json`.

### Protocol Flow (Simplified Overview)

1. **Connection**: Two clients connect to the server.
2. **Key Exchange Initiation**: The server instructs the clients to begin the key exchange process.
3. **Hybrid KEM + DH Exchange**:
    - Client A generates ML-KEM-1024, HQC-256, and X25519 key pairs and sends public keys to Client B (via the server).
    - Client B encapsulates secrets using Client A's ML-KEM and HQC public keys, sends the ciphertexts back along with
      its own public keys.
    - Both clients perform X25519 Diffie-Hellman key exchange.
    - Client A decapsulates the ML-KEM and HQC ciphertexts to derive the same shared secrets.
4. **Key Derivation**:
    - ML-KEM and X25519 shared secrets are combined using HKDF-SHA-512 to derive the session shared secret.
    - HQC shared secret is retained separately for the OTP-style XOR layer.
    - Per-session salts are derived from all six public keys (sorted lexicographically) using SHA-512.
    - Session-specific encryption keys and root chain keys are derived using HKDF with per-session salts.
5. **Fingerprint Verification**: Both clients display a session fingerprint derived from all public key material for
   out-of-band verification.
6. **Secure Communication**:
    - Messages are padded to 512-byte blocks, XORed with a keystream derived from the HQC secret and message counter.
    - The result is encrypted with ChaCha20-Poly1305, then encrypted again with AES-256-GCM-SIV (double AEAD).
    - Per-message X25519 ephemeral keys are mixed into the ratchet chain to provide forward secrecy.
    - HMAC-SHA-512 authenticates message metadata (counters, ephemeral keys).

**Note**: This is a simplified overview. See `docs/SPEC.md` for the complete protocol specification including message
formats, rekeying, file transfer, dead drops, and security considerations.

## Security Overview

This project is NOT intended for production use. It is an educational implementation to
demonstrate concepts in post-quantum cryptography, end-to-end encryption, forward secrecy, and defence-in-depth
cryptographic design.

**Important Security Notes**:

- This Python reference implementation may not provide constant-time guarantees and may be vulnerable to side-channel
  attacks.
- Endpoint security is assumed. Compromised endpoints will leak keys and plaintext.
- The server is trusted to faithfully relay messages but is NOT trusted with confidentiality.
- Out-of-band fingerprint verification (section 7.3 in `docs/SPEC.md`) is REQUIRED to prevent man-in-the-middle attacks.
- Before use in production, a thorough security audit and formal verification of the protocol and implementation is
  necessary.

### Cryptographic Details

- **Key Exchange**: ML-KEM-1024 (Kyber), HQC-256, X25519 (hybrid construction)
- **Symmetric Ciphers**: ChaCha20-Poly1305, AES-256-GCM-SIV (double AEAD)
- **Additional Layer**: OTP-style XOR using SHAKE-256 keystream derived from HQC secret
- **Key Derivation**: HKDF with SHA-512 and SHA-3-512, per-session salts from public keys
- **Message Authentication**: HMAC-SHA-512, AEAD authentication tags
- **Hash Functions**: SHA-512, SHA-3-512, BLAKE2b-256 (file integrity)
- **Forward Secrecy**: Per-message X25519 ephemeral keys mixed into ratchet chain

For detailed security analysis, threat model, and cryptographic resilience properties, see sections 17-18 in
`docs/SPEC.md`.
