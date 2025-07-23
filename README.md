# Post-Quantum E2E Encrypted Chat

A cryptographically secure, end-to-end encrypted chat application using post-quantum cryptography (ML-KEM) for key exchange and AES-GCM for symmetric encryption. It is designed to be secure against both classical and quantum adversaries.

## ✨ Features

-   **Quantum-Resistant Key Exchange**: Utilizes ML-KEM-1024 (a NIST PQC standard) to protect against future quantum computer attacks.
-   **End-to-End Encryption**: Messages are encrypted on the client-side using AES-256-GCM. The server only routes encrypted data and cannot read message contents.
-   **Forward Secrecy**: Keys are ephemeral, with a new shared secret generated for each session.
-   **Message Integrity & Authentication**: HMAC-SHA256 ensures that messages cannot be tampered with in transit.
-   **Replay Attack Prevention**: A monotonic message counter prevents attackers from replaying old messages.

## 🚀 Getting Started

### Prerequisites

-   Python 3.9+
-   `pip` for installing dependencies

### Installation

1.  Clone the repository:
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```

2.  Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

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

## 🧪 Running Tests

To verify the cryptographic implementation and protocol security, run the test suite:

```bash
python test_secure_chat.py
```

The tests cover key exchange, encryption/decryption, message authentication, and replay protection.

## 🛠️ Architecture

The application consists of three main components:

-   `server.py`: The central server that listens for client connections and relays encrypted messages between them. It has no knowledge of the encryption keys.
-   `client.py`: The client application that users interact with. It handles the UI, key generation, encryption, and decryption.
-   `shared.py`: A core module containing the cryptographic protocol logic used by both the client and server for message handling and key exchange.

### Protocol Flow

1.  **Connection**: Two clients connect to the server.
2.  **Key Exchange Initiation**: The server instructs the clients to begin the key exchange process.
3.  **ML-KEM Exchange**:
    -   Client A generates an ML-KEM key pair and sends its public key to Client B (via the server).
    -   Client B uses the public key to generate a shared secret and an encapsulated ciphertext, which it sends back to Client A.
    -   Client A decapsulates the ciphertext with its private key to derive the same shared secret.
4.  **Secure Communication**:
    -   Both clients use HKDF to derive encryption and MAC keys from the shared secret.
    -   All subsequent messages are encrypted with AES-GCM and authenticated with HMAC-SHA256 before being sent.

## 🔒 Security Overview

This project is designed to be secure against a range of threats.

| Threat Model                 | Mitigation                                                              |
| ---------------------------- | ----------------------------------------------------------------------- |
| **Eavesdropping**            | AES-256-GCM end-to-end encryption.                                      |
| **Quantum Attack**           | ML-KEM-1024 for key exchange is resistant to quantum algorithms.        |
| **Packet Tampering**         | HMAC-SHA256 detects any modification to messages in transit.            |
| **Replay Attacks**           | A message counter in the authenticated data prevents message replay.    |
| **Man-in-the-Middle (MITM)** | ML-KEM provides forward secrecy. *Note: Assumes an out-of-band method to verify public keys if identity verification is needed.* |

### Cryptographic Details

-   **Key Encapsulation**: ML-KEM-1024
-   **Symmetric Cipher**: AES-256-GCM
-   **Key Derivation**: HKDF with SHA-256
-   **Message Authentication**: HMAC with SHA-256