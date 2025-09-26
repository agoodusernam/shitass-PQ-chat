# Post-Quantum E2E Encrypted Chat

> [!CAUTION]
> **This should NOT be used for anything important.**
>
> This is an educational project and has not been designed to be secure
> against any form of attack. The intended use of this project
> is for learning and experimenting with PQC and end-to-end encryption concepts.

An end-to-end encrypted chat application using post-quantum cryptography (ML-KEM) for key exchange and AES-GCM for symmetric encryption.

## Features

-   **Quantum-Resistant Key Exchange**: Utilizes ML-KEM-1024 (a NIST PQC standard) to protect 
against future quantum computer attacks.
-   **End-to-End Encryption**: Messages are encrypted on the client-side using AES-256-GCM. 
The server only routes encrypted data and cannot read message contents.
-   **Forward Secrecy**: Keys are ephemeral, with a new shared secret generated for each session.
-   **Message Integrity & Authentication**: HMAC-SHA256 ensures that messages cannot be tampered with in transit.
-   **Replay Attack Prevention**: A monotonic message counter prevents attackers from replaying old messages.

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
encrypted messages between them. It has no knowledge of the encryption keys.
-   `gui_client.py`: A user-friendly GUI client built with tkinter (no additional dependencies). 
Features a chat interface with input box at the bottom and message display above.
-   `client.py`: A command-line client application for terminal-based interaction. 
Handles the same cryptographic operations as the GUI client.
-   `shared.py`: A core module containing the cryptographic protocol logic used 
by both clients and server for message handling and key exchange.

### Protocol Flow

[![](https://mermaid.ink/img/pako:eNq9Vttu2zgQ_RWCTwkgp5Z8i4VFAEdRs0ZqN7CyRVsYMFhpYhGVSC1FJXGD_PuOKF-kteNtsEX9YIjkXM6cuZDPNJQRUJfm8HcBIoQrzpaKpXNB8JcxpXnIMyY08WzCcuIlHHAx2j8PyuMA1AOoA8pOTfmyOq_-p1IDkaiEDizPccltzHIgtks8KQSEmkuBZnWRVfKe3bq4CLanREuS15x6ztHjnTeUqcCSR8Z1Tu6lIg4JDcL8JwDixw2siP8UxkwsgYwF15yVaCu1AHF4GAWv9mHxHVYL2EinkOdsCfseXHINAhQqkMmH1o0_adltp0tQOWNcNSm48b8s_M_en6Pptb8YT8d35CQrviU8NL5GpzUgiHYmCzS6p_MToXbcNZZGxHsqznHsf3xT7y58EbIsL5JSJo-ZgmiRQ6hAk0euY1KH38xnA_fMD24_TgOfnGB5xaA0PGmrrnx52kzCgdg3Ng6l4Ap2KHce1hAVf9ikc2RiugLc-lc4R1m9lGhnXWlEyEcSM9TXMdpg6UFDjbKdMPW9JJVsqymUaZaAhmbQ9YJbHBBxjoocrYhuVfyfMPJ7Htaq_nisUcUUExGJeJ4lbGUI5BGeopnERHXPEYxCmrd9aOrd5KVSqouYvi2wxcnDHhhTOyWIN-rtBfEXyuWGZcxMAyB54AwHTFjgfkmjgMSEdJLFUuAWSxILR0ArQwNSWAR0eHZaJ7jey5_82fj92BvdjT9OyUmFCyKXaFXAu3uW5PBqS9dV9xvnbYbt44aPFkavnKqGjYmZcEjVK_LVvEz4D0McF2XucQormb7eSYmU2ca-J9O0EI28HWpkU3Aoh5fbZuguTJWVjozjcmlyNmM6jHESbXfLGnlkKtpMLrXK1kNg5Actp9dvXXuTnetNKv2pN_tye-dfLSZ-EIyuyzElC6FBWdjteMVataFyutNvZhUqfxA174r9mbsZP-Xo-F8R4tQzEZbtaWpktXP5H85_E8HOLyDYfhvB9m8gGERUfVCLLhWPqFs2pkVTUCkrl_S5PJ9TvCJSmFMXPyO8BOZ0Ll5QB19YX6VMN2pKFsuYuqavLVpkEV5X61fddlehT1BeyRp1B8OeMULdZ_pEXccZnnXaw15nOBh2h459fm7RFXVb3UHnzOkOu07b7vfbdq__YtEfxq99hnL9rj0YdDpOf3je7lgUIq6lmlSPS_PGfPkHwpxZ4Q?type=png)](https://mermaid.live/edit#pako:eNq9Vttu2zgQ_RWCTwkgp5Z8i4VFAEdRs0ZqN7CyRVsYMFhpYhGVSC1FJXGD_PuOKF-kteNtsEX9YIjkXM6cuZDPNJQRUJfm8HcBIoQrzpaKpXNB8JcxpXnIMyY08WzCcuIlHHAx2j8PyuMA1AOoA8pOTfmyOq_-p1IDkaiEDizPccltzHIgtks8KQSEmkuBZnWRVfKe3bq4CLanREuS15x6ztHjnTeUqcCSR8Z1Tu6lIg4JDcL8JwDixw2siP8UxkwsgYwF15yVaCu1AHF4GAWv9mHxHVYL2EinkOdsCfseXHINAhQqkMmH1o0_adltp0tQOWNcNSm48b8s_M_en6Pptb8YT8d35CQrviU8NL5GpzUgiHYmCzS6p_MToXbcNZZGxHsqznHsf3xT7y58EbIsL5JSJo-ZgmiRQ6hAk0euY1KH38xnA_fMD24_TgOfnGB5xaA0PGmrrnx52kzCgdg3Ng6l4Ap2KHce1hAVf9ikc2RiugLc-lc4R1m9lGhnXWlEyEcSM9TXMdpg6UFDjbKdMPW9JJVsqymUaZaAhmbQ9YJbHBBxjoocrYhuVfyfMPJ7Htaq_nisUcUUExGJeJ4lbGUI5BGeopnERHXPEYxCmrd9aOrd5KVSqouYvi2wxcnDHhhTOyWIN-rtBfEXyuWGZcxMAyB54AwHTFjgfkmjgMSEdJLFUuAWSxILR0ArQwNSWAR0eHZaJ7jey5_82fj92BvdjT9OyUmFCyKXaFXAu3uW5PBqS9dV9xvnbYbt44aPFkavnKqGjYmZcEjVK_LVvEz4D0McF2XucQormb7eSYmU2ca-J9O0EI28HWpkU3Aoh5fbZuguTJWVjozjcmlyNmM6jHESbXfLGnlkKtpMLrXK1kNg5Actp9dvXXuTnetNKv2pN_tye-dfLSZ-EIyuyzElC6FBWdjteMVataFyutNvZhUqfxA174r9mbsZP-Xo-F8R4tQzEZbtaWpktXP5H85_E8HOLyDYfhvB9m8gGERUfVCLLhWPqFs2pkVTUCkrl_S5PJ9TvCJSmFMXPyO8BOZ0Ll5QB19YX6VMN2pKFsuYuqavLVpkEV5X61fddlehT1BeyRp1B8OeMULdZ_pEXccZnnXaw15nOBh2h459fm7RFXVb3UHnzOkOu07b7vfbdq__YtEfxq99hnL9rj0YdDpOf3je7lgUIq6lmlSPS_PGfPkHwpxZ4Q)
1.  **Connection**: Two clients connect to the server.
2.  **Key Exchange Initiation**: The server instructs the clients to begin the key exchange process.
3.  **ML-KEM Exchange**:
    -   Client A generates an ML-KEM key pair and sends its public key to Client B (via the server).
    -   Client B uses the public key to generate a shared secret and an encapsulated ciphertext, which it sends back to Client A.
    -   Client A decapsulates the ciphertext with its private key to derive the same shared secret.
4.  **Secure Communication**:
    -   Both clients use HKDF to derive encryption and MAC keys from the shared secret.
    -   All subsequent messages are encrypted with AES-GCM and authenticated with HMAC-SHA256 before being sent.

## Security Overview

This project is NOT intended for production use. It is an educational implementation to 
demonstrate concepts in post-quantum cryptography and end-to-end encryption and PQC.


### Cryptographic Details

-   **Key Encapsulation**: ML-KEM-1024
-   **Symmetric Cipher**: AES-256-GCM
-   **Key Derivation**: HKDF with SHA-256
-   **Message Authentication**: HMAC with SHA-256
