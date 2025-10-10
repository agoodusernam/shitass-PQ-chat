# Post-Quantum E2E Encrypted Chat

> [!CAUTION]
> **This should NOT be used for anything important.**
>
> This is an educational project and has not been designed to be secure
> against any form of attack. The intended use of this project
> is for learning and experimenting with PQC and end-to-end encryption concepts.

An end-to-end encrypted chat application using post-quantum cryptography (ML-KEM) for key exchange and AES-GCM for symmetric encryption.

## Features

-   **Quantum-Resistant Key Exchange**: Utilises ML-KEM-1024 (a NIST PQC standard) and X25519 to protect 
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

[![](https://mermaid.ink/img/pako:eNq1V91O4zgUfhUrV1SbMk36A1S7SG0aoIIW1HZGM6tKkUkMsUjtrOMAHcTtXuzlSvuC8yR77CRtStqySLO9qBL7-Px855zPJy-GzwNidI2E_JES5pMBxfcCL-YMwS_GQlKfxphJ5FgIJ8iJKIGXXnV_qranRDwSseWwXTrc37LfVPvusxQ4l5qzTGrMJUEclIIDpmN30U2IE4KsLnI4Y8SXlDMwK9M4k3es-unpdLWLJEdJySnH3ru9tgYyWTDoCVOZoDsukI187VtSOMdjWUidpVGULWozzb1m1G8KEk4TrLiTL-7EO_t8dbXeLEXdNNeu-BFPSIL8VeTZCcKCd-CCh0uyBID9ELN7goaMSorXGrQzgOlwPJwNezPXu3S_ee5X56I3PnermrvonDAiMKyMruqX7qhuNewWeiDLGFPx6634dLoSIHFIFvAYoa92u22dFFKb6Srb85QX6ABMJeCgieL0NqK-B-e8nomC0MsXerWS8xDhhKdgr6LpHWggBRfLW0EDdIFZkIT4gaCDLCr0469_cq9rFR12CYRdMWokXObjOEkjJQh1UI4G_fjzb3QAPRASIcmzNOHgwgMfBAlq-rDDF7GKCqLOltFvuY2D5MHrAzgPXs8LwtpmeW-AMHGnN9fjqVuCtGyy5FC_DG-_tlkbW-AtNG-rkP2e97TnfeW5jnNA1iCtnUNPVIYoFvQR1kuQrVHSh32-uKWMBGtDawGdw5UPuS1QCEljvljGmj9Ac4IOLi4HZzUERYCobo-IfgdnQkwzgZ111OfgZM4MiPEnpG2ht16VFG9orfDOCIsHtYdI0a6gKo6IJJsJ2UiFcz26uXJn7mZL7BDZ2xCtjCu-AEp31C-RxP7AgwxVGRKU4AX8kUTVGrqjEIGAHDKp0S96K6uyDPpfir4ZXJTXayWOUAEPaBJHeFlWqXk5BW5FjxV_dTMoPz94rhLnZ5BLdBJUXktaEvRIMUTqp0JXCtBylAUZh5zBEo4iE5Jej0GB6jsi_cNagX-Z--AKGJ4Nnd5seD3WfQo-kaCLpEjJpzscJWQn2ZWPVlngY4qt3Yr31kxbXVEahRGkHd8DRDvkh9taC90JvnjbMIXJiPO40A6kskjZRraqzJP390J7omkj16_sqVedogmWfkjkelWVxBMWQUHaihwyAuq507rd7tTPnVHpis-z546dybebmTvwRu502jsHmvV5yiQRJpABTFRltq29uf9XiczJCGgid3trcPYqON1ipQj_Q0hAsTokxUO6DpZz9o6V_xtC-ydAaH0MQutnQ_hmAFMjYT7nBjTJJ7WkWjbO1dAdz7zBcOpcj8euM6tWxtur1p1tj2jfgKgmjs2ZvZrsPvYflJwadKFxNTViBtyuFWbDeB6lYRr3MCoZXUUfpgEzzwKrV-NFicwNqeagudGFxwBusbkxZ69wBmb83zlfFMcET-9Do6vZxzTSOIDbPf_uWK0KsEaEo8rA6FqN9pHWYnRfjGf9fmi1OnbT7jRaJ8eNFuwujW7dOjrpHNod67jVOLYbTctuv5rGd23ZPjzptI5OGm37yLIb7WO7YxokoJKLUfYBpL-DXv8FpggyiQ?type=png)](https://mermaid.live/edit#pako:eNq1V91O4zgUfhUrV1SbMk36A1S7SG0aoIIW1HZGM6tKkUkMsUjtrOMAHcTtXuzlSvuC8yR77CRtStqySLO9qBL7-Px855zPJy-GzwNidI2E_JES5pMBxfcCL-YMwS_GQlKfxphJ5FgIJ8iJKIGXXnV_qranRDwSseWwXTrc37LfVPvusxQ4l5qzTGrMJUEclIIDpmN30U2IE4KsLnI4Y8SXlDMwK9M4k3es-unpdLWLJEdJySnH3ru9tgYyWTDoCVOZoDsukI187VtSOMdjWUidpVGULWozzb1m1G8KEk4TrLiTL-7EO_t8dbXeLEXdNNeu-BFPSIL8VeTZCcKCd-CCh0uyBID9ELN7goaMSorXGrQzgOlwPJwNezPXu3S_ee5X56I3PnermrvonDAiMKyMruqX7qhuNewWeiDLGFPx6634dLoSIHFIFvAYoa92u22dFFKb6Srb85QX6ABMJeCgieL0NqK-B-e8nomC0MsXerWS8xDhhKdgr6LpHWggBRfLW0EDdIFZkIT4gaCDLCr0469_cq9rFR12CYRdMWokXObjOEkjJQh1UI4G_fjzb3QAPRASIcmzNOHgwgMfBAlq-rDDF7GKCqLOltFvuY2D5MHrAzgPXs8LwtpmeW-AMHGnN9fjqVuCtGyy5FC_DG-_tlkbW-AtNG-rkP2e97TnfeW5jnNA1iCtnUNPVIYoFvQR1kuQrVHSh32-uKWMBGtDawGdw5UPuS1QCEljvljGmj9Ac4IOLi4HZzUERYCobo-IfgdnQkwzgZ111OfgZM4MiPEnpG2ht16VFG9orfDOCIsHtYdI0a6gKo6IJJsJ2UiFcz26uXJn7mZL7BDZ2xCtjCu-AEp31C-RxP7AgwxVGRKU4AX8kUTVGrqjEIGAHDKp0S96K6uyDPpfir4ZXJTXayWOUAEPaBJHeFlWqXk5BW5FjxV_dTMoPz94rhLnZ5BLdBJUXktaEvRIMUTqp0JXCtBylAUZh5zBEo4iE5Jej0GB6jsi_cNagX-Z--AKGJ4Nnd5seD3WfQo-kaCLpEjJpzscJWQn2ZWPVlngY4qt3Yr31kxbXVEahRGkHd8DRDvkh9taC90JvnjbMIXJiPO40A6kskjZRraqzJP390J7omkj16_sqVedogmWfkjkelWVxBMWQUHaihwyAuq507rd7tTPnVHpis-z546dybebmTvwRu502jsHmvV5yiQRJpABTFRltq29uf9XiczJCGgid3trcPYqON1ipQj_Q0hAsTokxUO6DpZz9o6V_xtC-ydAaH0MQutnQ_hmAFMjYT7nBjTJJ7WkWjbO1dAdz7zBcOpcj8euM6tWxtur1p1tj2jfgKgmjs2ZvZrsPvYflJwadKFxNTViBtyuFWbDeB6lYRr3MCoZXUUfpgEzzwKrV-NFicwNqeagudGFxwBusbkxZ69wBmb83zlfFMcET-9Do6vZxzTSOIDbPf_uWK0KsEaEo8rA6FqN9pHWYnRfjGf9fmi1OnbT7jRaJ8eNFuwujW7dOjrpHNod67jVOLYbTctuv5rGd23ZPjzptI5OGm37yLIb7WO7YxokoJKLUfYBpL-DXv8FpggyiQ)
1.  **Connection**: Two clients connect to the server.
2.  **Key Exchange Initiation**: The server instructs the clients to begin the key exchange process.
3.  **ML-KEM + DH Exchange**:
    -   Client A generates an ML-KEM key pair and sends its public key to Client B (via the server).
    -   Client A also generates an X25519 key pair and sends its public key to Client B.
    -   Client B uses the ML-KEM public key to generate a shared secret and an encapsulated ciphertext, which it sends back to Client A.
    -   Along with the ciphertext, Client B also sends its public key to Client A.
    -   Client A decapsulates the ciphertext with its private key to derive the same shared secret.
4.  **Secure Communication**:
    -   Both clients XOR their X25519 and ML-KEM shared secrets to generate a single shared secret.
    -   The secret combined shared secret is then hashed with SHA3-256 to derive the key for AES-256-GCM.
    -   All subsequent messages are encrypted with AES-GCM and authenticated with HMAC-SHA256 before being sent.

## Security Overview

This project is NOT intended for production use. It is an educational implementation to 
demonstrate concepts in post-quantum cryptography and end-to-end encryption and PQC.


### Cryptographic Details

-   **Key Exchange**: ML-KEM-1024, X25519
-   **Symmetric Cipher**: AES-256-GCM
-   **Key Derivation**: HKDF with SHA-256
-   **Message Authentication**: HMAC with SHA-256
