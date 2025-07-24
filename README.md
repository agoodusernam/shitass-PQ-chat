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

## 🧪 Running Tests

To verify the cryptographic implementation and protocol security, run the test suite:

```bash
python test_secure_chat.py
```

The tests cover key exchange, encryption/decryption, message authentication, and replay protection.

## 🛠️ Architecture

The application consists of four main components:

-   `server.py`: The central server that listens for client connections and relays encrypted messages between them. It has no knowledge of the encryption keys.
-   `gui_client.py`: A user-friendly GUI client built with tkinter (no additional dependencies). Features a chat interface with input box at the bottom and message display above.
-   `client.py`: A command-line client application for terminal-based interaction. Handles the same cryptographic operations as the GUI client.
-   `shared.py`: A core module containing the cryptographic protocol logic used by both clients and server for message handling and key exchange.

### Protocol Flow

[![](https://mermaid.ink/img/pako:eNq9Vt1u2zYUfhVCVzYgp5b8G2EI4ChKZmR2Azsr1iGAwUonNlGJVCnKiRvkKXbbp-uT7JCyY2l2tAYbmovAIs93_s_H82SFIgLLszL4kgMP4YLRpaTJHSf4l1KpWMhSyhXxHUIz4scM8GN0eD_X13OQa5BHwG4JfF7cF_-nQgERCEIDtu965GZFMyCOR3zBOYSKCY5qVZ4W8r7TOjubv9wSJUhWMuq7tdd7ayhTOEseKFMZuReSuCQ0HmY_4CD-uIYNCR7DFeVLIGPOFKPa2wI2Rz98jIIV57D4DJsF7KQTyDK6hEMLHrkCDhIBZPJb6zqYtJy22yUITimT1RRcBx8XwR_-r6PpVbAYT8e3pJHmn2IWGlujZskR9HYmclR6gPmBUDve1pdKxAcQt973Xz7Jd2cBD2ma5bGWyVZUQrTIIJSgyANTK1J2v1rPit-zYH7zfjoPSAPbawVSwaOyy-DzZrUIR2Lf6ThWggvYe7m3sHVRsvWunCMT0wXg0T_Cqc3quUA9204jXDyQFUW8WqEOmhxVVGnbCZWfdVLJSzeFIkljUFANutxwiyMibq1IbUd0i-b_gJHfs7DU9fWxRkWmKI9IxLI0phuTQBbhLaqJTVT3DJ2RmOaXOTT9bupSgMoiZm5zHHGyPnDG9I524o24gyB-R7nMZBkrU3GQrBlFgglzPNdp5BCbkBrpSnA8onFsIwW0UlQguE1AhSfNcoLLs_whmI0vx_7odvx-ShqFXxB5RMkc3t3TOINXR7oMPRyctyl26hXXNkZPs6rJxsQwHKaKNG5A3msuvhTygcpIS0gIN81XNBVMGrOvJqWM665AfpYieX3GYiHSnWVfJEnOKxU9NuKmFVEOn70dHS9M_2lDxrD-NNWcURWukKNeTnX36FB2nCY36ZYeRsG85fb6rSt_sje9K3Iw9Wcfb26Di8UkmM9HV5rARM4VSBt5AB9fu0Q3zT2-Wm8o7EFUfUUO2XhHTJpU_lOEyIcmQj24pns2e5P_YvwnJdj9HxLsvC3Bzk9IMPCoduhMxzO1IZdAFfZ-Rka4MK3Be0X--7e_yI3IVOtLjltZnhCEsExRzAxplN7sZh1-O81b_0lWTDNp6KBkESaOfZ2KGRg6TiVeFgteY5s-si1XVgefbGVpjm-meTkKHbo1sC3qoAGPWkq0MK-7KhtksSIiXXMuFD5T5qZp2dZSssjyNE_aVgIyofrTetIW7iy0nsCd5eHPCN_kO-uOPyMGF94_hUh2MCny5cryDM3aVp5GuD1sl-yXU4kOgfR17JY3dPtGieU9WY-W5zr9E7fbafcGbq99Ouj38HZjeS08Pu13uqcDp-8M-z230322ra_GsHPSdjrucNB3h47THgzbHduCiCkhJ8Wyb3b-578Bkq7h7w?type=png)](https://mermaid.live/edit#pako:eNq9Vt1u2zYUfhVCVzYgp5b8G2EI4ChKZmR2Azsr1iGAwUonNlGJVCnKiRvkKXbbp-uT7JCyY2l2tAYbmovAIs93_s_H82SFIgLLszL4kgMP4YLRpaTJHSf4l1KpWMhSyhXxHUIz4scM8GN0eD_X13OQa5BHwG4JfF7cF_-nQgERCEIDtu965GZFMyCOR3zBOYSKCY5qVZ4W8r7TOjubv9wSJUhWMuq7tdd7ayhTOEseKFMZuReSuCQ0HmY_4CD-uIYNCR7DFeVLIGPOFKPa2wI2Rz98jIIV57D4DJsF7KQTyDK6hEMLHrkCDhIBZPJb6zqYtJy22yUITimT1RRcBx8XwR_-r6PpVbAYT8e3pJHmn2IWGlujZskR9HYmclR6gPmBUDve1pdKxAcQt973Xz7Jd2cBD2ma5bGWyVZUQrTIIJSgyANTK1J2v1rPit-zYH7zfjoPSAPbawVSwaOyy-DzZrUIR2Lf6ThWggvYe7m3sHVRsvWunCMT0wXg0T_Cqc3quUA9204jXDyQFUW8WqEOmhxVVGnbCZWfdVLJSzeFIkljUFANutxwiyMibq1IbUd0i-b_gJHfs7DU9fWxRkWmKI9IxLI0phuTQBbhLaqJTVT3DJ2RmOaXOTT9bupSgMoiZm5zHHGyPnDG9I524o24gyB-R7nMZBkrU3GQrBlFgglzPNdp5BCbkBrpSnA8onFsIwW0UlQguE1AhSfNcoLLs_whmI0vx_7odvx-ShqFXxB5RMkc3t3TOINXR7oMPRyctyl26hXXNkZPs6rJxsQwHKaKNG5A3msuvhTygcpIS0gIN81XNBVMGrOvJqWM665AfpYieX3GYiHSnWVfJEnOKxU9NuKmFVEOn70dHS9M_2lDxrD-NNWcURWukKNeTnX36FB2nCY36ZYeRsG85fb6rSt_sje9K3Iw9Wcfb26Di8UkmM9HV5rARM4VSBt5AB9fu0Q3zT2-Wm8o7EFUfUUO2XhHTJpU_lOEyIcmQj24pns2e5P_YvwnJdj9HxLsvC3Bzk9IMPCoduhMxzO1IZdAFfZ-Rka4MK3Be0X--7e_yI3IVOtLjltZnhCEsExRzAxplN7sZh1-O81b_0lWTDNp6KBkESaOfZ2KGRg6TiVeFgteY5s-si1XVgefbGVpjm-meTkKHbo1sC3qoAGPWkq0MK-7KhtksSIiXXMuFD5T5qZp2dZSssjyNE_aVgIyofrTetIW7iy0nsCd5eHPCN_kO-uOPyMGF94_hUh2MCny5cryDM3aVp5GuD1sl-yXU4kOgfR17JY3dPtGieU9WY-W5zr9E7fbafcGbq99Ouj38HZjeS08Pu13uqcDp-8M-z230322ra_GsHPSdjrucNB3h47THgzbHduCiCkhJ8Wyb3b-578Bkq7h7w)

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

NOTE: Probably don't use this in production without a thorough security review and testing. This is a simplified example for educational purposes and may not cover all edge cases or security considerations.