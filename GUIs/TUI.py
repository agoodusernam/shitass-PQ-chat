"""
Terminal UI (TUI) for the secure chat client.

Implements :class:`UIBase` with simple ``print``/``input`` based interaction.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from client_base import ClientBase
from ui_base import UIBase, UICapability
from protocol.constants import MessageType

class TUI(UIBase):
    """Simple terminal-based UI for the secure chat client."""

    def __init__(self) -> None:
        self.client: ClientBase | None = None

    def set_client(self, client: ClientBase) -> None:
        """Attach the client core so the UI can call back into it."""
        self.client = client

    # -- capabilities ---------------------------------------------------------

    @property
    def capabilities(self) -> UICapability:
        return (
            UICapability.TEXT_MESSAGING
            | UICapability.FILE_TRANSFER
            | UICapability.DEADDROP
            | UICapability.DELIVERY_STATUS
            | UICapability.NICKNAMES
        )

    # -- display --------------------------------------------------------------

    def display_regular_message(self, message: str, nickname: str | None = None) -> None:
        if nickname:
            print(f"\n{nickname}: {message}")
        else:
            print(f"\n{message}")

    def display_error_message(self, message: str) -> None:
        print(f"[ERROR]: {message}")

    def display_system_message(self, message: str) -> None:
        print(f"[SYSTEM]: {message}")

    def display_raw_message(self, message: str) -> None:
        print(message)

    # -- prompts --------------------------------------------------------------

    def prompt_key_verification(self, fingerprint: str) -> bool:
        print("\nSession fingerprint:")
        print("-" * 40)
        print(fingerprint)

        print("\nINSTRUCTIONS:")
        print("1. Compare the fingerprint above with the other person through a")
        print("   secure channel (phone call, in-person, secure messaging)")
        print("2. Both users should see the SAME fingerprint")
        print("3. Only confirm if you both see identical fingerprints!")
        print("4. If the fingerprints don't match, there may be a Man-in-the-Middle attack.")

        while True:
            try:
                response = input("\nDo the fingerprints match? (y/n): ").lower().strip()
                if response in ['yes', 'y']:
                    print("\n✓ Key verification successful!")
                    return True
                if response in ['no', 'n']:
                    print("\nKey verification failed or declined")
                    print("Communication will proceed but may not be secure.")
                    return False
                print("Please enter 'yes', 'y' or 'no', 'n'")
            except (EOFError, KeyboardInterrupt):
                print("\nVerification cancelled. Connection may be insecure.")
                return False

    def prompt_file_transfer(
            self,
            filename: str,
            file_size: int,
            total_chunks: int,
            compressed_file_size: int | None = None,
    ) -> Path | bool | None:
        print("\nIncoming file transfer:")
        print(f"  Filename: {filename}")
        print(f"  Size: {file_size} bytes")
        print(f"  Chunks: {total_chunks}")
        if compressed_file_size is not None:
            print(f"  Compressed size: {compressed_file_size} bytes")

        while True:
            try:
                response = input("Accept file? (y/n): ").lower().strip()
                if response in ['yes', 'y']:
                    print("File transfer accepted. Waiting for file...")
                    return True
                if response in ['no', 'n']:
                    print("File transfer rejected.")
                    return False
                print("Please enter 'yes' or 'no'")
            except (EOFError, KeyboardInterrupt):
                print("File transfer rejected.")
                return False

    def prompt_rekey(self) -> bool | None:
        self.display_system_message("WARNING: Rekey requested by an UNVERIFIED peer.")
        self.display_system_message("Proceeding may expose you to Man-in-the-Middle attacks "
                                    "if this peer is not who you expect.")
        while True:
            try:
                resp = input("Do you want to commence the rekey? (yes = proceed, no = disconnect): ").strip().lower()
                if resp in ("yes", "y"):
                    return True
                if resp in ("no", "n"):
                    return False
                print("Please answer 'yes'/'y' or 'no'/'n'.")
            except (EOFError, KeyboardInterrupt):
                print("\nNo response provided. Defaulting to disconnect.")
                return False

    # -- connection lifecycle -------------------------------------------------

    def on_connected(self) -> None:
        pass  # connect messages are displayed via display_system_message

    def on_graceful_disconnect(self, reason: str) -> None:
        print(f"\n{reason}")

    def on_unexpected_disconnect(self, reason: str) -> None:
        print(f"\n[UNEXPECTED DISCONNECT]: {reason}")

    # -- key exchange UI updates ----------------------------------------------

    def on_key_exchange_complete(self) -> None:
        pass  # verification prompt follows immediately

    # -- voice calls (unsupported in TUI) -------------------------------------

    def on_voice_call_init(self, init_msg: dict[str, Any]) -> None:
        if self.client is not None:
            self.client.protocol.queue_message(("encrypt_json", {"type": MessageType.VOICE_CALL_REJECT}))
        self.display_system_message("Incoming voice call rejected: voice calls not supported on terminal client.")

    # -- file transfer progress -----------------------------------------------

    def file_download_progress(
            self,
            transfer_id: str,
            filename: str,
            received_chunks: int,
            total_chunks: int,
            bytes_transferred: int = -1,
    ) -> None:
        progress = (received_chunks / total_chunks) * 100 if total_chunks else 0
        self.display_system_message(f"Receiving {filename}: {progress:.1f}% ({received_chunks}/{total_chunks} chunks)")

    def file_upload_progress(
            self,
            transfer_id: str,
            filename: str,
            sent_chunks: int,
            total_chunks: int,
            bytes_transferred: int = -1,
            ) -> None:
        progress = (sent_chunks / total_chunks) * 100 if total_chunks else 0
        self.display_system_message(f"Sending {filename}: {progress:.1f}% ({sent_chunks}/{total_chunks} chunks)")
    
    def on_file_transfer_complete(self, transfer_id: str, output_path: str) -> None:
        self.display_system_message(f"File received successfully: {output_path}")

    # -- peer verification notification ---------------------------------------

    def on_peer_verified_our_key(self, verified: bool) -> None:
        pass  # handled via display_system_message in client

    # =========================================================================
    # Main chat loop
    # =========================================================================

    def start_chat(self) -> None:
        """Run the interactive TUI chat loop."""
        if self.client is None:
            print("No client attached.")
            return
        client = self.client

        if not client.connected:
            print("Not connected to server")
            return

        print("Secure Chat Client")
        print("==================")
        print("Commands:")
        print("  /quit - Exit the chat")
        print("  /verify - Start key verification")
        print("  /file <path> - Send a file")
        print("  /deaddrop upload - Upload a file to deaddrop")
        print("  /deaddrop check <name> - Check if a deaddrop exists")
        print("  /deaddrop download <name> - Download a deaddrop file")
        print("  /help - Show this help message")
        print()

        try:
            while client.connected:
                if not (client.key_exchange_complete and client.verification_complete):
                    time.sleep(0.2)
                    continue
                try:
                    message = input()
                    if message.lower() == '/quit':
                        break
                    if message.lower() == '/verify':
                        client.start_key_verification()
                    elif message.lower() == '/rekey':
                        client.initiate_rekey()
                    elif message.lower() == '/help':
                        print("Commands:")
                        print("  /quit - Exit the chat")
                        print("  /verify - Start key verification")
                        print("  /file <path> - Send a file")
                        print("  /deaddrop upload - Upload a file to deaddrop")
                        print("  /deaddrop check <name> - Check if a deaddrop exists")
                        print("  /deaddrop download <name> - Download a deaddrop file")
                        print("  /rekey - Initiate a rekey for fresh session keys")
                        print("  /help - Show this help message")
                    elif message.lower().strip() == '/deaddrop upload':
                        try:
                            name = input("Deaddrop name: ").strip()
                            password = input("Deaddrop password: ")
                            file_path = input("File path: ").strip()
                        except (EOFError, KeyboardInterrupt):
                            print("Deaddrop upload cancelled.")
                            continue
                        if not (name and password and file_path):
                            print("Deaddrop upload aborted: missing fields")
                            continue
                        client.start_deaddrop()
                        if not client.wait_for_deaddrop_handshake(3.0):
                            print("Deaddrop handshake failed.")
                            continue
                        client.deaddrop_upload(name, password, file_path)

                    elif message.lower().startswith('/deaddrop check'):
                        parts = message.split(maxsplit=2)
                        name = parts[2] if len(parts) >= 3 else ""
                        if not name:
                            print("Usage: /deaddrop check <name>")
                            continue

                        if not client.deaddrop_shared_secret:
                            client.start_deaddrop()
                            if not client.wait_for_deaddrop_handshake(3.0):
                                print("Deaddrop handshake failed.")
                                continue

                        client.deaddrop_check(name)

                    elif message.lower().startswith('/deaddrop download'):
                        parts = message.split(maxsplit=2)
                        name = parts[2] if len(parts) >= 3 else ""
                        if not name:
                            print("Usage: /deaddrop download <name>")
                            continue
                        try:
                            password = input("Deaddrop password: ")
                        except (EOFError, KeyboardInterrupt):
                            print("Deaddrop download cancelled.")
                            continue
                        if not password:
                            print("Deaddrop download aborted: missing password")
                            continue
                        client.start_deaddrop()
                        if not client.wait_for_deaddrop_handshake(3.0):
                            print("Deaddrop handshake failed.")
                            continue
                        client.deaddrop_download(name, password)

                    elif message.lower().startswith('/file '):
                        file_path = message[6:].strip()
                        if file_path:
                            client.send_file(file_path)
                        else:
                            print("Usage: /file <path>")
                    elif message.lower().startswith('/nick ') or message.lower().startswith('/nickname '):
                        new_nickname = message[6:].strip()
                        if new_nickname:
                            client.protocol.queue_message(("encrypt_json", {
                                "type":     MessageType.NICKNAME_CHANGE,
                                "nickname": new_nickname,
                            }))
                            print(f"Nickname changed to: {client.peer_nickname}")
                        else:
                            print("Usage: /nick <new_nickname>")

                    elif message.strip():
                        if not client.send_message(message):
                            continue

                        if client.peer_key_verified:
                            print(f"You: {message}")
                        else:
                            print(f"You (unverified): {message}")
                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                else:
                    time.sleep(0.1)

        except Exception as e:
            print(f"Chat error: {e}")
        finally:
            client.disconnect()


def main() -> None:
    """Main function to run the secure chat client with TUI."""
    print("Secure Chat Client")
    print("==================")

    try:
        host = input("Enter server host (default: localhost): ").strip()
        if not host:
            host = 'localhost'
    except EOFError:
        host = 'localhost'
        print("Using default host: localhost")

    try:
        port_input = input("Enter server port (default: 16384): ").strip()
        if port_input:
            try:
                port = int(port_input)
            except ValueError:
                print("Invalid port number, using default 16384")
                port = 16384
        else:
            port = 16384
    except EOFError:
        port = 16384
        print("Using default port: 16384")
    
    from new_client import SecureChatClient # avoid circular imports
    ui = TUI()
    client = SecureChatClient(ui)
    ui.set_client(client)

    if client.connect(host, port):
        try:
            ui.start_chat()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            client.disconnect()
    else:
        print("Failed to connect to server")
        sys.exit(1)


if __name__ == "__main__":
    main()
