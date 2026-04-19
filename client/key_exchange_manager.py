"""Key exchange manager.

Drives the 16-step hybrid PQC key exchange (ML-KEM + HQC + X25519 + ML-DSA),
interactive key-fingerprint verification, the rekey state machine, and
handles server-issued KEY_EXCHANGE_RESET frames.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from protocol import types

if TYPE_CHECKING:
    from new_client import SecureChatClient


class KeyExchangeManager:
    """Owns initial KE, verification, rekey, and reset handling."""

    def __init__(self, client: "SecureChatClient") -> None:
        self._client = client

    @property
    def _ui(self):
        return self._client.ui

    @property
    def _protocol(self):
        return self._client._protocol

    @property
    def _socket(self):
        return self._client._socket

    @property
    def _file_handler(self):
        return self._client.file_handler

    # initial KE

    def initiate(self) -> None:
        """Step 3: Client A sends KE_DSA_RANDOM (DSA pubkey + random)."""
        msg = self._protocol.create_ke_dsa_random()
        self._protocol.ke_step = 1
        self._client._send_raw(msg)

    def handle_dsa_random(self, message_data: bytes) -> None:
        """Handle receiving KE_DSA_RANDOM from peer."""
        version_warning = self._protocol.process_ke_dsa_random(message_data)
        if version_warning:
            self._ui.display_system_message(f"{version_warning}")

        if self._protocol.ke_step == 0:
            # Client B — receiving Client A's DSA random (step 3), respond with our own (step 6)
            self._protocol.ke_step = 2
            msg = self._protocol.create_ke_dsa_random()
            self._client._send_raw(msg)
        elif self._protocol.ke_step == 1:
            # Client A — receiving Client B's DSA random (step 6), send ML-KEM pubkey (step 8)
            msg = self._protocol.create_ke_mlkem_pubkey()
            self._client._send_raw(msg)

    def handle_mlkem_pubkey(self, message_data: bytes) -> None:
        """Handle KE_MLKEM_PUBKEY (step 8) — only Client B receives this."""
        self._protocol.process_ke_mlkem_pubkey(message_data)
        msg = self._protocol.create_ke_mlkem_ct_keys()
        self._client._send_raw(msg)

    def handle_mlkem_ct_keys(self, message_data: bytes) -> None:
        """Handle KE_MLKEM_CT_KEYS (step 10) — only Client A receives this."""
        self._protocol.process_ke_mlkem_ct_keys(message_data)
        msg = self._protocol.create_ke_x25519_hqc_ct()
        self._client._send_raw(msg)

    def handle_x25519_hqc_ct(self, message_data: bytes) -> None:
        """Handle KE_X25519_HQC_CT (step 13) — only Client B receives this."""
        self._protocol.process_ke_x25519_hqc_ct(message_data)
        msg = self._protocol.create_ke_verification()
        self._client._send_raw(msg)

    def handle_verification(self, message_data: bytes) -> None:
        """Handle receiving KE_VERIFICATION from peer."""
        if self._protocol.ke_step == 1:
            # Client A — receiving Client B's verification (step 15)
            if not self._protocol.process_ke_verification(message_data):
                self._ui.display_error_message("Key exchange verification failed!")
                return
            msg = self._protocol.create_ke_verification()
            self._client._send_raw(msg)
            self._ui.display_system_message("Key exchange completed successfully.")
            self._on_complete()
        elif self._protocol.ke_step == 2:
            # Client B — receiving Client A's verification (step 16)
            if not self._protocol.process_ke_verification(message_data):
                self._ui.display_error_message("Key exchange verification failed!")
                return
            self._ui.display_system_message("Key exchange completed successfully.")
            self._on_complete()

    def _on_complete(self) -> None:
        """Mark KE complete and start key verification."""
        self._client._key_exchange_complete = True
        self._ui.on_key_exchange_complete()
        self.start_verification()

    def start_verification(self) -> None:
        """Initiate key verification — delegates the prompt to the UI."""
        self._client._verification_started = True
        fingerprint = self._protocol.get_own_key_fingerprint()
        verified = self._ui.prompt_key_verification(fingerprint)
        self.confirm_verification(verified)

    def confirm_verification(self, verified: bool) -> None:
        """Record local verification decision, send to peer, start sender thread."""
        self._client._peer_key_verified = verified
        verification_message = self._protocol.create_key_verification_message(verified)
        self._client._send_raw(verification_message)

        self._client._verification_complete = True
        self._protocol.start_sender_thread(self._socket)

    def get_own_key_fingerprint(self) -> str:
        return self._protocol.get_own_key_fingerprint()

    def handle_verification_message(self, message_data: bytes) -> None:
        """Process peer's key verification result and notify UI."""
        try:
            peer_verified = self._protocol.process_key_verification_message(message_data)
        except types.DecodeError as e:
            self._ui.display_error_message(str(e))
            return

        self._client._peer_verified_own_key = peer_verified
        self._ui.on_peer_verified_our_key(peer_verified)

    # rekey

    def initiate_rekey(self) -> None:
        if not self._client.key_exchange_complete:
            self._ui.display_error_message("Cannot rekey - key exchange not complete")
            return
        if self._protocol.rekey_in_progress:
            self._ui.display_system_message("Rekey already in progress.")
            return
        msg = self._protocol.create_rekey_dsa_random(is_initiator=True)
        self._protocol.queue_json(msg)
        self._ui.display_system_message("Rekey initiated.")

    def check_auto_rekey(self) -> None:
        """Trigger a rekey if the protocol's message counter threshold has been reached.

        Skipped when rate-limit bypass is active (file transfer, voice call, etc.) or
        when a file transfer is in progress, to avoid disrupting those flows.
        """
        if not self._protocol.should_auto_rekey:
            return
        if self._client.bypass_rate_limits:
            self._protocol.reset_auto_rekey_counter()
            return
        if self._file_handler.has_active_file_transfers:
            return
        if not self._client.key_exchange_complete:
            return
        msg = self._protocol.create_rekey_dsa_random(is_initiator=True)
        self._protocol.queue_json(msg)
        self._file_handler.clear_orphan_handles()

    def handle_rekey(self, inner: dict[str, Any]) -> None:
        """Drive the four-step rekey handshake (init → response → commit → commit_ack).

        When the peer initiates a rekey over an unverified connection the user is prompted
        before proceeding; declining causes an immediate disconnect.
        """
        try:
            action = inner["action"]
        except KeyError:
            self._ui.display_error_message("Dropped rekey message without action. Invalid JSON.")
            return
        match action:
            case "dsa_random":
                # Peer initiated rekey (or race response). Prompt if peer is unverified and
                # we didn't initiate ourselves.
                if not self._protocol.rekey_in_progress:
                    self._ui.on_rekey_initiated_by_peer()
                    if not self._client.peer_key_verified:
                        proceed = self._ui.prompt_rekey()
                        if proceed is False:
                            self._ui.display_system_message(
                                    "Disconnecting as requested: rekey received from an unverified peer.")
                            self._client.disconnect()
                            return
                        elif proceed is None:
                            return
                    self._ui.display_system_message("Rekey initiated by peer.")
                try:
                    response = self._protocol.process_rekey_dsa_random(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                if response is not None:
                    self._protocol.queue_json(response)

            case "mlkem_pubkey":
                # B receives A's signed ML-KEM pubkey
                try:
                    response = self._protocol.process_rekey_mlkem_pubkey(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                self._protocol.queue_json(response)

            case "mlkem_ct_keys":
                # A receives B's ML-KEM ciphertext + encrypted pubkeys
                try:
                    response = self._protocol.process_rekey_mlkem_ct_keys(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                self._protocol.queue_json(response)  # x25519_hqc_ct
                self._protocol.queue_json(self._protocol.create_rekey_verification())  # A's verification

            case "x25519_hqc_ct":
                # B receives A's X25519 pubkey + encrypted HQC ciphertext; pending keys computed
                try:
                    self._protocol.process_rekey_x25519_hqc_ct(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                # Send verification under old keys, then activate — ensures A can decrypt B's proof.
                # on_rekey_complete deferred until B also verifies A's proof (in "verification" case).
                self._protocol.queue_json_then_switch(self._protocol.create_rekey_verification())

            case "verification":
                # Both A and B arrive here to verify peer's proof.
                # A still has pending keys; B has already activated via queue_json_then_switch.
                # process_rekey_verification falls back to active key material when pending is gone.
                try:
                    ok = self._protocol.process_rekey_verification(inner)
                except ValueError as e:
                    self._protocol.reset_rekey(str(e))
                    return
                if not ok:
                    self._protocol.reset_rekey("Rekey verification failed — possible MitM.")
                    self._ui.display_error_message("Rekey verification failed — possible MitM. Rekey aborted.")
                    return
                # A activates pending keys here; B already activated, so skip.
                if self._protocol.rekey_pending_keys_exist:
                    self._protocol.activate_pending_keys()
                self._ui.on_rekey_complete()

            case _:
                self._ui.display_error_message("Received unknown rekey action")

    # server-issued reset

    def handle_reset(self, message_data: bytes) -> None:
        """Handle KEY_EXCHANGE_RESET from server: tear down current session, prep for fresh KE."""
        message = json.loads(message_data.decode('utf-8'))
        reset_message = message.get("message", "Key exchange reset")

        self._client._key_exchange_complete = False
        self._client._verification_complete = False
        self._client._verification_started = False
        self._client._peer_key_verified = False
        self._client._peer_verified_own_key = False
        self._protocol.reset_key_exchange()
        self._file_handler.clear()

        self._client.peer_nickname = "Other user"

        self._client._file_transfer.clear()

        self._client.end_call(notify_peer=False)

        self._ui.display_system_message("KEY EXCHANGE RESET")
        self._ui.display_system_message(f"Reason: {reset_message}")
        self._ui.display_system_message("The secure session has been terminated.")
        self._ui.display_system_message("Waiting for a new client to connect...")
        self._ui.display_system_message("A new key exchange will start automatically.")
