"""
Debug GUI Client - Extends the base GUI client with debugging functionality.
"""
import hashlib
import base64
import json
import random
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog

from tkinterdnd2 import TkinterDnD, DND_FILES  # type: ignore

# Import base classes
from gui_client import ChatGUI, GUISecureChatClient, ltk
from shared import PROTOCOL_VERSION, send_message, SecureChatProtocol, MessageType


# noinspection PyBroadException
class DebugProtocol(SecureChatProtocol):
    def __init__(self) -> None:
        super().__init__()
        # Hold last encryption/decryption debug info
        self.last_encrypt_info: dict | None = None
        self.last_decrypt_info: dict | None = None
        self._debug_event_id: int = 0
        self.protocol_version = PROTOCOL_VERSION  # Allow spoofing version in debug
    
    def ratchet_send_key_forward(self, amount: int = 1) -> bool:
        """
        Ratchet the keys forward by one step.
        :param amount: Number of ratchet steps to perform. 0 or negative values do nothing.
        :return: If the keys were successfully ratcheted.
        """
        if amount <= 0:
            return False
        
        try:
            for _ in range(amount):
                # Perform the standard ratchet step (encrypt empty string)
                self.encrypt_message("")
            
            return True
        except ValueError:
            return False
    
    def ratchet_peer_key_forward(self, amount: int = 1) -> bool:
        """
        Ratchet the peer's keys forward by one step.
        :param amount: Number of ratchet steps to perform. 0 or negative values do nothing.
        :return: If the peer's keys were successfully ratcheted.
        """
        if amount <= 0:
            return False
        
        try:
            for _ in range(amount):
                counter = self.peer_counter + 1
                temp_chain_key = self.receive_chain_key
                for i in range(self.peer_counter + 1, counter):
                    temp_chain_key = self._ratchet_chain_key(temp_chain_key, i)
                new_chain_key = self._ratchet_chain_key(temp_chain_key, counter)
                self.receive_chain_key = new_chain_key
                self.peer_counter = counter
            
            return True
        except ValueError:
            return False
    
    # --- Overrides to capture debug info ---
    def encrypt_message(self, plaintext: str) -> bytes:
        # Snapshot state before encrypt
        prev_ck = self.send_chain_key
        try:
            # Call base implementation
            result = super().encrypt_message(plaintext)
        except Exception as e:
            # Still record failure event
            self._debug_event_id += 1
            event_id = self._debug_event_id
            self.last_encrypt_info = {
                "event_id": event_id,
                "ok":       False,
                "error":    str(e),
                "time":     time.time(),
            }
            raise
        
        # After encrypt, gather info
        used_counter = self.message_counter
        try:
            msg = json.loads(result.decode("utf-8"))
            nonce_b64 = msg.get("nonce", "")
            ciphertext_b64 = msg.get("ciphertext", "")
            dh_pub_b64 = msg.get("dh_public_key", "")
        except Exception:
            nonce_b64 = ""
            ciphertext_b64 = ""
            dh_pub_b64 = ""
            msg = {}
        
        # Determine if plaintext looked like control/dummy
        try:
            obj = json.loads(plaintext)
            t = obj.get("type")
            is_control = t is not None
        except Exception:
            is_control = False
        
        # Derive the message key from prev_ck and used counter (matches base logic)
        try:
            mk = self._derive_message_key(prev_ck, used_counter)
            mk_hex = str(base64.b64encode(mk))
        except Exception:
            mk_hex = ""
        
        self._debug_event_id += 1
        event_id = self._debug_event_id
        # Determine plaintext type and sizes
        plaintext_len: int = -1
        plaintext_type: str = "TEXT"
        try:
            plaintext_len = len(plaintext.encode("utf-8"))
            obj = json.loads(plaintext)
            t = obj.get("type")
            plaintext_type = t
            plaintext_type_name = MessageType(t).name if isinstance(t, int) else str(t)
        except Exception:
            plaintext_type_name = "TEXT"
            
        # Determine encrypted envelope details
        encrypted_type = None
        encrypted_type_name = None
        ciphertext_len_b64 = None
        ciphertext_len_bytes = None
        version_in_envelope = None
        try:
            if isinstance(ciphertext_b64, str):
                ciphertext_len_b64 = len(ciphertext_b64)
                try:
                    ciphertext_len_bytes = len(base64.b64decode(ciphertext_b64))
                except Exception:
                    ciphertext_len_bytes = None
            enc_type = msg.get("type")
            version_in_envelope = msg.get("version")
            encrypted_type = enc_type
            try:
                encrypted_type_name = MessageType(enc_type).name if isinstance(enc_type, int) else str(enc_type)
            except Exception:
                encrypted_type_name = str(enc_type)
        except Exception:
            pass
        # Prepare raw representations
        try:
            raw_envelope = result.decode("utf-8")
        except Exception:
            raw_envelope = ""
        try:
            ciphertext_hex = base64.b64decode(ciphertext_b64).hex() if isinstance(ciphertext_b64, str) else ""
        except Exception:
            ciphertext_hex = ""
        # DH context for debug
        try:
            base_peer_dh_b64 = base64.b64encode(self.peer_dh_public_key_bytes).decode('utf-8') if getattr(self, 'peer_dh_public_key_bytes', b'') else ""
        except Exception:
            base_peer_dh_b64 = ""
        self.last_encrypt_info = {
            "event_id":             event_id,
            "ok":                   True,
            "time":                 time.time(),
            "direction":            "send",
            "counter":              used_counter,
            "nonce_b64":            nonce_b64,
            "send_ck_before":       str(base64.b64encode(prev_ck)),
            "send_ck_after":        str(base64.b64encode(self.send_chain_key)),
            "msg_key":              mk_hex,
            "is_control":           is_control,
            # New fields
            "plaintext_type":       plaintext_type,
            "plaintext_type_name":  plaintext_type_name,
            "plaintext_len":        plaintext_len,
            "encrypted_type":       encrypted_type,
            "encrypted_type_name":  encrypted_type_name,
            "ciphertext_len_b64":   ciphertext_len_b64,
            "ciphertext_len_bytes": ciphertext_len_bytes,
            "version":              version_in_envelope,
            # Raw displays
            "raw_envelope":         raw_envelope,
            "ciphertext_b64":       ciphertext_b64,
            "ciphertext_hex":       ciphertext_hex,
            "plaintext":            plaintext,
            # DH (per-message) fields
            "msg_dh_pub_b64":      dh_pub_b64,
            "base_peer_dh_b64":    base_peer_dh_b64,
            "dh_mixed":            True,
        }
        return result
    
    def decrypt_message(self, data: bytes) -> str:
        # Snapshot state before decrypt
        prev_rck = self.receive_chain_key
        prev_peer_ctr = self.peer_counter
        # Capture current base peer DH public (for mixing) before state updates
        try:
            base_peer_dh_b64 = base64.b64encode(self.msg_peer_base_public).decode('utf-8') if getattr(self, 'msg_peer_base_public', b'') else ""
        except Exception:
            base_peer_dh_b64 = ""
        # Parse header for counter/nonce and envelope details
        counter = None
        nonce_b64 = ""
        encrypted_type = None
        encrypted_type_name = None
        ciphertext_len_b64 = None
        ciphertext_len_bytes = None
        version_in_envelope = None
        try:
            msg = json.loads(data.decode("utf-8"))
            counter = msg.get("counter")
            nonce_b64 = msg.get("nonce", "")
            enc_type = msg.get("type")
            version_in_envelope = msg.get("version")
            dh_pub_b64 = msg.get("dh_public_key", "")
            try:
                encrypted_type_name = MessageType(enc_type).name if isinstance(enc_type, int) else str(enc_type)
            except Exception:
                encrypted_type_name = str(enc_type)
            encrypted_type = enc_type
            ct_b64 = msg.get("ciphertext", "")
            if isinstance(ct_b64, str):
                ciphertext_len_b64 = len(ct_b64)
                try:
                    ciphertext_len_bytes = len(base64.b64decode(ct_b64))
                except Exception:
                    ciphertext_len_bytes = None
        except Exception:
            dh_pub_b64 = ""
            pass
        
        # Prepare raw representations
        try:
            raw_envelope = data.decode("utf-8")
        except Exception:
            raw_envelope = ""
        ciphertext_b64_val = ""
        ciphertext_hex_val = ""
        try:
            msg2 = json.loads(raw_envelope) if raw_envelope else {}
            b64 = msg2.get("ciphertext", "")
            if isinstance(b64, str):
                ciphertext_b64_val = b64
                try:
                    ciphertext_hex_val = base64.b64decode(b64).hex()
                except Exception:
                    ciphertext_hex_val = ""
        except Exception:
            pass
        
        # Try to compute the would-be message key (same as base)
        msg_key_hex = ""
        try:
            if counter is not None:
                temp_ck = prev_rck
                for i in range(prev_peer_ctr + 1, counter):
                    temp_ck = self._ratchet_chain_key(temp_ck, i)
                mk = self._derive_message_key(temp_ck, int(counter))
                msg_key_hex = str(base64.b64encode(mk))
        except Exception:
            pass
        
        try:
            plaintext = super().decrypt_message(data)
            ok = True
            err = None
        except Exception as e:
            plaintext = ""
            ok = False
            err = str(e)
        
        # After decrypt, gather info
        self._debug_event_id += 1
        event_id = self._debug_event_id
        # Determine plaintext type and sizes after decryption
        plaintext_len = None
        plaintext_type = None
        plaintext_type_name = None
        if ok:
            try:
                plaintext_len = len(plaintext.encode("utf-8"))
                obj = json.loads(plaintext)
                t = obj.get("type")
                plaintext_type = t
                try:
                    plaintext_type_name = MessageType(t).name if isinstance(t, int) else str(t)
                except Exception:
                    plaintext_type_name = str(t)
            except Exception:
                plaintext_type_name = "TEXT"
        self.last_decrypt_info = {
            "event_id":             event_id,
            "ok":                   ok,
            "error":                err,
            "time":                 time.time(),
            "direction":            "recv",
            "counter":              self.peer_counter if ok else counter,
            "nonce_b64":            nonce_b64,
            "recv_ck_before":       str(base64.b64encode(prev_rck)),
            "recv_ck_after":        str(base64.b64encode(self.receive_chain_key)),
            "msg_key":              msg_key_hex,
            # New fields
            "encrypted_type":       encrypted_type,
            "encrypted_type_name":  encrypted_type_name,
            "ciphertext_len_b64":   ciphertext_len_b64,
            "ciphertext_len_bytes": ciphertext_len_bytes,
            "version":              version_in_envelope,
            "plaintext_type":       plaintext_type,
            "plaintext_type_name":  plaintext_type_name,
            "plaintext_len":        plaintext_len,
            # Raw displays
            "raw_envelope":         raw_envelope,
            "ciphertext_b64":       ciphertext_b64_val,
            "ciphertext_hex":       ciphertext_hex_val,
            "plaintext":            plaintext if ok else "",
            # DH (per-message) fields
            "msg_dh_pub_b64":      dh_pub_b64,
            "base_peer_dh_b64":    base_peer_dh_b64,
            "dh_mixed":            True,
        }
        if ok:
            return plaintext
        raise ValueError(err or "Decryption failed")


# noinspection PyBroadException
class DebugChatGUI(ChatGUI):
    """Debug version of ChatGUI - extends base with debug features."""
    
    def __init__(self, root: TkinterDnD.Tk) -> None:
        # Initialize debug-specific attributes
        self.debug_visible: bool = True  # Show debug panel by default
        self.last_debug_update: int = 0
        self.debug_update_interval: float = 1.0
        # Toggle: attach cryptographic info to messages
        self.attach_crypto_info_to_messages: bool = False
        
        super().__init__(root)
        self.client: DebugGUISecureChatClient = DebugGUISecureChatClient(self)
        self.root.geometry("1400x700")
        
        # Add debug-specific UI elements
        self._setup_debug_ui()
    
    def _setup_debug_ui(self) -> None:
        """Initialize debug-specific UI setup.
        
        This method is called after the parent constructor to set up any
        debug-specific initialization. The actual UI creation happens in
        create_widgets() via _modify_layout_for_debug() and _create_debug_ui().
        """
        # Initialize debug-specific state variables
        self.debug_timer_id = None
        
        # Start periodic debug info updates
        self._start_debug_timer()
    
    def _start_debug_timer(self) -> None:
        """Start the periodic debug info update timer."""
        if self.debug_visible:
            # Schedule the next debug update
            self.debug_timer_id = self.root.after(
                    int(self.debug_update_interval * 1000),  # Convert to milliseconds
                    self._periodic_debug_update
            ) # type: ignore
    
    # noinspection PyBroadException
    def _periodic_debug_update(self) -> None:
        """Periodic callback to update debug information."""
        try:
            # Update debug info if visible and client exists
            if self.debug_visible and self.client:
                self.update_debug_info()
        except Exception:
            # Silently handle errors to prevent timer from stopping
            pass
        finally:
            # Schedule the next update
            self._start_debug_timer()
    
    def _stop_debug_timer(self) -> None:
        """Stop the periodic debug info update timer."""
        if self.debug_timer_id:
            self.root.after_cancel(self.debug_timer_id)
            self.debug_timer_id = None
    
    # noinspection PyAttributeOutsideInit
    def create_widgets(self) -> None:
        """Override create_widgets to create proper side-by-side layout."""
        # Create the main layout with debug panels from the start
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        main_frame.pack(fill=ltk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection frame
        conn_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        conn_frame.pack(fill=ltk.X, pady=(0, 10))
        
        # Host and port inputs
        tk.Label(conn_frame, text="Host:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=ltk.LEFT)
        self.host_entry = tk.Entry(
                conn_frame, width=15, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=ltk.FLAT
        )
        self.host_entry.pack(side=ltk.LEFT, padx=(5, 10))
        self.host_entry.insert(0, "localhost")
        
        tk.Label(conn_frame, text="Port:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=ltk.LEFT)
        self.port_entry = tk.Entry(
                conn_frame, width=8, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=ltk.FLAT
        )
        self.port_entry.pack(side=ltk.LEFT, padx=(5, 10))
        self.port_entry.insert(0, "16384")
        
        # Connect/Disconnect button
        self.connect_btn = tk.Button(
                conn_frame, text="Connect", command=self.toggle_connection,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.connect_btn.pack(side=ltk.LEFT, padx=(10, 0))
        
        # Config menu button
        self.config_btn = tk.Button(
                conn_frame, text="Config", command=self.open_config_dialog,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 10)
        )
        self.config_btn.pack(side=ltk.LEFT, padx=(10, 0))
        
        self.voice_call_btn = tk.Button(
                conn_frame, text="Voice Call", command=self.start_call,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 10)
        )
        
        self.voice_call_btn.pack(side=ltk.LEFT, padx=(10, 0))
        
        # Status indicator (top right)
        self.status_label = tk.Label(
                conn_frame, text="Not Connected",
                bg=self.BG_COLOR, fg="#ff6b6b", font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=ltk.RIGHT, padx=(10, 0))
        
        # Debug toggle button (in connection frame)
        self.debug_toggle_btn = tk.Button(
                conn_frame, text="🔍 Hide Debug Info", command=self.toggle_debug_box,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.debug_toggle_btn.pack(side=ltk.RIGHT, padx=(5, 10))
        
        # Content frame to hold chat and debug side by side
        content_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        content_frame.pack(fill=ltk.BOTH, expand=True, pady=(0, 10))
        
        # Chat frame (left side)
        chat_frame = tk.Frame(content_frame, bg=self.BG_COLOR)
        chat_frame.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=True, padx=(0, 5))
        
        # Chat display area (in chat frame)
        self.chat_display = scrolledtext.ScrolledText(
                chat_frame,
                state=ltk.DISABLED,
                wrap=ltk.WORD,
                height=20,
                font=("Consolas", 10),
                bg=self.TEXT_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR,
                relief=ltk.FLAT
        )
        self.chat_display.pack(fill=ltk.BOTH, expand=True, pady=(0, 10))
        self.chat_display.drop_target_register(DND_FILES)  # type: ignore
        self.chat_display.dnd_bind('<<Drop>>', self.handle_drop)  # type: ignore
        
        # Input frame (in chat frame)
        self.input_frame = tk.Frame(chat_frame, bg=self.BG_COLOR)
        self.input_frame.pack(fill=ltk.X)
        
        # Message input
        self.message_entry = tk.Text(
                self.input_frame, height=1, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR, width=15,
                insertbackground=self.FG_COLOR, relief=ltk.FLAT, wrap=ltk.NONE
        )
        self.message_entry.pack(side=ltk.LEFT, fill=ltk.X, expand=True, padx=(0, 10))
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        self.message_entry.bind("<Control-v>", self.on_paste)
        
        # Ephemeral mode dropdown (OFF, LOCAL, GLOBAL)
        self.ephemeral_mode_var = tk.StringVar(value="OFF")
        self.ephemeral_menu = tk.OptionMenu(
                self.input_frame,
                self.ephemeral_mode_var,
                "OFF", "LOCAL", "GLOBAL",
                command=self.on_ephemeral_change
        )
        self.ephemeral_menu.config(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, activebackground=self.BUTTON_ACTIVE_BG,
                                   activeforeground=self.FG_COLOR, relief=ltk.FLAT)
        self.ephemeral_menu.pack(side=ltk.RIGHT, padx=(0, 5))
        
        # File Transfer window button
        self.file_transfer_btn = tk.Button(
                self.input_frame, text="Transfers", command=self.show_file_transfer_window,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.file_transfer_btn.pack(side=ltk.RIGHT, padx=(0, 10))
        
        # Send File button
        self.send_file_btn = tk.Button(
                self.input_frame, text="Send File", command=self.send_file,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.send_file_btn.pack(side=ltk.RIGHT, padx=(0, 10))
        
        # Send button
        self.send_btn = tk.Button(
                self.input_frame, text="Send", command=self.send_message,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.send_btn.pack(side=ltk.RIGHT)
        
        # Initially disable input until connected
        self.message_entry.config(state=ltk.DISABLED)
        self.send_btn.config(state=ltk.DISABLED)
        self.send_file_btn.config(state=ltk.DISABLED)
        self.ephemeral_menu.config(state=ltk.DISABLED)
        self.file_transfer_btn.config(state=ltk.DISABLED)
        
        # Debug frame (middle, initially visible)
        self.debug_frame = tk.Frame(content_frame, bg=self.BG_COLOR, width=330)
        self.debug_frame.pack_propagate(False)
        self.debug_visible = True
        
        # Debug Actions frame (right side)
        self.debug_actions_frame = tk.Frame(content_frame, bg=self.BG_COLOR, width=300)
        self.debug_actions_frame.pack_propagate(False)
        
        # Pack debug frames to the right
        self.debug_frame.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=False, padx=(5, 5))
        self.debug_actions_frame.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=False, padx=(0, 0))
        
        # Create debug UI elements
        self._create_debug_display()
        self._create_debug_action_buttons()
        
        # Start ephemeral message cleanup thread
        self.start_ephemeral_cleanup()
    
    def _create_debug_display(self) -> None:
        """Create the debug information display area."""
        self.debug_display = scrolledtext.ScrolledText(
                self.debug_frame,
                state=ltk.DISABLED,
                wrap=ltk.WORD,
                height=20,
                font=("Consolas", 8),
                bg="#2d2d2d",
                fg="#00ff00",
                insertbackground="#00ff00",
                relief=ltk.FLAT
        )
        self.debug_display.pack(fill=ltk.BOTH, expand=True, padx=5)
    
    def _create_debug_action_buttons(self) -> None:
        """Create all debug action buttons."""
        # Debug Actions label
        debug_actions_label = tk.Label(
                self.debug_actions_frame,
                text="Debug Actions",
                bg=self.BG_COLOR,
                fg=self.FG_COLOR,
                font=("Consolas", 10, "bold")
        )
        debug_actions_label.pack(fill=ltk.X, padx=5, pady=5)
        
        # Create all debug buttons
        self._create_debug_buttons()
    
    # noinspection PyAttributeOutsideInit
    def _create_debug_buttons(self) -> None:
        """Create individual debug action buttons."""
        # Keepalive toggle button
        self.keepalive_toggle_btn = tk.Button(
                self.debug_actions_frame,
                text="Stop Keepalive Responses",
                command=self.toggle_keepalive_responses,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.keepalive_toggle_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        self.send_keepalive_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Keepalive",
                command=self.force_keepalive,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.send_keepalive_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Delivery confirmation toggle button
        self.delivery_confirmation_toggle_btn = tk.Button(
                self.debug_actions_frame,
                text="Disable Delivery Confirmations",
                command=self.toggle_delivery_confirmations,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.delivery_confirmation_toggle_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Send malformed message button
        self.malformed_msg_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Malformed Message",
                command=self.send_malformed_message,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.malformed_msg_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Set chain keys button
        self.set_chain_keys_btn = tk.Button(
                self.debug_actions_frame,
                text="Set Chain Keys",
                command=self.set_chain_keys,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.set_chain_keys_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Force disconnect button
        self.force_disconnect_btn = tk.Button(
                self.debug_actions_frame,
                text="Force Disconnect",
                command=self.force_disconnect,
                bg=self.BUTTON_BG_COLOR,
                fg="#ff6b6b",
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground="#ff6b6b",
                font=("Consolas", 9, "bold")
        )
        self.force_disconnect_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # View fingerprints button
        self.view_fingerprints_btn = tk.Button(
                self.debug_actions_frame,
                text="View Key Fingerprints",
                command=self.view_key_fingerprints,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.view_fingerprints_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Simulate latency button
        self.simulate_latency_btn = tk.Button(
                self.debug_actions_frame,
                text="Simulate Network Latency",
                command=self.simulate_network_latency,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.simulate_latency_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Export debug log button
        self.export_debug_log_btn = tk.Button(
                self.debug_actions_frame,
                text="Export Debug Log",
                command=self.export_debug_log,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.export_debug_log_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Send stale message button
        self.stale_msg_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Stale Message",
                command=self.send_stale_message,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.stale_msg_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Simulate packet loss button
        self.packet_loss_btn = tk.Button(
                self.debug_actions_frame,
                text="Simulate Packet Loss",
                command=self.simulate_packet_loss,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.packet_loss_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Send duplicate message button
        self.duplicate_msg_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Duplicate Message",
                command=self.send_duplicate_message,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.duplicate_msg_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        # Set message counter button
        self.set_counter_btn = tk.Button(
                self.debug_actions_frame,
                text="Set Message Counter",
                command=self.set_message_counter,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.set_counter_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        self.dummy_message_toggle_btn = tk.Button(
                self.debug_actions_frame,
                text="Dummy messages: ON",
                command=self.toggle_dummy_messages,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.dummy_message_toggle_btn.pack(fill=ltk.X, padx=5, pady=2)
        
        self.ratchet_send_keys_btn = tk.Button(
                self.debug_actions_frame,
                text="Ratchet Send Keys Forward",
                command=self.ratchet_send_key,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.ratchet_send_keys_btn.pack(fill=ltk.X, padx=5, pady=2)
        # Right-click binding for custom ratchet steps (send keys)
        self.ratchet_send_keys_btn.bind("<Button-3>", self.open_send_ratchet_menu)
        
        self.ratchet_peer_keys_btn = tk.Button(
                self.debug_actions_frame,
                text="Ratchet Peer Keys Forward",
                command=self.ratchet_peer_key,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.ratchet_peer_keys_btn.pack(fill=ltk.X, padx=5, pady=2)
        # Right-click binding for custom ratchet steps (peer keys)
        self.ratchet_peer_keys_btn.bind("<Button-3>", self.open_peer_ratchet_menu)
        
        # Toggle: Attach crypto info to messages
        self.crypto_info_toggle_btn = tk.Button(
                self.debug_actions_frame,
                text="Attach Crypto Info: OFF",
                command=self.toggle_crypto_info_in_messages,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.crypto_info_toggle_btn.pack(fill=ltk.X, padx=5, pady=6)
        
        self.view_raw_crypto_btn = tk.Button(
                self.debug_actions_frame,
                text="View Raw Crypto Data",
                command=self.view_raw_crypto_data,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.view_raw_crypto_btn.pack(fill=ltk.X, padx=5, pady=6)
    
    # Debug-specific methods
    def toggle_debug_box(self):
        """Toggle the visibility of the debug information box."""
        if self.debug_visible:
            self.debug_frame.pack_forget()
            self.debug_actions_frame.pack_forget()
            self.debug_toggle_btn.config(text="Show Debug Info")
            self.debug_visible = False
            # Stop the debug timer when hiding
            self._stop_debug_timer()
        else:
            self.debug_frame.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=False, padx=(5, 5))
            self.debug_actions_frame.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=False, padx=(0, 0))
            self.debug_toggle_btn.config(text="Hide Debug Info")
            self.debug_visible = True
            # Start the debug timer when showing
            self._start_debug_timer()
            # Update debug info immediately when showing
            if self.client:
                self.update_debug_info()
    
    def update_debug_info(self):
        """Update the debug information display with current cryptographic state."""
        if not self.debug_visible or self.client is None:
            return
        
        current_time = time.time()
        if current_time - self.last_debug_update < self.debug_update_interval:
            return  # Skip update if interval hasn't passed
        
        self.last_debug_update = current_time  # Update timestamp
        
        try:
            debug_text = "=== CRYPTOGRAPHIC DEBUG INFO ===\n"
            debug_text += f"Timestamp: {time.strftime('%H:%M:%S')}\n\n"
            
            # Protocol Version Information
            debug_text += "PROTOCOL VERSIONS:\n"
            debug_text += f"  Client Version: {PROTOCOL_VERSION}\n"
            
            # Server protocol version (if known)
            if self.client.server_protocol_version is not None:
                debug_text += f"  Server Protocol Version: {self.client.server_protocol_version}\n"
            else:
                debug_text += "  Server Protocol Version: Unknown\n"
            
            if self.client.peer_version != "":
                debug_text += f"  Peer Protocol Version: {self.client.peer_version}\n"
            else:
                debug_text += "  Peer Protocol Version: Unknown\n"
            
            debug_text += "\n"
            
            # Key Exchange Status
            debug_text += "KEY EXCHANGE STATUS:\n"
            
            # Check overall key exchange completion
            if self.client.key_exchange_complete:
                debug_text += "  KEY EXCHANGE COMPLETE\n"
            else:
                debug_text += "  Key Exchange In Progress\n"
            
            # Check verification status
            if self.client.verification_complete:
                debug_text += "  VERIFICATION COMPLETE\n"
            else:
                debug_text += "  Verification Pending\n"
            
            
            if self.client.protocol and self.client.protocol.verification_key:
                debug_text += f"    ✓ Encryption Key: {self.client.protocol.verification_key[:16].hex()}...\n"
            else:
                debug_text += "     ✗ No Encryption Key\n"
            
            # Chain Keys and Counters
            debug_text += "\nCHAIN KEYS & COUNTERS:\n"
            if self.client.protocol and self.client.protocol.send_chain_key:
                debug_text += f"  Send Chain Key: {self.client.protocol.send_chain_key[:16].hex()}...\n"
            else:
                debug_text += "  Send Chain Key: Not initialized\n"
            
            if self.client.protocol and self.client.protocol.receive_chain_key:
                debug_text += f"  Receive Chain Key: {self.client.protocol.receive_chain_key[:16].hex()}...\n"
            else:
                debug_text += "  Receive Chain Key: Not initialized\n"
            
            if self.client.protocol:
                debug_text += f"  Message Counter (Out): {self.client.protocol.message_counter}\n"
            else:
                debug_text += "  Message Counter (Out): 0\n"
            
            if self.client.protocol:
                debug_text += f"  Peer Counter (In): {self.client.protocol.peer_counter}\n"
            else:
                debug_text += "  Peer Counter (In): 0\n"
            
            # Public Keys
            debug_text += "\nPUBLIC KEYS:\n"
            if self.client.protocol and self.client.protocol.mlkem_public_key:
                debug_text += f"  Own Public Key: {self.client.protocol.mlkem_public_key[:16].hex()}...\n"
            else:
                debug_text += "  Own Public Key: Not generated\n"
            
            if self.client.protocol and self.client.protocol.peer_mlkem_public_key:
                debug_text += f"  Peer Public Key: {self.client.protocol.peer_mlkem_public_key[:16].hex()}...\n"
            else:
                debug_text += "  Peer Public Key: Not received\n"
            
            # Key Verification
            debug_text += "\nKEY VERIFICATION:\n"
            if self.client.protocol:
                if self.client.protocol.peer_key_verified:
                    debug_text += "  Peer Key Verified\n"
                else:
                    debug_text += "  Peer Key Not Verified\n"
            else:
                debug_text += "  Verification Status Unknown\n"
            
            # Connection Status
            debug_text += "\nCONNECTION STATUS:\n"
            debug_text += f"  Connected: {'Yes' if self.connected else 'No'}\n"
            if self.client.socket:
                debug_text += "  Socket: Active\n"
            else:
                debug_text += "  Socket: Inactive\n"
            
            # Keepalive Status
            debug_text += "\nKEEPALIVE STATUS:\n"
            last_received = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_received)) if (
                self.client) else None
            if last_received:
                last_received = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_received))
                debug_text += f"  Last Keepalive Received: {last_received}\n"
            else:
                debug_text += "  Last Keepalive Received: None\n"
            
            last_sent = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_sent)) if self.client \
                else None
            if last_sent:
                last_sent = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_sent))
                debug_text += f"  Last Keepalive Sent: {last_sent}\n"
            else:
                debug_text += "  Last Keepalive Sent: None\n"
            
            respond_to_keepalive = self.client.respond_to_keepalive if self.client else None
            if respond_to_keepalive is not None:
                status = "Enabled" if respond_to_keepalive else "Disabled"
                debug_text += f"  Keepalive Responses: {status}\n"
            else:
                debug_text += "  Keepalive Responses: Unknown\n"
            
            dummy_messages_enabled = self.client.protocol.send_dummy_messages
            status = "Enabled" if dummy_messages_enabled else "Disabled"
            debug_text += f"  Dummy Messages: {status}\n"
            
            # DH Handshake (X25519)
            debug_text += "\nDH HANDSHAKE (X25519):\n"
            if self.client.protocol:
                # Own ephemeral/public DH key (from handshake phase)
                if getattr(self.client.protocol, 'dh_public_key_bytes', b''):
                    dh_own = self.client.protocol.dh_public_key_bytes
                    debug_text += f"  Own DH Public: {dh_own[:16].hex()}...\n"
                else:
                    debug_text += "  Own DH Public: Not generated\n"
                # Peer DH public key (from handshake)
                if getattr(self.client.protocol, 'peer_dh_public_key_bytes', b''):
                    dh_peer = self.client.protocol.peer_dh_public_key_bytes
                    debug_text += f"  Peer DH Public: {dh_peer[:16].hex()}...\n"
                else:
                    debug_text += "  Peer DH Public: Not received\n"
                # DH private presence indicator
                has_dh_priv = getattr(self.client.protocol, 'dh_private_key', None) is not None
                debug_text += f"  DH Private Key Present: {'Yes' if has_dh_priv else 'No'}\n"
            else:
                debug_text += "  Protocol not initialized\n"
            
            # Message-phase DH Ratchet state
            debug_text += "\nMESSAGE RATCHET (DH):\n"
            if self.client.protocol:
                has_msg_recv_priv = getattr(self.client.protocol, 'msg_recv_private', None) is not None
                debug_text += f"  Recv DH Private Present: {'Yes' if has_msg_recv_priv else 'No'}\n"
                # Last seen peer per-message DH public key (used for next send base)
                msg_base = getattr(self.client.protocol, 'msg_peer_base_public', b'')
                if msg_base:
                    debug_text += f"  Last Peer per‑msg DH: {msg_base[:16].hex()}...\n"
                else:
                    debug_text += "  Last Peer per‑msg DH: None\n"
            else:
                debug_text += "  Protocol not initialized\n"
            
            debug_text += "\n" + "=" * 44 + "\n"
            
            # Update the debug display
            self.debug_display.config(state=ltk.NORMAL)
            self.debug_display.delete(1.0, tk.END)
            self.debug_display.insert(tk.END, debug_text)
            self.debug_display.see(tk.END)
            self.debug_display.config(state=ltk.DISABLED)
        
        except Exception as e:
            # Fallback debug info if there's an error
            error_text = f"Debug Info Error: {e}\n"
            error_text += f"Client exists: {self.client is not None}\n"
            error_text += f"Connected: {self.connected}\n"
            
            self.debug_display.config(state=ltk.NORMAL)
            self.debug_display.delete(1.0, tk.END)
            self.debug_display.insert(tk.END, error_text)
            self.debug_display.config(state=ltk.DISABLED)
    
    def toggle_keepalive_responses(self):
        """Toggle whether the client responds to keepalive messages."""
        if not self.client:
            return
        
        # Toggle the flag
        self.client.respond_to_keepalive = not self.client.respond_to_keepalive
        
        # Update button text
        if self.client.respond_to_keepalive:
            self.keepalive_toggle_btn.config(
                    text="Stop Keepalive Responses",
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR
            )
            self.append_to_chat("Keepalive responses enabled")
        else:
            self.keepalive_toggle_btn.config(
                    text="Resume Keepalive Responses",
                    bg="#ff6b6b",
                    fg="#ffffff"
            )
            self.append_to_chat("Keepalive responses disabled - server will disconnect after 3 failures")
        
        # Update debug info
        self.update_debug_info()
    
    def force_keepalive(self):
        """Send a keepalive message immediately."""
        if not self.client or not self.client.socket:
            return
        
        try:
            response_message = {
                "type": MessageType.KEEP_ALIVE_RESPONSE
            }
            response_data = json.dumps(response_message).encode('utf-8')
            
            # Send response to server
            send_message(self.client.socket, response_data)
            self.append_to_chat("Sent keepalive message to server")
        except Exception as e:
            self.append_to_chat(f"Error sending keepalive: {e}")
    
    def toggle_delivery_confirmations(self):
        """Toggle whether the client sends delivery confirmations."""
        if not self.client:
            return
        
        # Toggle the flag
        self.client.send_delivery_confirmations = not self.client.send_delivery_confirmations
        
        # Update button text
        if self.client.send_delivery_confirmations:
            self.delivery_confirmation_toggle_btn.config(
                    text="Disable Delivery Confirmations",
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR
            )
            self.append_to_chat("Delivery confirmations enabled")
        else:
            self.delivery_confirmation_toggle_btn.config(
                    text="Enable Delivery Confirmations",
                    bg="#ff6b6b",
                    fg="#ffffff"
            )
            self.append_to_chat("Delivery confirmations disabled")
        
        # Update debug info
        self.update_debug_info()
    
    def toggle_crypto_info_in_messages(self):
        """Toggle attaching cryptographic info to sent/received messages."""
        try:
            self.attach_crypto_info_to_messages = not self.attach_crypto_info_to_messages
            if self.attach_crypto_info_to_messages:
                self.crypto_info_toggle_btn.config(text="Attach Crypto Info: ON")
                self.append_to_chat("Crypto info attachment enabled")
            else:
                self.crypto_info_toggle_btn.config(text="Attach Crypto Info: OFF")
                self.append_to_chat("Crypto info attachment disabled")
            if self.client:
                self.client.attach_crypto_info_to_messages = self.attach_crypto_info_to_messages
        except Exception as e:
            self.append_to_chat(f"Error toggling crypto info: {e}")
    
    def send_malformed_message(self):
        """Send a malformed message to test error handling."""
        if not self.client or not self.client.socket:
            return
        
        try:
            # Create a malformed message (invalid JSON)
            malformed_message = b'{"type": 3, "counter": 999, "nonce": "invalid", "ciphertext": "invalid"'
            
            # Send directly to socket, bypassing normal message handling
            self.client.protocol.queue_message(("encrypted", malformed_message))
            
            self.append_to_chat("Sent malformed message to server")
        except Exception as e:
            self.append_to_chat(f"Error sending malformed message: {e}")
    
    def set_chain_keys(self):
        """Set custom chain keys for testing."""
        if not self.client or not self.client.protocol:
            return
        
        try:
            # Create a simple dialog to input hex values
            dialog = tk.Toplevel(self.root)
            dialog.title("Set Chain Keys")
            dialog.geometry("500x300")
            dialog.configure(bg=self.BG_COLOR)
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Send chain key input
            tk.Label(dialog, text="Send Chain Key (hex):", bg=self.BG_COLOR,
                     fg=self.FG_COLOR).pack(anchor=ltk.W, padx=10, pady=(10, 0))
            send_key_entry = tk.Entry(dialog, width=50, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            send_key_entry.pack(fill=ltk.X, padx=10, pady=5)
            # Receive chain key input
            tk.Label(dialog, text="Receive Chain Key (hex):", bg=self.BG_COLOR,
                     fg=self.FG_COLOR).pack(anchor=ltk.W, padx=10, pady=(10, 0))
            
            receive_key_entry = tk.Entry(dialog, width=50, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            receive_key_entry.pack(fill=ltk.X, padx=10, pady=5)
            
            # Pre-fill with current values if available
            if self.client.protocol.send_chain_key:
                send_key_entry.insert(0, self.client.protocol.send_chain_key.hex())
            if self.client.protocol.receive_chain_key:
                receive_key_entry.insert(0, self.client.protocol.receive_chain_key.hex())
            
            # Warning label
            warning_label = tk.Label(
                    dialog,
                    text="WARNING: Setting custom chain keys will break the security of the connection.\nOnly use for debugging!",
                    bg=self.BG_COLOR,
                    fg="#ff6b6b",
                    justify=ltk.LEFT
            )
            warning_label.pack(fill=ltk.X, padx=10, pady=10)
            
            def apply_keys():
                try:
                    send_key_hex = send_key_entry.get().strip()
                    receive_key_hex = receive_key_entry.get().strip()
                    
                    if send_key_hex:
                        self.client.protocol.send_chain_key = bytes.fromhex(send_key_hex)
                    if receive_key_hex:
                        self.client.protocol.receive_chain_key = bytes.fromhex(receive_key_hex)
                    
                    self.append_to_chat("Chain keys updated")
                    self.update_debug_info()
                    dialog.destroy()
                except ValueError as err:
                    messagebox.showerror("Error", f"Invalid hex value: {err}")
                except Exception as err:
                    messagebox.showerror("Error", f"Failed to set keys: {err}")
            
            # Buttons
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=ltk.X, padx=10, pady=10)
            
            apply_btn = tk.Button(
                    button_frame, text="Apply", command=apply_keys,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT
            )
            apply_btn.pack(side=ltk.LEFT, padx=(0, 5))
            
            cancel_btn = tk.Button(
                    button_frame, text="Cancel", command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT
            )
            cancel_btn.pack(side=ltk.LEFT)
        
        except Exception as e:
            self.append_to_chat(f"Error opening chain key dialog: {e}")
    
    def force_disconnect(self):
        """Force disconnect without proper cleanup."""
        if not self.client:
            return
        
        try:
            if self.client.socket:
                self.client.socket.close()
            self.connected = False
            self.connect_btn.config(text="Connect")
            self.update_status("Force Disconnected", "#ff6b6b")
            self.append_to_chat("Force disconnected from server")
        except Exception as e:
            self.append_to_chat(f"Error during force disconnect: {e}")
    
    def view_key_fingerprints(self):
        """View key fingerprints in a dialog."""
        if not self.client or not self.client.protocol:
            return
        
        try:
            
            dialog = tk.Toplevel(self.root)
            dialog.title("Key Fingerprints")
            dialog.geometry("600x400")
            dialog.configure(bg=self.BG_COLOR)
            dialog.transient(self.root)
            
            text_area = scrolledtext.ScrolledText(
                    dialog,
                    state=ltk.DISABLED,
                    wrap=ltk.WORD,
                    font=("Consolas", 10),
                    bg="#1e1e1e",
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR,
                    relief=ltk.FLAT
            )
            text_area.pack(fill=ltk.BOTH, expand=True, padx=10, pady=10)
            
            fingerprint_text = "=== KEY FINGERPRINTS ===\n\n"
            
            # Own public key fingerprint
            if self.client.protocol.mlkem_public_key:
                own_fp = hashlib.sha3_256(self.client.protocol.mlkem_public_key).hexdigest()[:32]
                fingerprint_text += f"Own Public Key:\n{own_fp}\n\n"
            else:
                fingerprint_text += "Own Public Key: Not available\n\n"
            
            # Peer public key fingerprint
            if self.client.protocol.peer_mlkem_public_key:
                peer_fp = hashlib.sha3_256(self.client.protocol.peer_mlkem_public_key).hexdigest()[:32]
                fingerprint_text += f"Peer Public Key:\n{peer_fp}\n\n"
            else:
                fingerprint_text += "Peer Public Key: Not available\n\n"
            
            
            text_area.config(state=ltk.NORMAL)
            text_area.insert(tk.END, fingerprint_text)
            text_area.config(state=ltk.DISABLED)
        
        except Exception as e:
            self.append_to_chat(f"Error viewing fingerprints: {e}")
    
    def simulate_network_latency(self):
        """Simulate network latency by delaying message sending."""
        if not self.client:
            return
        
        try:
            dialog = tk.Toplevel(self.root)
            dialog.title("Simulate Network Latency")
            dialog.geometry("400x200")
            dialog.configure(bg=self.BG_COLOR)
            dialog.transient(self.root)
            dialog.grab_set()
            
            tk.Label(dialog, text="Latency (milliseconds):", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(pady=10)
            latency_entry = tk.Entry(dialog, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            latency_entry.pack(pady=5)
            latency_entry.insert(0, "100")
            
            def apply_latency():
                try:
                    latency_ms = int(latency_entry.get())
                    self.client.simulated_latency = latency_ms / 1000.0  # Convert to seconds
                    self.append_to_chat(f"Network latency set to {latency_ms}ms")
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("Error", "Please enter a valid number")
                except Exception as err:
                    messagebox.showerror("Error", f"Failed to set latency: {err}")
            
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(pady=20)
            
            apply_btn = tk.Button(
                    button_frame, text="Apply", command=apply_latency,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT
            )
            apply_btn.pack(side=ltk.LEFT, padx=5)
            
            cancel_btn = tk.Button(
                    button_frame, text="Cancel", command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT
            )
            cancel_btn.pack(side=ltk.LEFT, padx=5)
        
        except Exception as e:
            self.append_to_chat(f"Error opening latency dialog: {e}")
    
    def export_debug_log(self):
        """Export debug information to a file."""
        try:
            
            filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                    title="Export Debug Log"
            )
            
            if filename:
                debug_content = self.debug_display.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(debug_content)
                self.append_to_chat(f"Debug log exported to {filename}")
        except Exception as e:
            self.append_to_chat(f"Error exporting debug log: {e}")
    
    def view_raw_crypto_data(self):
        """Open a window showing the raw encrypted and decrypted data for the last messages."""
        try:
            proto = self.client.protocol if self.client else None
            send_info = getattr(proto, "last_encrypt_info", None)
            recv_info = getattr(proto, "last_decrypt_info", None)
            dialog = tk.Toplevel(self.root)
            dialog.title("Raw Crypto Data")
            dialog.geometry("900x650")
            dialog.configure(bg=self.BG_COLOR)
            dialog.transient(self.root)
            dialog.grab_set()
            text = scrolledtext.ScrolledText(
                dialog,
                state=ltk.NORMAL,
                wrap=ltk.WORD,
                font=("Consolas", 9),
                bg="#1e1e1e",
                fg="#d0d0d0",
                insertbackground="#d0d0d0",
                relief=ltk.FLAT
            )
            text.pack(fill=ltk.BOTH, expand=True, padx=10, pady=10)
            def write_section(title: str, info: dict | None):
                text.insert(tk.END, title + "\n")
                text.insert(tk.END, ("-" * len(title)) + "\n")
                if not info:
                    text.insert(tk.END, "  (no data yet)\n\n")
                    return
                def w(label: str, key: str):
                    val = info.get(key)
                    if val is None or val == "":
                        return
                    if isinstance(val, (dict, list)):
                        try:
                            val_str = json.dumps(val, indent=2)
                        except Exception:
                            val_str = str(val)
                    else:
                        val_str = str(val)
                    text.insert(tk.END, f"{label}: {val_str}\n")
                # Core fields
                w("counter", "counter")
                w("nonce_b64", "nonce_b64")
                w("ciphertext_b64", "ciphertext_b64")
                w("ciphertext_hex", "ciphertext_hex")
                w("raw_envelope", "raw_envelope")
                w("plaintext", "plaintext")
                text.insert(tk.END, "\n")
            write_section("→ Last Sent (outgoing)", send_info)
            write_section("← Last Received (incoming)", recv_info)
            text.config(state=ltk.DISABLED)
        except Exception as e:
            self.append_to_chat(f"Error opening raw crypto view: {e}")
    
    def send_stale_message(self):
        """Send a stale message (with an old counter value) to test replay protection."""
        if not self.client or not self.client.socket:
            return
        
        try:
            # Create a dialog to get the message text
            dialog = tk.Toplevel(self.root)
            dialog.title("Send Stale Message")
            dialog.geometry("400x200")
            dialog.configure(bg=self.BG_COLOR)
            
            # Make dialog modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add a label
            tk.Label(
                    dialog,
                    text="Send Stale Message",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            ).pack(pady=10)
            
            # Message input
            # noinspection DuplicatedCode
            tk.Label(
                    dialog,
                    text="Message:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=ltk.X, padx=20, pady=(10, 5))
            
            message_entry = tk.Entry(
                    dialog,
                    width=40,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=ltk.X, padx=20, pady=(0, 10))
            message_entry.insert(0, "This is a stale message")
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=ltk.X, pady=10)
            
            # Send button
            def send_stale():
                message_text = message_entry.get().strip()
                if not message_text:
                    messagebox.showerror("Error", "Please enter a message")
                    return
                
                # Store the current message counter
                current_counter = self.client.protocol.message_counter
                current_chain_key = self.client.protocol.send_chain_key
                
                # Set the counter to a lower value to make the message stale
                self.client.protocol.message_counter = max(0, current_counter - 10)
                
                # Create the encrypted message
                try:
                    encrypted_data = self.client.protocol.encrypt_message(message_text)
                    
                    # Send the message directly to the socket
                    send_message(self.client.socket, encrypted_data)
                    
                    self.append_to_chat(
                            f"Sent stale message with counter {self.client.protocol.message_counter} (current: {current_counter})")
                    
                    # Restore the original counter
                    self.client.protocol.message_counter = current_counter
                    self.client.protocol.send_chain_key = current_chain_key
                
                except Exception as err:
                    self.append_to_chat(f"Error sending stale message: {err}")
                
                dialog.destroy()
            
            # noinspection DuplicatedCode
            tk.Button(
                    button_frame,
                    text="Send",
                    command=send_stale,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=ltk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=ltk.RIGHT, padx=5)
        
        except Exception as e:
            self.append_to_chat(f"Error creating stale message dialog: {e}")
    
    def simulate_packet_loss(self):
        """Simulate packet loss by randomly dropping messages."""
        if not self.client:
            return
        
        try:
            # Create a dialog to configure packet loss
            dialog = tk.Toplevel(self.root)
            dialog.title("Simulate Packet Loss")
            dialog.geometry("400x200")
            dialog.configure(bg=self.BG_COLOR)
            
            # Make dialog modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add a label
            tk.Label(
                    dialog,
                    text="Simulate Packet Loss",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            ).pack(pady=10)
            
            # Create a frame for the packet loss settings
            loss_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            loss_frame.pack(fill=ltk.BOTH, expand=True, padx=20, pady=10)
            
            # Packet loss percentage slider
            tk.Label(
                    loss_frame,
                    text="Packet Loss Percentage:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=ltk.X, pady=(10, 5))
            
            loss_var = tk.IntVar(value=25)  # Default 25%
            loss_slider = tk.Scale(
                    loss_frame,
                    from_=0,
                    to=100,
                    orient=ltk.HORIZONTAL,
                    variable=loss_var,
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    highlightthickness=0,
                    troughcolor="#2d2d2d"
            )
            loss_slider.pack(fill=ltk.X, pady=(0, 10))
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=ltk.X, pady=10)
            
            # Apply button
            def apply_packet_loss():
                loss_percentage = loss_var.get()
                
                if loss_percentage == 0:
                    # Disable packet loss simulation
                    self.client.packet_loss_percentage = 0
                    self.append_to_chat("Packet loss simulation disabled")
                else:
                    # Store the packet loss percentage in the client
                    self.client.packet_loss_percentage = loss_percentage
                    self.append_to_chat(f"Simulating {loss_percentage}% packet loss for future messages")
                
                # Close the dialog
                dialog.destroy()
            
            tk.Button(
                    button_frame,
                    text="Apply",
                    command=apply_packet_loss,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=ltk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=ltk.RIGHT, padx=5)
        
        except Exception as e:
            self.append_to_chat(f"Error simulating packet loss: {e}")
    
    def send_duplicate_message(self):
        """Send the same message multiple times to test duplicate detection."""
        if not self.client or not self.client.socket:
            return
        
        try:
            # Create a dialog to get the message text and count
            dialog = tk.Toplevel(self.root)
            dialog.title("Send Duplicate Message")
            dialog.geometry("400x250")
            dialog.configure(bg=self.BG_COLOR)
            
            # Make dialog modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add a label
            tk.Label(
                    dialog,
                    text="Send Duplicate Message",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            ).pack(pady=10)
            
            # Message input
            # noinspection DuplicatedCode
            tk.Label(
                    dialog,
                    text="Message:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=ltk.X, padx=20, pady=(10, 5))
            
            message_entry = tk.Entry(
                    dialog,
                    width=40,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=ltk.X, padx=20, pady=(0, 10))
            message_entry.insert(0, "This is a duplicate message")
            
            # Count input
            tk.Label(
                    dialog,
                    text="Number of duplicates:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=ltk.X, padx=20, pady=(10, 5))
            
            count_var = tk.IntVar(value=3)  # Default 3 duplicates
            count_slider = tk.Scale(
                    dialog,
                    from_=2,
                    to=10,
                    orient=ltk.HORIZONTAL,
                    variable=count_var,
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    highlightthickness=0,
                    troughcolor="#2d2d2d"
            )
            count_slider.pack(fill=ltk.X, padx=20, pady=(0, 10))
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=ltk.X, pady=10)
            
            # Send button
            def send_duplicates():
                message_text = message_entry.get().strip()
                count = count_var.get()
                
                if not message_text:
                    messagebox.showerror("Error", "Please enter a message")
                    return
                
                # Create the encrypted message
                try:
                    encrypted_data = self.client.protocol.encrypt_message(message_text)
                    
                    # Send the message multiple times
                    for i in range(count):
                        send_message(self.client.socket, encrypted_data)
                        self.append_to_chat(f"Sent duplicate {i + 1}/{count}: {message_text}")
                
                except Exception as err:
                    self.append_to_chat(f"Error sending duplicate messages: {err}")
                
                dialog.destroy()
            
            # noinspection DuplicatedCode
            tk.Button(
                    button_frame,
                    text="Send",
                    command=send_duplicates,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=ltk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=ltk.RIGHT, padx=5)
        
        except Exception as e:
            self.append_to_chat(f"Error creating duplicate message dialog: {e}")
    
    def set_message_counter(self):
        """Set the message counter to a specific value."""
        if not self.client or not self.client.protocol:
            return
        
        try:
            # Create a dialog to input counter values
            dialog = tk.Toplevel(self.root)
            dialog.title("Set Message Counter")
            dialog.geometry("400x250")
            dialog.configure(bg=self.BG_COLOR)
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Send counter input
            tk.Label(
                    dialog,
                    text="Send Counter:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=ltk.X, padx=20, pady=(20, 5))
            
            # noinspection DuplicatedCode
            send_counter_entry = tk.Entry(
                    dialog,
                    width=20,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            send_counter_entry.pack(fill=ltk.X, padx=20, pady=(0, 10))
            
            # Pre-fill with current value
            send_counter_entry.insert(0, str(self.client.protocol.message_counter))
            
            # Peer counter input
            tk.Label(
                    dialog,
                    text="Peer Counter:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=ltk.X, padx=20, pady=(10, 5))
            
            # noinspection DuplicatedCode
            peer_counter_entry = tk.Entry(
                    dialog,
                    width=20,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            peer_counter_entry.pack(fill=ltk.X, padx=20, pady=(0, 10))
            
            # Pre-fill with current value if available
            peer_counter_entry.insert(0, str(self.client.protocol.peer_counter))
            
            # Warning label
            warning_label = tk.Label(
                    dialog,
                    text="WARNING: Setting custom counters may break message encryption.\nOnly use for debugging!",
                    bg=self.BG_COLOR,
                    fg="#ff6b6b",
                    justify=ltk.LEFT
            )
            warning_label.pack(fill=ltk.X, padx=20, pady=10)
            
            # Buttons frame
            buttons_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            buttons_frame.pack(fill=ltk.X, padx=20, pady=10)
            
            def apply_counters():
                try:
                    # Get values from entries
                    send_counter = int(send_counter_entry.get().strip())
                    peer_counter = int(peer_counter_entry.get().strip())
                    
                    # Set the counters
                    self.client.protocol.message_counter = send_counter
                    self.client.protocol.peer_counter = peer_counter
                    
                    self.append_to_chat(f"Message counters set: send={send_counter}, peer={peer_counter}")
                    self.update_debug_info()
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("Error", "Please enter valid integer values")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to set counters: {e}")
            
            # Apply button
            apply_btn = tk.Button(
                    buttons_frame,
                    text="Apply",
                    command=apply_counters,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            )
            apply_btn.pack(side=ltk.LEFT, padx=5)
            
            # Cancel button
            cancel_btn = tk.Button(
                    buttons_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=ltk.FLAT,
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            )
            cancel_btn.pack(side=ltk.RIGHT, padx=5)
        
        except Exception as err:
            self.append_to_chat(f"Error setting message counters: {err}")
    
    def toggle_dummy_messages(self):
        """Toggle sending of dummy messages for testing."""
        if not self.client:
            return
        
        self.client.protocol.send_dummy_messages = not self.client.protocol.send_dummy_messages
        status = "enabled" if self.client.protocol.send_dummy_messages else "disabled"
        self.append_to_chat(f"Dummy messages {status}")
        self.dummy_message_toggle_btn.config(
                text=f"Dummy Messages: {'ON' if self.client.protocol.send_dummy_messages else 'OFF'}"
        )
    
    def ratchet_send_key(self):
        """Manually ratchet the sending and receiving chain keys."""
        if not self.client or not self.client.protocol:
            return
        
        self.client.protocol.ratchet_send_key_forward()
    
    # --- New context-menu ratcheting helpers ---
    def open_send_ratchet_menu(self, event):
        """Right-click handler to open custom step ratchet dialog for send keys."""
        return self._open_ratchet_dialog('send', event.x_root, event.y_root)
    
    def open_peer_ratchet_menu(self, event):
        """Right-click handler to open custom step ratchet dialog for peer keys."""
        return self._open_ratchet_dialog('peer', event.x_root, event.y_root)
    
    def _open_ratchet_dialog(self, ratchet_type: str, x: int, y: int):
        """Generic small dialog for entering ratchet steps.
        :param ratchet_type: 'send' or 'peer'
        :param x: screen x for dialog placement
        :param y: screen y for dialog placement
        """
        if not self.client or not self.client.protocol:
            return None
        
        dialog = tk.Toplevel(self.root)
        dialog.transient(self.root)
        dialog.title(f"Ratchet {'Send' if ratchet_type == 'send' else 'Peer'} Keys")
        dialog.configure(bg=self.BG_COLOR)
        # Place near cursor
        try:
            dialog.geometry(f"+{x}+{y}")
        except Exception:
            pass
        
        tk.Label(dialog, text=f"Enter number of steps to ratchet {ratchet_type} keys forward:",
                 bg=self.BG_COLOR, fg=self.FG_COLOR, font=("Consolas", 9)).pack(padx=10, pady=(10, 5))
        entry = tk.Entry(dialog, width=10, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                         insertbackground=self.FG_COLOR, relief=ltk.FLAT, justify='center')
        entry.pack(padx=10, pady=(0, 10))
        entry.insert(0, "5")
        entry.focus_set()
        
        status_var = tk.StringVar(value="")
        status_lbl = tk.Label(dialog, textvariable=status_var, bg=self.BG_COLOR, fg="#ff6b6b", font=("Consolas", 8))
        status_lbl.pack(padx=10, pady=(0, 5))
        
        btn_frame = tk.Frame(dialog, bg=self.BG_COLOR)
        btn_frame.pack(fill=ltk.X, padx=10, pady=(0, 10))
        
        def apply():
            try:
                steps_str = entry.get().strip()
                steps = int(steps_str)
                if steps <= 0:
                    raise ValueError
                if ratchet_type == 'send':
                    ok = self.client.protocol.ratchet_send_key_forward(steps)
                else:
                    ok = self.client.protocol.ratchet_peer_key_forward(steps)
                if not ok:
                    raise ValueError("Ratchet operation failed")
                self.append_to_chat(f"Ratchet {ratchet_type} keys forward by {steps} steps")
                self.update_debug_info()
                dialog.destroy()
            except ValueError:
                status_var.set("Enter a positive integer")
            except Exception as e:
                status_var.set(str(e))
        
        def close():
            dialog.destroy()
        
        apply_btn = tk.Button(btn_frame, text="Apply", command=apply,
                              bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                              activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR)
        apply_btn.pack(side=ltk.LEFT, padx=(0, 5))
        cancel_btn = tk.Button(btn_frame, text="Cancel", command=close,
                               bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                               activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR)
        cancel_btn.pack(side=ltk.RIGHT)
        
        def on_enter(_event):
            apply()
        
        entry.bind('<Return>', on_enter)
        dialog.bind('<Escape>', lambda _e: close())
        
        # Prevent interaction with main window until closed (modal-ish)
        dialog.grab_set()
        return 'break'
    
    def ratchet_peer_key(self):
        """Manually ratchet the receiving chain key."""
        if not self.client or not self.client.protocol:
            return
        
        self.client.protocol.ratchet_peer_key_forward()
    
    def connect_to_server(self):
        if self.connected:
            return
        host = self.host_entry.get().strip() or "localhost"
        try:
            port = int(self.port_entry.get().strip() or "16384")
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return
        
        self.append_to_chat(f"Connecting to {host}:{port}...")
        self.update_status("Connecting")
        
        def worker():
            self.client = DebugGUISecureChatClient(self)
            if not self.client.connect(host, port):
                self.on_tk_thread(self.append_to_chat, "Connection failed.")
                self.on_tk_thread(self.update_status, "Not Connected")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def on_closing(self):
        """Handle window closing - override to clean up debug timer."""
        # Stop the debug timer before closing
        self._stop_debug_timer()
        # Call parent cleanup
        super().on_closing()


# noinspection PyBroadException
class DebugGUISecureChatClient(GUISecureChatClient):
    """Debug version of GUISecureChatClient - extends base with debug features."""
    
    def __init__(self, gui: DebugChatGUI):
        super().__init__(gui)
        self.gui: DebugChatGUI = gui
        
        # Protocol version tracking
        self.peer_version: str = ""
        
        # Keepalive tracking
        self.last_keepalive_received: float = 0.0
        self.last_keepalive_sent: float = 0.0
        self.respond_to_keepalive: bool = True
        
        # Delivery confirmation tracking
        self.send_delivery_confirmations = True
        
        # Debug features
        self.simulated_latency: float = 0
        self.packet_loss_percentage: int = 0
        self.protocol: DebugProtocol = DebugProtocol()
        
        # Attach crypto info toggle
        self.attach_crypto_info_to_messages: bool = False
        self._last_outgoing_appended_counter: int = 0
        self._last_incoming_appended_counter: int = 0
    
    @staticmethod
    def _format_crypto_info(info: dict, direction: str) -> str:
        try:
            ctr = info.get("counter")
            nonce = info.get("nonce_b64", "")
            msg_key = info.get("msg_key", "")
            # DH details
            dh_pub_b64 = info.get("msg_dh_pub_b64", "") or ""
            base_peer_dh_b64 = info.get("base_peer_dh_b64", "") or ""
            if direction == "send":
                before = info.get("send_ck_before", "")
                after = info.get("send_ck_after", "")
                header = "→ Crypto (sent)"
                chain = f"- send_chain_key: {before[:16]} -> {after[:16]}"
            else:
                before = info.get("recv_ck_before", "")
                after = info.get("recv_ck_after", "")
                header = "← Crypto (recv)"
                chain = f"- recv_chain_key: {before[:16]} -> {after[:16]}"
            # Prepare type and size lines
            pt_name = info.get("plaintext_type_name") or "TEXT"
            pt_val = info.get("plaintext_type")
            enc_name = info.get("encrypted_type_name") or ""
            enc_val = info.get("encrypted_type")
            pt_len = info.get("plaintext_len")
            ct_len = info.get("ciphertext_len_bytes") or info.get("ciphertext_len")
            types_line = f"   - types: plaintext={pt_name}" + (f"({pt_val})" if pt_val is not None else "")
            if enc_name or enc_val is not None:
                types_line += f", encrypted={enc_name}" + (f"({enc_val})" if enc_val is not None else "")
            sizes_line = ""
            if pt_len is not None or ct_len is not None:
                sizes_line = "   - sizes: "
                if pt_len is not None:
                    sizes_line += f"plaintext={pt_len} B"
                if ct_len is not None:
                    sizes_line += (", " if pt_len is not None else "") + f"ciphertext={ct_len} B"
            dh_lines = []
            if dh_pub_b64:
                dh_lines.append(f"   - dh_pub (per‑msg): {dh_pub_b64[:22]}...")
            if base_peer_dh_b64:
                dh_lines.append(f"   - dh_base_peer: {base_peer_dh_b64[:22]}...")
            parts = [
                "--------------------------------",
                f"   {header}",
                f"   - counter: {ctr}",
                f"   - nonce: {nonce[:16]}..." if nonce else "",
                types_line,
                sizes_line if sizes_line else None,
                f"   {chain}..." if chain else "",
                f"   - message_key: {msg_key[:16]}..." if msg_key else "",
            ] + dh_lines
            # Filter out None/empty entries to keep it clean
            return "\n".join([p for p in parts if p])
        except Exception:
            return ""
    
    def _append_outgoing_crypto_info(self, expected_counter: int, retries: int = 20, delay_ms: int = 100) -> None:
        if not self.gui or not self.attach_crypto_info_to_messages:
            return
        try:
            info = getattr(self.protocol, "last_encrypt_info", None)
            if info and info.get("counter") == expected_counter and not info.get("is_control", False):
                if self._last_outgoing_appended_counter != expected_counter:
                    formatted = self._format_crypto_info(info, "send")
                    if formatted:
                        self.gui.on_tk_thread(self.gui.append_to_chat, formatted, False, False)
                        self._last_outgoing_appended_counter = expected_counter
                return
        except Exception:
            pass
        # Not yet available -> retry
        if retries > 0:
            try:
                self.gui.root.after(delay_ms, self._append_outgoing_crypto_info, expected_counter, retries - 1,
                                    delay_ms)
            except Exception:
                pass
    
    def handle_message(self, message_data: bytes) -> None:
        """Handle incoming messages with GUI updates and debug logging."""
        if self.simulated_latency > 0:
            time.sleep(self.simulated_latency)
        
        if self.packet_loss_percentage > 0:
            if random.randint(1, 100) <= self.packet_loss_percentage:
                self.gui.append_to_chat(f"DEBUG: Packet loss simulated ({self.packet_loss_percentage}%)",
                                        is_message=False)
                return
        
        super().handle_message(message_data)
    
    def handle_encrypted_message(self, message_data: bytes) -> None:
        """Override to append crypto info for received messages after displaying them."""
        # Call the base pipeline to decrypt and display
        super().handle_encrypted_message(message_data)
        # Append crypto info if enabled
        try:
            if not self.gui or not self.attach_crypto_info_to_messages:
                return
            info = getattr(self.protocol, "last_decrypt_info", None)
            if not info:
                return
            ctr = info.get("counter")
            # Ensure we only append once per counter
            if isinstance(ctr, int) and ctr and ctr != self._last_incoming_appended_counter:
                formatted = self._format_crypto_info(info, "recv")
                if formatted:
                    self.gui.on_tk_thread(self.gui.append_to_chat, formatted, False, False)
                    self._last_incoming_appended_counter = ctr
        except Exception:
            pass
    
    def handle_key_exchange_init(self, message_data: bytes):
        """Handle key exchange init - override to extract and store protocol version."""
        try:
            # Extract protocol version from message
            message = json.loads(message_data.decode('utf-8'))
            self.peer_version = message.get("version")
            
            # Debug logging
            self.gui.append_to_chat(f"DEBUG: Key exchange init from peer (version {self.peer_version})",
                                    is_message=False)
            
            # Call parent method to handle the key exchange
            super().handle_key_exchange_init(message_data)
            
            # Update debug info after key exchange init
            self.gui.on_tk_thread(self.gui.update_debug_info)
        
        except Exception as e:
            self.gui.append_to_chat(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes):
        """Handle key exchange response - override to extract and store protocol version."""
        try:
            # Extract protocol version from message
            message = json.loads(message_data.decode('utf-8'))
            self.peer_version = message.get("version")
            
            # Debug logging
            self.gui.append_to_chat(f"DEBUG: Key exchange response from peer (version {self.peer_version})",
                                    is_message=False)
            
            # Call parent method to handle the key exchange
            super().handle_key_exchange_response(message_data)
            
            # Update debug info after key exchange response
            self.gui.on_tk_thread(self.gui.update_debug_info)
        
        except Exception as e:
            self.gui.append_to_chat(f"Key exchange response error: {e}")
    
    def handle_keepalive(self) -> None:
        """Handle keepalive messages from the server with GUI updates."""
        try:
            # Update last keepalive received time
            self.last_keepalive_received = time.time()
            
            # Call parent method to handle the keepalive
            if self.respond_to_keepalive:
                super().handle_keepalive()
                self.last_keepalive_sent = time.time()
            
            # Debug logging
            self.gui.append_to_chat("DEBUG: Keepalive received from server", is_message=False)
            if not self.respond_to_keepalive:
                self.gui.append_to_chat("DEBUG: Keepalive response suppressed", is_message=False)
        
        except Exception as err:
            self.gui.append_to_chat(f"Keepalive error: {err}")
    
    def _send_delivery_confirmation(self, confirmed_counter: int):
        """Send delivery confirmation - override to add debug control."""
        if not self.send_delivery_confirmations:
            return
        if self.packet_loss_percentage > 0:
            if random.randint(1, 100) <= self.packet_loss_percentage:
                self.gui.append_to_chat(f"DEBUG: Packet loss simulated ({self.packet_loss_percentage}%) " +
                                        "for delivery confirmation", is_message=False)
                return
        
        super()._send_delivery_confirmation(confirmed_counter)
    
    def send_message(self, text: str) -> bool:
        """Encrypt and send a chat message with optional simulated latency and packet loss."""
        if not self.socket:
            return False
        
        # Simulate packet loss
        if self.packet_loss_percentage > 0:
            if random.randint(1, 100) <= self.packet_loss_percentage:
                self.gui.append_to_chat("DEBUG: Packet loss simulated " +
                                        f"({self.packet_loss_percentage}%)", is_message=False)
                return False
        
        # Simulate network latency if configured
        if self.simulated_latency > 0:
            time.sleep(self.simulated_latency)
        
        # Compute expected counter for this outgoing message (before queuing)
        expected_counter = self.protocol.message_counter + 1
        
        # Call the parent method to send the message
        result = super().send_message(text)
        
        # Schedule appending crypto info once encryption completes
        if result and self.attach_crypto_info_to_messages and self.gui:
            self.gui.root.after(50, self._append_outgoing_crypto_info, expected_counter) # type: ignore
        
        return result


def main() -> None:
    """Main function to run the GUI chat client."""
    root = TkinterDnD.Tk()
    root.title("Secure Chat Client (DEBUG)")
    
    # Create GUI
    gui: DebugChatGUI = DebugChatGUI(root)
    assert gui
    
    # Start the GUI
    root.mainloop()


if __name__ == "__main__":
    main()
