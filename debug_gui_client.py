"""
Debug GUI Client - Extends the base GUI client with debugging functionality.
"""
import json
import random
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinterdnd2 import TkinterDnD, DND_FILES
import time
import threading
import hashlib

# Import base classes
from gui_client import ChatGUI, GUISecureChatClient, FileTransferWindow
from shared import PROTOCOL_VERSION, send_message


class DebugFileTransferWindow(FileTransferWindow):
    """Debug version of FileTransferWindow - extends base with debug features."""
    pass


# noinspection DuplicatedCode,PyAttributeOutsideInit
class DebugChatGUI(ChatGUI):
    """Debug version of ChatGUI - extends base with debug features."""
    
    def __init__(self, root):
        # Initialize debug-specific attributes
        self.debug_visible = True  # Show debug panel by default
        self.last_debug_update = 0
        self.debug_update_interval = 1.0
        
        # Call parent constructor
        super().__init__(root)
        self.root.geometry("1400x700")
        
        # Add debug-specific UI elements
        self._setup_debug_ui()
    
    def _setup_debug_ui(self):
        """Initialize debug-specific UI setup.
        
        This method is called after the parent constructor to set up any
        debug-specific initialization. The actual UI creation happens in
        create_widgets() via _modify_layout_for_debug() and _create_debug_ui().
        """
        # Initialize debug-specific state variables
        self.debug_timer_id = None
        
        # Start periodic debug info updates
        self._start_debug_timer()
    
    def _start_debug_timer(self):
        """Start the periodic debug info update timer."""
        if self.debug_visible:
            # Schedule the next debug update
            self.debug_timer_id = self.root.after(
                    int(self.debug_update_interval * 1000),  # Convert to milliseconds
                    self._periodic_debug_update
            )
    
    def _periodic_debug_update(self):
        """Periodic callback to update debug information."""
        # noinspection PyBroadException
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
    
    def _stop_debug_timer(self):
        """Stop the periodic debug info update timer."""
        if self.debug_timer_id:
            self.root.after_cancel(self.debug_timer_id)
            self.debug_timer_id = None
    
    def create_widgets(self):
        """Override create_widgets to create proper side-by-side layout."""
        # Create the main layout with debug panels from the start
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10) # type: ignore
        
        # Connection frame
        conn_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        conn_frame.pack(fill=tk.X, pady=(0, 10)) # type: ignore
        
        # Host and port inputs
        tk.Label(conn_frame, text="Host:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=tk.LEFT) # type: ignore
        self.host_entry = tk.Entry(
                conn_frame, width=15, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=tk.FLAT # type: ignore
        )
        self.host_entry.pack(side=tk.LEFT, padx=(5, 10)) # type: ignore
        self.host_entry.insert(0, "localhost")
        
        tk.Label(conn_frame, text="Port:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=tk.LEFT) # type: ignore
        self.port_entry = tk.Entry(
                conn_frame, width=8, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=tk.FLAT # type: ignore
        )
        self.port_entry.pack(side=tk.LEFT, padx=(5, 10)) # type: ignore
        self.port_entry.insert(0, "16384")
        
        # Connect/Disconnect button
        self.connect_btn = tk.Button(
                conn_frame, text="Connect", command=self.toggle_connection,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.connect_btn.pack(side=tk.LEFT, padx=(10, 0)) # type: ignore
        
        # Sound toggle button
        self.sound_btn = tk.Button(
                conn_frame, text="Notif sounds ON", command=self.toggle_sound_notifications,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 10)
        )
        self.sound_btn.pack(side=tk.LEFT, padx=(10, 0)) # type: ignore
        
        # Windows notifications toggle button
        self.windows_notif_btn = tk.Button(
                conn_frame, text="System notifs ON", command=self.toggle_windows_notifications,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 10)
        )
        self.windows_notif_btn.pack(side=tk.LEFT, padx=(10, 0)) # type: ignore
        
        # Status indicator (top right)
        self.status_label = tk.Label(
                conn_frame, text="Not Connected",
                bg=self.BG_COLOR, fg="#ff6b6b", font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0)) # type: ignore
        
        # Debug toggle button (in connection frame)
        self.debug_toggle_btn = tk.Button(
                conn_frame, text="🔍 Hide Debug Info", command=self.toggle_debug_box,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.debug_toggle_btn.pack(side=tk.RIGHT, padx=(5, 10)) # type: ignore
        
        # Content frame to hold chat and debug side by side
        content_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10)) # type: ignore
        
        # Chat frame (left side)
        chat_frame = tk.Frame(content_frame, bg=self.BG_COLOR)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5)) # type: ignore
        
        # Chat display area (in chat frame)
        self.chat_display = scrolledtext.ScrolledText(
                chat_frame,
                state=tk.DISABLED,
                wrap=tk.WORD,
                height=20,
                font=("Consolas", 10),
                bg=self.TEXT_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR,
                relief=tk.FLAT
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10)) # type: ignore
        self.chat_display.drop_target_register(DND_FILES) # type: ignore
        self.chat_display.dnd_bind('<<Drop>>', self.handle_drop) # type: ignore
        
        # Input frame (in chat frame)
        self.input_frame = tk.Frame(chat_frame, bg=self.BG_COLOR)
        self.input_frame.pack(fill=tk.X) # type: ignore
        
        # Message input
        self.message_entry = tk.Text(
                self.input_frame, height=1, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR, width=15,
                insertbackground=self.FG_COLOR, relief=tk.FLAT, wrap=tk.NONE # type: ignore
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10)) # type: ignore
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        self.message_entry.bind("<Control-v>", self.on_paste)
        
        # Ephemeral mode button
        self.ephemeral_btn = tk.Button(
                self.input_frame, text="Ephemeral", command=self.toggle_ephemeral_mode,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.ephemeral_btn.pack(side=tk.RIGHT, padx=(0, 5)) # type: ignore
        
        # File Transfer window button
        self.file_transfer_btn = tk.Button(
                self.input_frame, text="Transfers", command=self.show_file_transfer_window,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.file_transfer_btn.pack(side=tk.RIGHT, padx=(0, 10)) # type: ignore
        
        # Send File button
        self.send_file_btn = tk.Button(
                self.input_frame, text="Send File", command=self.send_file,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.send_file_btn.pack(side=tk.RIGHT, padx=(0, 10)) # type: ignore
        
        # Send button
        self.send_btn = tk.Button(
                self.input_frame, text="Send", command=self.send_message,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.send_btn.pack(side=tk.RIGHT) # type: ignore
        
        # Debug frame (middle, initially visible)
        self.debug_frame = tk.Frame(content_frame, bg=self.BG_COLOR, width=300)
        self.debug_frame.pack_propagate(False)
        self.debug_visible = True
        
        # Debug Actions frame (right side)
        self.debug_actions_frame = tk.Frame(content_frame, bg=self.BG_COLOR, width=250)
        self.debug_actions_frame.pack_propagate(False)
        
        # Pack debug frames to the right
        self.debug_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(5, 5)) # type: ignore
        self.debug_actions_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 0)) # type: ignore
        
        # Create debug UI elements
        self._create_debug_display()
        self._create_debug_action_buttons()
    
    def _create_debug_display(self):
        """Create the debug information display area."""
        self.debug_display = scrolledtext.ScrolledText(
                self.debug_frame,
                state=tk.DISABLED,
                wrap=tk.WORD,
                height=20,
                font=("Consolas", 8),
                bg="#2d2d2d",
                fg="#00ff00",
                insertbackground="#00ff00",
                relief=tk.FLAT
        )
        self.debug_display.pack(fill=tk.BOTH, expand=True, padx=5) # type: ignore
    
    def _create_debug_action_buttons(self):
        """Create all debug action buttons."""
        # Debug Actions label
        debug_actions_label = tk.Label(
                self.debug_actions_frame,
                text="Debug Actions",
                bg=self.BG_COLOR,
                fg=self.FG_COLOR,
                font=("Consolas", 10, "bold")
        )
        debug_actions_label.pack(fill=tk.X, padx=5, pady=5) # type: ignore
        
        # Create all debug buttons
        self._create_debug_buttons()
    
    def _create_debug_buttons(self):
        """Create individual debug action buttons."""
        # Keepalive toggle button
        self.keepalive_toggle_btn = tk.Button(
                self.debug_actions_frame,
                text="Stop Keepalive Responses",
                command=self.toggle_keepalive_responses,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.keepalive_toggle_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Delivery confirmation toggle button
        self.delivery_confirmation_toggle_btn = tk.Button(
                self.debug_actions_frame,
                text="Disable Delivery Confirmations",
                command=self.toggle_delivery_confirmations,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.delivery_confirmation_toggle_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Send malformed message button
        self.malformed_msg_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Malformed Message",
                command=self.send_malformed_message,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.malformed_msg_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Set chain keys button
        self.set_chain_keys_btn = tk.Button(
                self.debug_actions_frame,
                text="Set Chain Keys",
                command=self.set_chain_keys,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.set_chain_keys_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Force disconnect button
        self.force_disconnect_btn = tk.Button(
                self.debug_actions_frame,
                text="Force Disconnect",
                command=self.force_disconnect,
                bg=self.BUTTON_BG_COLOR,
                fg="#ff6b6b",
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground="#ff6b6b",
                font=("Consolas", 9, "bold")
        )
        self.force_disconnect_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Force key reset button
        self.force_key_reset_btn = tk.Button(
                self.debug_actions_frame,
                text="Force Key Reset",
                command=self.force_key_reset,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.force_key_reset_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # View fingerprints button
        self.view_fingerprints_btn = tk.Button(
                self.debug_actions_frame,
                text="View Key Fingerprints",
                command=self.view_key_fingerprints,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.view_fingerprints_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Simulate latency button
        self.simulate_latency_btn = tk.Button(
                self.debug_actions_frame,
                text="Simulate Network Latency",
                command=self.simulate_network_latency,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.simulate_latency_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Export debug log button
        self.export_debug_log_btn = tk.Button(
                self.debug_actions_frame,
                text="Export Debug Log",
                command=self.export_debug_log,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.export_debug_log_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Send stale message button
        self.stale_msg_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Stale Message",
                command=self.send_stale_message,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR, # type: ignore
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.stale_msg_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Simulate packet loss button
        self.packet_loss_btn = tk.Button(
                self.debug_actions_frame,
                text="Simulate Packet Loss",
                command=self.simulate_packet_loss,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.packet_loss_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Send duplicate message button
        self.duplicate_msg_btn = tk.Button(
                self.debug_actions_frame,
                text="Send Duplicate Message",
                command=self.send_duplicate_message,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.duplicate_msg_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Set message counter button
        self.set_counter_btn = tk.Button(
                self.debug_actions_frame,
                text="Set Message Counter",
                command=self.set_message_counter,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.set_counter_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
        
        # Test protocol version button
        self.test_protocol_btn = tk.Button(
                self.debug_actions_frame,
                text="Test Protocol Version",
                command=self.test_protocol_version,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=tk.FLAT, # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.test_protocol_btn.pack(fill=tk.X, padx=5, pady=2) # type: ignore
    
    # Debug-specific methods
    def toggle_debug_box(self):
        """Toggle the visibility of the debug information box."""
        if self.debug_visible:
            self.debug_frame.pack_forget()
            self.debug_actions_frame.pack_forget()
            self.debug_toggle_btn.config(text="🔍 Show Debug Info")
            self.debug_visible = False
            # Stop the debug timer when hiding
            self._stop_debug_timer()
        else:
            self.debug_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(5, 5)) # type: ignore
            self.debug_actions_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 0)) # type: ignore
            self.debug_toggle_btn.config(text="🔍 Hide Debug Info")
            self.debug_visible = True
            # Start the debug timer when showing
            self._start_debug_timer()
            # Update debug info immediately when showing
            if self.client:
                self.update_debug_info()
    
    def update_debug_info(self):
        """Update the debug information display with current cryptographic state."""
        if not self.debug_visible or not self.client:
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
            if self.client.server_version is not None:
                debug_text += f"  Server Protocol Version: {self.client.server_protocol_version}\n"
            else:
                debug_text += "  Server Protocol Version: Unknown\n"
            
            # Peer version (if known)
            if self.client.peer_version is not None:
                debug_text += f"  Peer Version: {self.client.peer_version}\n"
            else:
                debug_text += "  Peer Version: Unknown\n"
            
            # Version compatibility check
            if (self.client.peer_version is not None and
                    self.client.server_protocol_version is not None):
                if (self.client.peer_version == PROTOCOL_VERSION and
                        self.client.server_protocol_version == PROTOCOL_VERSION):
                    debug_text += "  ✅ All versions compatible\n"
                else:
                    debug_text += "  ⚠️ Version mismatch detected\n"
            else:
                debug_text += "  ❓ Version compatibility unknown\n"
            
            debug_text += "\n"
            
            # Key Exchange Status
            debug_text += "KEY EXCHANGE STATUS:\n"
            
            # Check overall key exchange completion
            if self.client.key_exchange_complete:
                debug_text += "  ✅ KEY EXCHANGE COMPLETE\n"
            else:
                debug_text += "  ⏳ Key Exchange In Progress\n"
            
            # Check verification status
            if self.client.verification_complete:
                debug_text += "  ✅ VERIFICATION COMPLETE\n"
            else:
                debug_text += "  ⏳ Verification Pending\n"
            
            if self.client.protocol and self.client.protocol.shared_key:
                debug_text += f"  ✓ Shared Key: {self.client.protocol.shared_key[:16].hex()}...\n"
            else:
                debug_text += "  ✗ No Shared Key\n"
            
            if self.client.protocol and self.client.protocol.encryption_key:
                debug_text += f"  ✓ Encryption Key: {self.client.protocol.encryption_key[:16].hex()}...\n"
            else:
                debug_text += "  ✗ No Encryption Key\n"
            
            if self.client.protocol and self.client.protocol.mac_key:
                debug_text += f"  ✓ MAC Key: {self.client.protocol.mac_key[:16].hex()}...\n"
            else:
                debug_text += "  ✗ No MAC Key\n"
            
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
            if self.client.protocol and self.client.protocol.own_public_key:
                debug_text += f"  Own Public Key: {self.client.protocol.own_public_key[:16].hex()}...\n"
            else:
                debug_text += "  Own Public Key: Not generated\n"
            
            if self.client.protocol and self.client.protocol.peer_public_key:
                debug_text += f"  Peer Public Key: {self.client.protocol.peer_public_key[:16].hex()}...\n"
            else:
                debug_text += "  Peer Public Key: Not received\n"
            
            # Key Verification
            debug_text += "\nKEY VERIFICATION:\n"
            if self.client.protocol:
                if self.client.protocol.peer_key_verified:
                    debug_text += "  ✓ Peer Key Verified\n"
                else:
                    debug_text += "  ⚠ Peer Key Not Verified\n"
            else:
                debug_text += "  ⚠ Verification Status Unknown\n"
            
            # Connection Status
            debug_text += "\nCONNECTION STATUS:\n"
            debug_text += f"  Connected: {'Yes' if self.connected else 'No'}\n"
            if self.client.socket:
                debug_text += "  Socket: Active\n"
            else:
                debug_text += "  Socket: Inactive\n"
            
            # Keepalive Status
            debug_text += "\nKEEPALIVE STATUS:\n"
            if getattr(self.client, 'last_keepalive_received', None):
                last_received = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_received))
                debug_text += f"  Last Keepalive Received: {last_received}\n"
            else:
                debug_text += "  Last Keepalive Received: None\n"
            
            if getattr(self.client, 'last_keepalive_sent', None):
                last_sent = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_sent))
                debug_text += f"  Last Keepalive Sent: {last_sent}\n"
            else:
                debug_text += "  Last Keepalive Sent: None\n"
            
            respond_to_keepalive = getattr(self.client, 'respond_to_keepalive', None)
            if respond_to_keepalive is not None:
                status = "Enabled" if respond_to_keepalive else "Disabled"
                debug_text += f"  Keepalive Responses: {status}\n"
            else:
                debug_text += "  Keepalive Responses: Unknown\n"
            
            debug_text += "\n" + "=" * 45 + "\n"
            
            # Update the debug display
            self.debug_display.config(state=tk.NORMAL) # type: ignore # type: ignore
            self.debug_display.delete(1.0, tk.END)
            self.debug_display.insert(tk.END, debug_text)
            self.debug_display.see(tk.END)
            self.debug_display.config(state=tk.DISABLED) # type: ignore # type: ignore
        
        except Exception as e:
            # Fallback debug info if there's an error
            error_text = f"Debug Info Error: {e}\n"
            error_text += f"Client exists: {self.client is not None}\n"
            error_text += f"Connected: {self.connected}\n"
            
            self.debug_display.config(state=tk.NORMAL) # type: ignore # type: ignore
            self.debug_display.delete(1.0, tk.END)
            self.debug_display.insert(tk.END, error_text)
            self.debug_display.config(state=tk.DISABLED) # type: ignore # type: ignore
    
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
    
    def send_malformed_message(self):
        """Send a malformed message to test error handling."""
        if not self.client or not self.client.socket:
            return
        
        try:
            # Create a malformed message (invalid JSON)
            malformed_message = b'{"type": 3, "counter": 999, "nonce": "invalid", "ciphertext": "invalid"'
            
            # Send directly to socket, bypassing normal message handling
            self.client.socket.sendall(len(malformed_message).to_bytes(4, byteorder='big'))
            self.client.socket.sendall(malformed_message)
            
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
            tk.Label(dialog, text="Send Chain Key (hex):", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(anchor=tk.W, # type: ignore
                                                                                                    padx=10,
                                                                                                    pady=(10, 0))
            send_key_entry = tk.Entry(dialog, width=50, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            send_key_entry.pack(fill=tk.X, padx=10, pady=5) # type: ignore
             # type: ignore # type: ignore
            # Receive chain key input
            tk.Label(dialog, text="Receive Chain Key (hex):", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(anchor=tk.W, # type: ignore
                                                                                                       padx=10,
                                                                                                       pady=(10, 0))
            receive_key_entry = tk.Entry(dialog, width=50, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            receive_key_entry.pack(fill=tk.X, padx=10, pady=5) # type: ignore
            
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
                    justify=tk.LEFT # type: ignore
            )
            warning_label.pack(fill=tk.X, padx=10, pady=10) # type: ignore
            
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
            button_frame.pack(fill=tk.X, padx=10, pady=10) # type: ignore
            
            apply_btn = tk.Button(
                    button_frame, text="Apply", command=apply_keys,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT # type: ignore
            )
            apply_btn.pack(side=tk.LEFT, padx=(0, 5)) # type: ignore
            
            cancel_btn = tk.Button(
                    button_frame, text="Cancel", command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT # type: ignore
            )
            cancel_btn.pack(side=tk.LEFT) # type: ignore
        
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
    
    def force_key_reset(self):
        """Force reset all cryptographic keys."""
        if not self.client or not self.client.protocol:
            return
        
        try:
            # Reset all keys
            self.client.protocol.shared_key = None
            self.client.protocol.encryption_key = None
            self.client.protocol.mac_key = None
            self.client.protocol.send_chain_key = None
            self.client.protocol.receive_chain_key = None
            self.client.protocol.message_counter = 0
            self.client.protocol.peer_counter = 0
            self.client.key_exchange_complete = False
            self.client.verification_complete = False
            
            self.append_to_chat("All cryptographic keys have been reset")
            self.update_debug_info()
        except Exception as e:
            self.append_to_chat(f"Error resetting keys: {e}")
    
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
                    state=tk.DISABLED,
                    wrap=tk.WORD,
                    font=("Consolas", 10),
                    bg="#1e1e1e",
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR,
                    relief=tk.FLAT
            )
            text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10) # type: ignore
            
            fingerprint_text = "=== KEY FINGERPRINTS ===\n\n"
            
            # Own public key fingerprint
            if self.client.protocol.own_public_key:
                own_fp = hashlib.sha3_256(self.client.protocol.own_public_key).hexdigest()[:32]
                fingerprint_text += f"Own Public Key:\n{own_fp}\n\n"
            else:
                fingerprint_text += "Own Public Key: Not available\n\n"
            
            # Peer public key fingerprint
            if self.client.protocol.peer_public_key:
                peer_fp = hashlib.sha3_256(self.client.protocol.peer_public_key).hexdigest()[:32]
                fingerprint_text += f"Peer Public Key:\n{peer_fp}\n\n"
            else:
                fingerprint_text += "Peer Public Key: Not available\n\n"
            
            # Shared key fingerprint
            if self.client.protocol.shared_key:
                shared_fp = hashlib.sha3_256(self.client.protocol.shared_key).hexdigest()[:32]
                fingerprint_text += f"Shared Key:\n{shared_fp}\n\n"
            else:
                fingerprint_text += "Shared Key: Not available\n\n"
            
            text_area.config(state=tk.NORMAL) # type: ignore
            text_area.insert(tk.END, fingerprint_text)
            text_area.config(state=tk.DISABLED) # type: ignore
        
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
                    self.client.network_latency = latency_ms / 1000.0  # Convert to seconds
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
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT # type: ignore
            )
            apply_btn.pack(side=tk.LEFT, padx=5) # type: ignore
            
            cancel_btn = tk.Button(
                    button_frame, text="Cancel", command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT # type: ignore
            )
            cancel_btn.pack(side=tk.LEFT, padx=5) # type: ignore
        
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
            
            # Message input # type: ignore
            tk.Label(
                    dialog,
                    text="Message:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5)) # type: ignore
            
            message_entry = tk.Entry(
                    dialog,
                    width=40,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            message_entry.insert(0, "This is a stale message")
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10) # type: ignore
            
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
            
            tk.Button(
                    button_frame,
                    text="Send",
                    command=send_stale,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5) # type: ignore
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5) # type: ignore
        
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
            loss_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10) # type: ignore
            
            # Packet loss percentage slider
            tk.Label(
                    loss_frame,
                    text="Packet Loss Percentage:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=tk.X, pady=(10, 5)) # type: ignore
            
            loss_var = tk.IntVar(value=25)  # Default 25%
            loss_slider = tk.Scale(
                    loss_frame,
                    from_=0,
                    to=100,
                    orient=tk.HORIZONTAL, # type: ignore
                    variable=loss_var,
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    highlightthickness=0,
                    troughcolor="#2d2d2d"
            )
            loss_slider.pack(fill=tk.X, pady=(0, 10)) # type: ignore
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10) # type: ignore
            
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
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5) # type: ignore
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5) # type: ignore
        
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
            tk.Label(
                    dialog,
                    text="Message:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10), # type: ignore
                    anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5)) # type: ignore
            
            message_entry = tk.Entry(
                    dialog,
                    width=40,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            message_entry.insert(0, "This is a duplicate message")
            
            # Count input
            tk.Label(
                    dialog,
                    text="Number of duplicates:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5)) # type: ignore
            
            count_var = tk.IntVar(value=3)  # Default 3 duplicates
            count_slider = tk.Scale(
                    dialog,
                    from_=2,
                    to=10,
                    orient=tk.HORIZONTAL, # type: ignore
                    variable=count_var,
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    highlightthickness=0,
                    troughcolor="#2d2d2d"
            )
            count_slider.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10) # type: ignore
            
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
            
            tk.Button(
                    button_frame,
                    text="Send",
                    command=send_duplicates,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5) # type: ignore
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5) # type: ignore
        
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
            ).pack(fill=tk.X, padx=20, pady=(20, 5)) # type: ignore
            
            send_counter_entry = tk.Entry(
                    dialog,
                    width=20,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            send_counter_entry.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            
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
            ).pack(fill=tk.X, padx=20, pady=(10, 5)) # type: ignore
            
            peer_counter_entry = tk.Entry(
                    dialog,
                    width=20,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            peer_counter_entry.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            
            # Pre-fill with current value if available
            peer_counter_entry.insert(0, str(self.client.protocol.peer_counter))
            
            # Warning label
            warning_label = tk.Label(
                    dialog,
                    text="WARNING: Setting custom counters may break message encryption.\nOnly use for debugging!",
                    bg=self.BG_COLOR,
                    fg="#ff6b6b",
                    justify=tk.LEFT # type: ignore
            )
            warning_label.pack(fill=tk.X, padx=20, pady=10) # type: ignore
            
            # Buttons frame
            buttons_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            buttons_frame.pack(fill=tk.X, padx=20, pady=10) # type: ignore
            
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
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            )
            apply_btn.pack(side=tk.LEFT, padx=5) # type: ignore
            
            # Cancel button
            cancel_btn = tk.Button(
                    buttons_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            )
            cancel_btn.pack(side=tk.RIGHT, padx=5) # type: ignore
        
        except Exception as err:
            self.append_to_chat(f"Error setting message counters: {err}")
    
    def test_protocol_version(self):
        """Test protocol version compatibility by sending messages with different versions."""
        if not self.client or not self.client.socket:
            return
        
        try:
            # Create a dialog to get the protocol version
            dialog = tk.Toplevel(self.root)
            dialog.title("Test Protocol Version")
            dialog.geometry("400x250")
            dialog.configure(bg=self.BG_COLOR)
            
            # Make dialog modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add a label
            tk.Label(
                    dialog,
                    text="Test Protocol Version",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            ).pack(pady=10)
            
            # Message input
            tk.Label(
                    dialog,
                    text="Message:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5)) # type: ignore
            
            message_entry = tk.Entry(
                    dialog,
                    width=40,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            message_entry.insert(0, "Testing protocol version compatibility")
            
            # Version input
            tk.Label(
                    dialog,
                    text="Protocol Version:",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 10),
                    anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5)) # type: ignore
            
            # Get the current protocol version
            current_version = PROTOCOL_VERSION
            
            version_entry = tk.Entry(
                    dialog,
                    width=10,
                    bg=self.ENTRY_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR
            )
            version_entry.pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            version_entry.insert(0, str(current_version - 1))  # Default to previous version
            
            # Current version label
            tk.Label(
                    dialog,
                    text=f"Current version: {current_version}",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 9),
                    anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(0, 10)) # type: ignore
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10) # type: ignore
            
            # Send button
            def send_with_version():
                message_text = message_entry.get().strip()
                try:
                    version = int(version_entry.get().strip())
                except ValueError:
                    messagebox.showerror("Error", "Please enter a valid version number")
                    return
                
                if not message_text:
                    messagebox.showerror("Error", "Please enter a message")
                    return
                
                # Create a message with the specified version
                try:
                    # Create a custom message with the specified version
                    encrypted_data = self.client.protocol.encrypt_message(message_text)
                    
                    # Decode the message to modify the version
                    message_dict = json.loads(encrypted_data.decode('utf-8'))
                    message_dict["version"] = version
                    
                    # Re-encode the message
                    modified_data = json.dumps(message_dict).encode('utf-8')
                    
                    # Send the modified message
                    send_message(self.client.socket, modified_data)
                    
                    self.append_to_chat(f"Sent message with protocol version {version} (current: {current_version})")
                
                except Exception as e:
                    self.append_to_chat(f"Error sending version test message: {e}")
                
                dialog.destroy()
            
            tk.Button(
                    button_frame,
                    text="Send",
                    command=send_with_version,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5) # type: ignore
            
            # Cancel button
            tk.Button(
                    button_frame,
                    text="Cancel",
                    command=dialog.destroy,
                    bg=self.BUTTON_BG_COLOR,
                    fg=self.FG_COLOR,
                    relief=tk.FLAT, # type: ignore
                    activebackground=self.BUTTON_ACTIVE_BG,
                    activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5) # type: ignore
        
        except Exception as err:
            self.append_to_chat(f"Error creating protocol version test dialog: {err}")
    
    def on_closing(self):
        """Handle window closing - override to clean up debug timer."""
        # Stop the debug timer before closing
        self._stop_debug_timer()
        # Call parent cleanup
        super().on_closing()


class DebugGUISecureChatClient(GUISecureChatClient):
    """Debug version of GUISecureChatClient - extends base with debug features."""
    
    def __init__(self, host='localhost', port=16384, gui=None):
        super().__init__(host, port, gui)
        
        # Protocol version tracking
        self.protocol_version = PROTOCOL_VERSION
        self.peer_version = None  # Will be set during key exchange
        
        # Keepalive tracking
        self.last_keepalive_received = None
        self.last_keepalive_sent = None
        self.respond_to_keepalive = True  # Flag to control whether to respond to keepalives
        
        # Delivery confirmation tracking
        self.send_delivery_confirmations = True  # Flag to control whether to send delivery confirmations
        
        # Socket lock for thread synchronization
        self.socket_lock = threading.Lock()
        
        # Debug features
        self.simulated_latency = 0  # No latency by default
        self.packet_loss_percentage = 0  # No packet loss by default
    
    def handle_message(self, message_data: bytes) -> None:
        """Handle incoming messages with GUI updates and debug logging."""
        if self.simulated_latency > 0:
            time.sleep(self.simulated_latency)
        
        if self.packet_loss_percentage > 0:
            if random.randint(1, 100) <= self.packet_loss_percentage:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(
                            f"DEBUG: Packet loss simulated ({self.packet_loss_percentage}%)", is_message=False))
                return
        
        super().handle_message(message_data)
    
    def handle_key_exchange_init(self, message_data: bytes):
        """Handle key exchange init - override to extract and store protocol version."""
        try:
            # Extract protocol version from message
            message = json.loads(message_data.decode('utf-8'))
            self.peer_version = message.get("version")
            
            # Debug logging
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        f"DEBUG: Key exchange init from peer (version {self.peer_version})", is_message=False))
            
            # Call parent method to handle the key exchange
            super().handle_key_exchange_init(message_data)
            
            # Update debug info after key exchange init
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.update_debug_info())
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda er=e: self.gui.append_to_chat(f"Key exchange init error: {er}"))
            else:
                print(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes):
        """Handle key exchange response - override to extract and store protocol version."""
        try:
            # Extract protocol version from message
            message = json.loads(message_data.decode('utf-8'))
            self.peer_version = message.get("version")
            
            # Debug logging
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        f"DEBUG: Key exchange response from peer (version {self.peer_version})", is_message=False))
            
            # Call parent method to handle the key exchange
            super().handle_key_exchange_response(message_data)
            
            # Update debug info after key exchange response
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.update_debug_info())
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda er=e: self.gui.append_to_chat(f"Key exchange response error: {er}"))
            else:
                print(f"Key exchange response error: {e}")
    
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
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        "DEBUG: Keepalive received from server", is_message=False))
        
        except Exception as err:
            if self.gui:
                self.gui.root.after(0, lambda er=err: self.gui.append_to_chat(f"Keepalive error: {er}"))
            else:
                print(f"Keepalive error: {err}")
    
    def _send_delivery_confirmation(self, confirmed_counter: int):
        """Send delivery confirmation - override to add debug control."""
        if self.packet_loss_percentage > 0:
            if random.randint(1, 100) <= self.packet_loss_percentage:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(
                            f"DEBUG: Packet loss simulated ({self.packet_loss_percentage}%) for delivery confirmation", is_message=False))
                return
            
        if self.send_delivery_confirmations:
            super()._send_delivery_confirmation(confirmed_counter)
        else:
            # Debug flag is False, skip sending confirmation for debugging
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        f"Delivery confirmation suppressed", is_message=False))
    
    def send_message(self, text: str) -> bool | None:
        """Encrypt and send a chat message with optional simulated latency and packet loss."""
        if not self.socket:
            return None
        
        try:
            # Simulate packet loss
            if self.packet_loss_percentage > 0:
                if random.randint(1, 100) <= self.packet_loss_percentage:
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(
                                f"DEBUG: Packet loss simulated ({self.packet_loss_percentage}%)", is_message=False))
                    return None
                
            # Simulate network latency if configured
            if self.simulated_latency > 0:
                time.sleep(self.simulated_latency)
            
            
            # Call the parent method to send the message
            return super().send_message(text)
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda er=e: self.gui.append_to_chat(f"Error sending message: {er}"))
            else:
                print(f"Error sending message: {e}")
            return None


def main():
    """Main function to run the GUI chat client."""
    root = TkinterDnD.Tk()
    root.title("Secure Chat Client (DEBUG)")
    
    # Create GUI
    gui = DebugChatGUI(root)
    
    # Override the client creation to use our GUI-aware version
    def gui_connect():
        try:
            host = gui.host_entry.get().strip() or "localhost"
            port = int(gui.port_entry.get().strip() or "16384")
            
            gui.append_to_chat(f"Connecting to {host}:{port}...")
            
            # Create Debug GUI-aware client instance
            gui.client = DebugGUISecureChatClient(host, port, gui)
            
            # Start connection in a separate thread
            # noinspection DuplicatedCode
            def connect_thread():
                try:
                    if gui.client.connect():
                        gui.connected = True
                        gui.root.after(0, gui.on_connected)
                        gui.start_chat_monitoring()
                    else:
                        gui.root.after(0, lambda: gui.append_to_chat("Failed to connect to server"))
                except Exception as er:
                    gui.root.after(0, lambda error=er: gui.append_to_chat(f"Connection error: {error}"))
            
            threading.Thread(target=connect_thread, daemon=True).start()
        
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
        except Exception as err:
            gui.append_to_chat(f"Connection error: {err}")
    
    gui.connect_to_server = gui_connect
    
    # Start the GUI
    root.mainloop()


if __name__ == "__main__":
    main()
