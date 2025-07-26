import tkinter as tk  # type: ignore
from tkinter import scrolledtext, messagebox, filedialog, ttk  # type: ignore
import threading
import sys
import io
import os
import time
from client import SecureChatClient
import json

from shared import bytes_to_human_readable, send_message, MSG_TYPE_FILE_METADATA, MSG_TYPE_FILE_ACCEPT, MSG_TYPE_FILE_REJECT,\
    MSG_TYPE_FILE_COMPLETE, MSG_TYPE_FILE_CHUNK, MSG_TYPE_KEEP_ALIVE, MSG_TYPE_KEEP_ALIVE_RESPONSE, MSG_TYPE_KEY_EXCHANGE_RESET, PROTOCOL_VERSION, FILE_CHUNK_SIZE, SEND_CHUNK_SIZE


class FileTransferWindow:
    """Separate window for file transfer progress and status updates."""
    
    def __init__(self, parent_root):
        """Initialize the file transfer window manager.

        Args:
            parent_root (tk.Tk): The parent root window that this transfer window
                will be associated with.

        Attributes:
            parent_root (tk.Tk): Reference to the parent window.
            window (tk.Toplevel): The actual transfer window (created on demand).
            transfers (dict): Dictionary mapping transfer ID to transfer information.
            speed_label (tk.Label): Label widget displaying current transfer speed.
            transfer_list (scrolledtext.ScrolledText): Text widget showing transfer messages.
            last_update_time (float): Timestamp of last speed calculation update.
            last_bytes_transferred (int): Bytes transferred at last speed update.
            current_speed (float): Current transfer speed in bytes per second.
            BG_COLOR (str): Background color for dark theme.
            FG_COLOR (str): Foreground text color for dark theme.
            ENTRY_BG_COLOR (str): Background color for entry widgets.
            BUTTON_BG_COLOR (str): Background color for button widgets.
        """
        self.parent_root = parent_root
        self.window = None
        self.transfers = {}  # transfer_id -> transfer_info
        self.speed_label = None
        self.transfer_list = None
        
        # Speed calculation variables
        self.last_update_time = time.time()
        self.last_bytes_transferred = 0
        self.current_speed = 0.0
        
        # Dark theme colors (matching main window)
        self.BG_COLOR = "#2b2b2b"
        self.FG_COLOR = "#d4d4d4"
        self.ENTRY_BG_COLOR = "#3c3c3c"
        self.BUTTON_BG_COLOR = "#555555"
    
    def create_window(self):
        """Create the file transfer window if it doesn't exist."""
        if self.window is None or not self.window.winfo_exists():
            self.window = tk.Toplevel(self.parent_root)
            self.window.title("File Transfer Progress")
            self.window.geometry("550x400")
            self.window.configure(bg=self.BG_COLOR)
            
            # Make window stay on top but not always
            self.window.transient(self.parent_root)
            
            # Top frame for speed display
            top_frame = tk.Frame(self.window, bg=self.BG_COLOR)
            top_frame.pack(fill=tk.X, padx=10, pady=5)
            
            # Speed label in top right
            self.speed_label = tk.Label(
                    top_frame,
                    text="Speed: 0.0 MiB/s",
                    bg=self.BG_COLOR,
                    fg="#4CAF50",
                    font=("Consolas", 10, "bold")
            )
            self.speed_label.pack(side=tk.RIGHT)
            
            # Title label
            title_label = tk.Label(
                    top_frame,
                    text="File Transfers",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            )
            title_label.pack(side=tk.LEFT)
            
            # Main frame for transfer list
            main_frame = tk.Frame(self.window, bg=self.BG_COLOR)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            # Scrollable text area for transfer updates
            self.transfer_list = scrolledtext.ScrolledText(
                    main_frame,
                    state=tk.DISABLED,
                    wrap=tk.WORD,
                    height=20,
                    font=("Consolas", 9),
                    bg="#1e1e1e",
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR,
                    relief=tk.FLAT
            )
            self.transfer_list.pack(fill=tk.BOTH, expand=True)
            
            # Handle window closing
            self.window.protocol("WM_DELETE_WINDOW", self.hide_window)
    
    def show_window(self):
        """Show the file transfer window."""
        self.create_window()
        self.window.deiconify()
        self.window.lift()
    
    def hide_window(self):
        """Hide the file transfer window."""
        if self.window:
            self.window.withdraw()
    
    def add_transfer_message(self, message, transfer_id=None):
        """Add a message to the transfer window."""
        self.create_window()
        
        if self.transfer_list:
            self.transfer_list.config(state=tk.NORMAL)
            timestamp = time.strftime("%H:%M:%S")
            self.transfer_list.insert(tk.END, f"[{timestamp}] {message}\n")
            self.transfer_list.see(tk.END)
            self.transfer_list.config(state=tk.DISABLED)
        
        # Show window if not visible
        if self.window.state() == 'withdrawn':
            self.show_window()
    
    def update_transfer_progress(self, transfer_id, filename, current, total, bytes_transferred=None):
        """Update progress for a specific transfer."""
        progress = (current / total) * 100 if total > 0 else 0
        
        # Calculate speed if bytes_transferred is provided
        if bytes_transferred is not None:
            self.update_speed(bytes_transferred)
        
        message = f"{filename}: {progress:.1f}% ({current}/{total} chunks)"
        self.add_transfer_message(message, transfer_id)
    
    def update_speed(self, total_bytes_transferred):
        """Update the transfer speed display."""
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        
        if time_diff >= 1.0:  # Update speed every second
            bytes_diff = total_bytes_transferred - self.last_bytes_transferred
            speed_bytes_per_sec = bytes_diff / time_diff
            speed_mib_per_sec = speed_bytes_per_sec / (1024 * 1024)  # Convert to MiB/s
            
            self.current_speed = speed_mib_per_sec
            
            if self.speed_label:
                self.speed_label.config(text=f"Speed: {speed_mib_per_sec:.2f} MiB/s")
            
            self.last_update_time = current_time
            self.last_bytes_transferred = total_bytes_transferred
    
    def clear_speed(self):
        """Clear the speed display when no transfers are active."""
        self.current_speed = 0.0
        if self.speed_label:
            self.speed_label.config(text="Speed: 0.0 MiB/s")
        self.last_bytes_transferred = 0
        self.last_update_time = time.time()


class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("1200x600")
        
        # Dark theme colours
        self.BG_COLOR = "#2b2b2b"
        self.FG_COLOR = "#d4d4d4"
        self.ENTRY_BG_COLOR = "#3c3c3c"
        self.BUTTON_BG_COLOR = "#555555"
        self.BUTTON_ACTIVE_BG = "#6a6a6a"
        
        self.root.configure(bg=self.BG_COLOR)
        
        # Chat client instance
        self.client = None
        self.connected = False
        
        # Ephemeral mode state
        self.ephemeral_mode = False
        self.ephemeral_messages = {}  # Track messages with timestamps for removal
        self.message_counter = 0  # Counter for unique message IDs
        
        # Debug update throttling
        self.last_debug_update = 0  # Timestamp of last debug update
        self.debug_update_interval = 1.0  # Update debug info max once per second
        
        # File transfer window
        self.file_transfer_window = FileTransferWindow(self.root)
        
        # Create GUI elements
        self.create_widgets()
        
        # Redirect stdout to capture print statements
        self.setup_output_redirection()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        """Create the GUI widgets."""
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)  # type: ignore
        
        # Connection frame
        conn_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        conn_frame.pack(fill=tk.X, pady=(0, 10))  # type: ignore
        
        # Host and port inputs
        tk.Label(conn_frame, text="Host:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=tk.LEFT)  # type: ignore
        self.host_entry = tk.Entry(
                conn_frame, width=15, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=tk.FLAT  # type: ignore
        )
        self.host_entry.pack(side=tk.LEFT, padx=(5, 10))  # type: ignore
        self.host_entry.insert(0, "localhost")
        
        tk.Label(conn_frame, text="Port:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=tk.LEFT)  # type: ignore
        self.port_entry = tk.Entry(
                conn_frame, width=8, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=tk.FLAT  # type: ignore
        )
        self.port_entry.pack(side=tk.LEFT, padx=(5, 10))  # type: ignore
        self.port_entry.insert(0, "16384")
        
        # Connect/Disconnect button
        self.connect_btn = tk.Button(
                conn_frame, text="Connect", command=self.toggle_connection,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.connect_btn.pack(side=tk.LEFT, padx=(10, 0))  # type: ignore
        
        # Status indicator (top right)
        self.status_label = tk.Label(
                conn_frame, text="Not Connected",
                bg=self.BG_COLOR, fg="#ff6b6b", font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0))  # type: ignore
        
        # Content frame to hold chat and debug side by side
        content_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))  # type: ignore
        
        # Chat frame (left side)
        chat_frame = tk.Frame(content_frame, bg=self.BG_COLOR)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))  # type: ignore
        
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(
                chat_frame,
                state=tk.DISABLED,
                wrap=tk.WORD,
                height=20,
                font=("Consolas", 10),
                bg="#1e1e1e",
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR,
                relief=tk.FLAT
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)  # type: ignore
        
        # Debug frame (middle, initially visible by default)
        self.debug_frame = tk.Frame(content_frame, bg=self.BG_COLOR, width=300)
        self.debug_frame.pack_propagate(False)  # Maintain fixed width
        self.debug_visible = True  # Show debug panel by default
        
        # Debug Actions frame (right side)
        self.debug_actions_frame = tk.Frame(content_frame, bg=self.BG_COLOR, width=200)
        self.debug_actions_frame.pack_propagate(False)  # Maintain fixed width
        
        # Show debug frames by default
        self.debug_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(5, 5))  # type: ignore
        self.debug_actions_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(0, 0))  # type: ignore
        
        # Debug toggle button frame
        debug_toggle_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        debug_toggle_frame.pack(fill=tk.X, pady=(0, 5))  # type: ignore
        
        self.debug_toggle_btn = tk.Button(
                debug_toggle_frame, text="🔍 Hide Debug Info", command=self.toggle_debug_box,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.debug_toggle_btn.pack(side=tk.LEFT)  # type: ignore
        
        # Debug display area
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
        self.debug_display.pack(fill=tk.BOTH, expand=True, padx=5)  # type: ignore
        
        # Debug Actions area
        debug_actions_label = tk.Label(
            self.debug_actions_frame, 
            text="Debug Actions", 
            bg=self.BG_COLOR, 
            fg=self.FG_COLOR,
            font=("Consolas", 10, "bold")
        )
        debug_actions_label.pack(fill=tk.X, padx=5, pady=5)
        
        # Keepalive toggle button
        self.keepalive_toggle_btn = tk.Button(
            self.debug_actions_frame, 
            text="Stop Keepalive Responses", 
            command=self.toggle_keepalive_responses,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.keepalive_toggle_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Send malformed message button
        self.malformed_msg_btn = tk.Button(
            self.debug_actions_frame, 
            text="Send Malformed Message", 
            command=self.send_malformed_message,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.malformed_msg_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Set chain keys button
        self.set_chain_keys_btn = tk.Button(
            self.debug_actions_frame, 
            text="Set Chain Keys", 
            command=self.set_chain_keys,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.set_chain_keys_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Force disconnect button
        self.force_disconnect_btn = tk.Button(
            self.debug_actions_frame, 
            text="Force Disconnect", 
            command=self.force_disconnect,
            bg=self.BUTTON_BG_COLOR, 
            fg="#ff6b6b", 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground="#ff6b6b",
            font=("Consolas", 9, "bold")
        )
        self.force_disconnect_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Force key reset button
        self.force_key_reset_btn = tk.Button(
            self.debug_actions_frame, 
            text="Force Key Reset", 
            command=self.force_key_reset,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.force_key_reset_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # View fingerprints button
        self.view_fingerprints_btn = tk.Button(
            self.debug_actions_frame, 
            text="View Key Fingerprints", 
            command=self.view_key_fingerprints,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.view_fingerprints_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Simulate latency button
        self.simulate_latency_btn = tk.Button(
            self.debug_actions_frame, 
            text="Simulate Network Latency", 
            command=self.simulate_network_latency,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.simulate_latency_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Export debug log button
        self.export_debug_log_btn = tk.Button(
            self.debug_actions_frame, 
            text="Export Debug Log", 
            command=self.export_debug_log,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.export_debug_log_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Send stale message button
        self.stale_msg_btn = tk.Button(
            self.debug_actions_frame, 
            text="Send Stale Message", 
            command=self.send_stale_message,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.stale_msg_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Simulate packet loss button
        self.packet_loss_btn = tk.Button(
            self.debug_actions_frame, 
            text="Simulate Packet Loss", 
            command=self.simulate_packet_loss,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.packet_loss_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Send duplicate message button
        self.duplicate_msg_btn = tk.Button(
            self.debug_actions_frame, 
            text="Send Duplicate Message", 
            command=self.send_duplicate_message,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.duplicate_msg_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Set message counter button
        self.set_counter_btn = tk.Button(
            self.debug_actions_frame, 
            text="Set Message Counter", 
            command=self.set_message_counter,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.set_counter_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Test protocol version button
        self.test_protocol_btn = tk.Button(
            self.debug_actions_frame, 
            text="Test Protocol Version", 
            command=self.test_protocol_version,
            bg=self.BUTTON_BG_COLOR, 
            fg=self.FG_COLOR, 
            relief=tk.FLAT,
            activebackground=self.BUTTON_ACTIVE_BG, 
            activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.test_protocol_btn.pack(fill=tk.X, padx=5, pady=2)
        
        # Initially disable debug action buttons until connected
        self.keepalive_toggle_btn.config(state=tk.DISABLED)
        self.malformed_msg_btn.config(state=tk.DISABLED)
        self.set_chain_keys_btn.config(state=tk.DISABLED)
        self.force_disconnect_btn.config(state=tk.DISABLED)
        self.force_key_reset_btn.config(state=tk.DISABLED)
        self.view_fingerprints_btn.config(state=tk.DISABLED)
        self.simulate_latency_btn.config(state=tk.DISABLED)
        self.stale_msg_btn.config(state=tk.DISABLED)
        self.packet_loss_btn.config(state=tk.DISABLED)
        self.duplicate_msg_btn.config(state=tk.DISABLED)
        self.set_counter_btn.config(state=tk.DISABLED)
        self.test_protocol_btn.config(state=tk.DISABLED)
        # Export debug log is always enabled
        self.export_debug_log_btn.config(state=tk.NORMAL)
        
        # Input frame
        input_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        input_frame.pack(fill=tk.X)  # type: ignore
        
        # Message input
        self.message_entry = tk.Entry(
                input_frame, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR, relief=tk.FLAT  # type: ignore
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))  # type: ignore
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        
        # Ephemeral mode button (with gap before Send File)
        self.ephemeral_btn = tk.Button(
                input_frame, text="⏱️ Ephemeral", command=self.toggle_ephemeral_mode,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.ephemeral_btn.pack(side=tk.RIGHT, padx=(0, 5))  # type: ignore
        
        # File Transfer window button
        self.file_transfer_btn = tk.Button(
                input_frame, text="📁 Transfers", command=self.show_file_transfer_window,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.file_transfer_btn.pack(side=tk.RIGHT, padx=(0, 10))  # type: ignore
        
        # Send File button
        self.send_file_btn = tk.Button(
                input_frame, text="Send File", command=self.send_file,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_file_btn.pack(side=tk.RIGHT, padx=(0, 5))  # type: ignore
        
        # Send button
        self.send_btn = tk.Button(
                input_frame, text="Send", command=self.send_message,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_btn.pack(side=tk.RIGHT)  # type: ignore
        
        # Initially disable input until connected
        self.message_entry.config(state=tk.DISABLED)  # type: ignore
        self.send_btn.config(state=tk.DISABLED)  # type: ignore
        self.send_file_btn.config(state=tk.DISABLED)  # type: ignore
        self.ephemeral_btn.config(state=tk.DISABLED)  # type: ignore
        self.file_transfer_btn.config(state=tk.DISABLED)  # type: ignore
        
        # Start ephemeral message cleanup thread
        self.start_ephemeral_cleanup()
    
    def setup_output_redirection(self):
        """Setup output redirection to capture print statements."""
        self.output_buffer = io.StringIO()
    
    def append_to_chat(self, text, is_message=False):
        """Append text to the chat display."""
        self.chat_display.config(state=tk.NORMAL)  # type: ignore
        
        # If ephemeral mode is enabled and this is a message, track it
        if self.ephemeral_mode and is_message:
            self.message_counter += 1
            message_id = f"msg_{self.message_counter}"
            
            self.ephemeral_messages[message_id] = time.time()
            # Add invisible marker for tracking
            self.chat_display.insert(tk.END, f"{text} <!-- {message_id} -->\n")
        else:
            self.chat_display.insert(tk.END, text + "\n")
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)  # type: ignore
    
    def update_status(self, status_text, color="#ff6b6b"):
        """Update the status indicator with new text and color."""
        self.status_label.config(text=status_text, fg=color)  # type: ignore
    
    def show_file_transfer_window(self):
        """Show the file transfer progress window."""
        self.file_transfer_window.show_window()
    
    def toggle_debug_box(self):
        """Toggle the visibility of the debug information box."""
        if self.debug_visible:
            self.debug_frame.pack_forget()
            self.debug_toggle_btn.config(text="🔍 Show Debug Info")  # type: ignore
            self.debug_visible = False
        else:
            self.debug_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(5, 0))  # type: ignore
            self.debug_toggle_btn.config(text="🔍 Hide Debug Info")  # type: ignore
            self.debug_visible = True
            # Update debug info when showing
            if hasattr(self, 'client') and self.client:
                self.update_debug_info()
    
    def update_debug_info(self):
        """Update the debug information display with current cryptographic state."""
        if not self.debug_visible or not hasattr(self, 'client') or not self.client:
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
            
            # Server version (if known)
            if hasattr(self.client, 'server_version'):
                debug_text += f"  Server Version: {self.client.server_version}\n"
            else:
                debug_text += "  Server Version: Unknown\n"
            
            # Peer version (if known)
            if hasattr(self.client, 'peer_version'):
                debug_text += f"  Peer Version: {self.client.peer_version}\n"
            else:
                debug_text += "  Peer Version: Unknown\n"
            
            # Version compatibility check
            if (hasattr(self.client, 'peer_version') and
                hasattr(self.client, 'server_version')):
                if (self.client.peer_version == PROTOCOL_VERSION and
                    self.client.server_version == PROTOCOL_VERSION):
                    debug_text += "  ✅ All versions compatible\n"
                else:
                    debug_text += "  ⚠️ Version mismatch detected\n"
            else:
                debug_text += "  ❓ Version compatibility unknown\n"
            
            debug_text += "\n"
            
            # Key Exchange Status
            debug_text += "KEY EXCHANGE STATUS:\n"
            
            # Check overall key exchange completion
            if hasattr(self.client, 'key_exchange_complete') and self.client.key_exchange_complete:
                debug_text += "  ✅ KEY EXCHANGE COMPLETE\n"
            else:
                debug_text += "  ⏳ Key Exchange In Progress\n"
            
            # Check verification status
            if hasattr(self.client, 'verification_complete') and self.client.verification_complete:
                debug_text += "  ✅ VERIFICATION COMPLETE\n"
            else:
                debug_text += "  ⏳ Verification Pending\n"
            
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'shared_key') and self.client.protocol.shared_key:
                debug_text += f"  ✓ Shared Key: {self.client.protocol.shared_key[:16].hex()}...\n"
            else:
                debug_text += "  ✗ No Shared Key\n"
                
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'encryption_key') and self.client.protocol.encryption_key:
                debug_text += f"  ✓ Encryption Key: {self.client.protocol.encryption_key[:16].hex()}...\n"
            else:
                debug_text += "  ✗ No Encryption Key\n"
                
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'mac_key') and self.client.protocol.mac_key:
                debug_text += f"  ✓ MAC Key: {self.client.protocol.mac_key[:16].hex()}...\n"
            else:
                debug_text += "  ✗ No MAC Key\n"
            
            # Chain Keys and Counters
            debug_text += "\nCHAIN KEYS & COUNTERS:\n"
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'send_chain_key') and self.client.protocol.send_chain_key:
                debug_text += f"  Send Chain Key: {self.client.protocol.send_chain_key[:16].hex()}...\n"
            else:
                debug_text += "  Send Chain Key: Not initialized\n"
                
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'receive_chain_key') and self.client.protocol.receive_chain_key:
                debug_text += f"  Receive Chain Key: {self.client.protocol.receive_chain_key[:16].hex()}...\n"
            else:
                debug_text += "  Receive Chain Key: Not initialized\n"
                
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'message_counter'):
                debug_text += f"  Message Counter (Out): {self.client.protocol.message_counter}\n"
            else:
                debug_text += "  Message Counter (Out): 0\n"
                
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'peer_counter'):
                debug_text += f"  Peer Counter (In): {self.client.protocol.peer_counter}\n"
            else:
                debug_text += "  Peer Counter (In): 0\n"
            
            # Public Keys
            debug_text += "\nPUBLIC KEYS:\n"
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'own_public_key') and self.client.protocol.own_public_key:
                debug_text += f"  Own Public Key: {self.client.protocol.own_public_key[:16].hex()}...\n"
            else:
                debug_text += "  Own Public Key: Not generated\n"
                
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'peer_public_key') and self.client.protocol.peer_public_key:
                debug_text += f"  Peer Public Key: {self.client.protocol.peer_public_key[:16].hex()}...\n"
            else:
                debug_text += "  Peer Public Key: Not received\n"
            
            # Key Verification
            debug_text += "\nKEY VERIFICATION:\n"
            if hasattr(self.client, 'protocol') and hasattr(self.client.protocol, 'peer_key_verified'):
                if self.client.protocol.peer_key_verified:
                    debug_text += "  ✓ Peer Key Verified\n"
                else:
                    debug_text += "  ⚠ Peer Key Not Verified\n"
            else:
                debug_text += "  ⚠ Verification Status Unknown\n"
            
            # Connection Status
            debug_text += "\nCONNECTION STATUS:\n"
            debug_text += f"  Connected: {'Yes' if self.connected else 'No'}\n"
            if hasattr(self.client, 'socket') and self.client.socket:
                debug_text += "  Socket: Active\n"
            else:
                debug_text += "  Socket: Inactive\n"
            
            # Keepalive Status
            debug_text += "\nKEEPALIVE STATUS:\n"
            if hasattr(self.client, 'last_keepalive_received') and self.client.last_keepalive_received:
                last_received = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_received))
                debug_text += f"  Last Keepalive Received: {last_received}\n"
            else:
                debug_text += "  Last Keepalive Received: None\n"
                
            if hasattr(self.client, 'last_keepalive_sent') and self.client.last_keepalive_sent:
                last_sent = time.strftime('%H:%M:%S', time.localtime(self.client.last_keepalive_sent))
                debug_text += f"  Last Keepalive Sent: {last_sent}\n"
            else:
                debug_text += "  Last Keepalive Sent: None\n"
                
            if hasattr(self.client, 'respond_to_keepalive'):
                status = "Enabled" if self.client.respond_to_keepalive else "Disabled"
                debug_text += f"  Keepalive Responses: {status}\n"
            else:
                debug_text += "  Keepalive Responses: Unknown\n"
            
            debug_text += "\n" + "="*50 + "\n";
            
            # Update the debug display
            self.debug_display.config(state=tk.NORMAL)  # type: ignore
            self.debug_display.delete(1.0, tk.END)
            self.debug_display.insert(tk.END, debug_text)
            self.debug_display.see(tk.END)
            self.debug_display.config(state=tk.DISABLED)  # type: ignore
            
        except Exception as e:
            # Fallback debug info if there's an error
            error_text = f"Debug Info Error: {e}\n"
            error_text += f"Client exists: {hasattr(self, 'client')}\n"
            error_text += f"Connected: {self.connected}\n"
            
            self.debug_display.config(state=tk.NORMAL)  # type: ignore
            self.debug_display.delete(1.0, tk.END)
            self.debug_display.insert(tk.END, error_text)
            self.debug_display.config(state=tk.DISABLED)  # type: ignore
    
    def toggle_connection(self):
        """Toggle connection to the server."""
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()
    
    def connect_to_server(self):
        """Connect to the chat server."""
        try:
            host = self.host_entry.get().strip() or "localhost"
            port = int(self.port_entry.get().strip() or "16384")
            
            self.update_status("Connecting...", "#ffa500")  # Orange for connecting
            
            # Create client instance
            self.client = GUISecureChatClient(host, port, gui=self)
            
            # Start connection in a separate thread
            def connect_thread():
                try:
                    if self.client.connect():
                        self.connected = True
                        self.root.after(0, self.on_connected)
                        self.start_chat_monitoring()
                    else:
                        self.root.after(0, lambda: self.append_to_chat("Failed to connect to server"))
                        self.root.after(0, lambda: self.update_status("Not Connected", "#ff6b6b"))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.append_to_chat(f"Connection error: {e}"))
                    self.root.after(0, lambda: self.update_status("Not Connected", "#ff6b6b"))
            
            threading.Thread(target=connect_thread, daemon=True).start()
        
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            self.update_status("Not Connected", "#ff6b6b")
        except Exception as e:
            self.append_to_chat(f"Connection error: {e}")
            self.update_status("Not Connected", "#ff6b6b")
    
    def on_connected(self):
        """Called when successfully connected."""
        self.connected = True
        self.connect_btn.config(text="Disconnect")
        self.host_entry.config(state=tk.DISABLED)  # type: ignore
        self.port_entry.config(state=tk.DISABLED)  # type: ignore
        self.message_entry.config(state=tk.NORMAL)  # type: ignore
        self.send_btn.config(state=tk.NORMAL)  # type: ignore
        self.send_file_btn.config(state=tk.NORMAL)  # type: ignore
        self.ephemeral_btn.config(state=tk.NORMAL)  # type: ignore
        self.file_transfer_btn.config(state=tk.NORMAL)  # type: ignore
        
        # Enable debug action buttons
        self.keepalive_toggle_btn.config(state=tk.NORMAL)
        self.malformed_msg_btn.config(state=tk.NORMAL)
        self.set_chain_keys_btn.config(state=tk.NORMAL)
        self.force_disconnect_btn.config(state=tk.NORMAL)
        self.force_key_reset_btn.config(state=tk.NORMAL)
        self.view_fingerprints_btn.config(state=tk.NORMAL)
        self.simulate_latency_btn.config(state=tk.NORMAL)
        # Enable new debug buttons
        self.stale_msg_btn.config(state=tk.NORMAL)
        self.packet_loss_btn.config(state=tk.NORMAL)
        self.duplicate_msg_btn.config(state=tk.NORMAL)
        self.set_counter_btn.config(state=tk.NORMAL)
        self.test_protocol_btn.config(state=tk.NORMAL)
        
        self.message_entry.focus()
        self.update_status("Connected, waiting for other client", "#ffff00")  # Yellow for waiting
        
        # Update debug info after connection
        self.update_debug_info()
    
    def disconnect_from_server(self):
        """Disconnect from the server."""
        if self.client:
            self.client.disconnect()
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.host_entry.config(state=tk.NORMAL)  # type: ignore
        self.port_entry.config(state=tk.NORMAL)  # type: ignore
        self.message_entry.config(state=tk.DISABLED)  # type: ignore
        self.send_btn.config(state=tk.DISABLED)  # type: ignore
        self.send_file_btn.config(state=tk.DISABLED)  # type: ignore
        self.ephemeral_btn.config(state=tk.DISABLED)  # type: ignore
        self.file_transfer_btn.config(state=tk.DISABLED)  # type: ignore
        
        # Disable debug action buttons
        self.keepalive_toggle_btn.config(state=tk.DISABLED)
        self.malformed_msg_btn.config(state=tk.DISABLED)
        self.set_chain_keys_btn.config(state=tk.DISABLED)
        self.force_disconnect_btn.config(state=tk.DISABLED)
        self.force_key_reset_btn.config(state=tk.DISABLED)
        self.view_fingerprints_btn.config(state=tk.DISABLED)
        self.simulate_latency_btn.config(state=tk.DISABLED)
        # Disable new debug buttons
        self.stale_msg_btn.config(state=tk.DISABLED)
        self.packet_loss_btn.config(state=tk.DISABLED)
        self.duplicate_msg_btn.config(state=tk.DISABLED)
        self.set_counter_btn.config(state=tk.DISABLED)
        self.test_protocol_btn.config(state=tk.DISABLED)
        
        self.append_to_chat("Disconnected from server.")
        self.update_status("Not Connected", "#ff6b6b")
        
        # Update debug info after disconnection
        self.update_debug_info()
        
        sys.exit(0)  # Exit the application
    
    def start_chat_monitoring(self):
        """Start monitoring the chat client for messages and status updates."""
        
        def monitor_thread():
            try:
                while self.connected and self.client and self.client.connected:
                    # Check if key exchange is complete and verification is needed
                    if (hasattr(self.client, 'key_exchange_complete') and
                            self.client.key_exchange_complete and
                            not hasattr(self.client, 'verification_started')):
                        # Mark that we've started verification to avoid repeated prompts
                        self.client.verification_started = True
                        
                        # Show verification dialogue
                        self.root.after(0, self.show_verification_dialog)
                    
                    # Update debug info regularly if debug box is visible
                    if self.debug_visible:
                        self.root.after(0, self.update_debug_info)
                    
                    
                    time.sleep(0.5)  # Update every 500ms for better responsiveness
            
            except Exception as e:
                self.root.after(0, lambda: self.append_to_chat(f"Monitor error: {e}"))
        
        threading.Thread(target=monitor_thread, daemon=True).start()
    
    def show_verification_dialog(self):
        """Show the key verification dialogue."""
        if not self.client or not hasattr(self.client, 'protocol'):
            return
        
        # Update status to show we're now verifying the fingerprint
        self.update_status("Verifying fingerprint", "#ffa500")  # Orange for verifying
        
        try:
            fingerprint = self.client.protocol.get_own_key_fingerprint()
            
            dialog_text = f"""Key Exchange Complete!

{fingerprint}

INSTRUCTIONS:
1. Compare the fingerprint above with the other person through a
   separate secure channel (phone call, in person, etc.)
2. If the fingerprints match exactly, click 'Verify'
3. If they don't match or you're unsure, click 'Don't Verify'

Do the fingerprints match?"""
            
            result = messagebox.askyesno("Key Verification", dialog_text)
            
            # Send verification result
            self.client.confirm_key_verification(result)
            
            if result:
                self.append_to_chat("You verified the peer's key.")
                self.update_status("Verified, Secure", "#00ff00")  # Green for verified
            else:
                self.append_to_chat("You did not verify the peer's key.")
                self.update_status("Not Verified, Secure", "#ffff00")  # Yellow for not verified but secure
            
            self.append_to_chat("You can now send messages!")
        
        except Exception as e:
            self.append_to_chat(f"Verification error: {e}")
    
    def send_message(self, event=None):
        """Send a message."""
        if not self.connected or not self.client:
            return
        
        # Check if verification is complete (like console client does)
        if not hasattr(self.client, 'verification_complete') or not self.client.verification_complete:
            self.append_to_chat("Cannot send messages - verification not complete")
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        # Handle special commands
        if message.lower() == '/quit':
            self.disconnect_from_server()
            return
        elif message.lower() == '/verify':
            self.show_verification_dialog()
            self.message_entry.delete(0, tk.END)
            return
        
        # Send the message
        try:
            if self.client.send_message(message):
                # Display the sent message with ephemeral tracking
                if hasattr(self.client, 'protocol') and self.client.protocol.is_peer_key_verified():
                    self.append_to_chat(f"You: {message}", is_message=True)
                else:
                    self.append_to_chat(f"You (unverified): {message}", is_message=True)
                
                # Update debug info after message encryption
                self.update_debug_info()
            else:
                self.append_to_chat("Failed to send message")
        
        except Exception as e:
            self.append_to_chat(f"Send error: {e}")
        
        self.message_entry.delete(0, tk.END)
    def send_file(self):
        """Send a file using file dialog."""
        if not self.connected or not self.client:
            return
        
        # Check if verification is complete
        if not hasattr(self.client, 'verification_complete') or not self.client.verification_complete:
            self.append_to_chat("Cannot send files - verification not complete")
            return
        
        try:
            # Open file dialog
            file_path = filedialog.askopenfilename(
                    title="Select file to send",
                    filetypes=[("All files", "*.*")]
            )
            
            if file_path:
                # Get file info
                file_size = os.path.getsize(file_path)
                file_name = os.path.basename(file_path)
                
                # Confirm file sending
                result = messagebox.askyesno(
                        "Send File",
                        f"Send file '{file_name}' ({bytes_to_human_readable(file_size)})?"
                )
                
                if result:
                    self.append_to_chat(f"Sending file: {file_name}")
                    self.client.send_file(file_path)
        
        except Exception as e:
            self.append_to_chat(f"File send error: {e}")
    
    def on_key_press(self, event):
        """Handle key press events in message entry."""
        # Allow normal typing when connected
        pass
    
    def on_closing(self):
        """Handle window closing."""
        if self.connected:
            self.disconnect_from_server()
        self.root.destroy()
    
    def start_ephemeral_cleanup(self):
        """Start the background thread to clean up ephemeral messages."""
        
        def cleanup_thread():
            
            while True:
                try:
                    if self.ephemeral_mode and self.ephemeral_messages:
                        current_time = time.time()
                        # Find messages older than 30 seconds
                        expired_message_ids = []
                        for message_id, timestamp in self.ephemeral_messages.items():
                            if current_time - timestamp >= 30.0:
                                expired_message_ids.append(message_id)
                        
                        # Remove expired messages
                        if expired_message_ids:
                            self.root.after(0, lambda: self.remove_ephemeral_messages(expired_message_ids))
                    
                    time.sleep(1.0)  # Check every second
                except Exception as e:
                    # Silently continue on errors to avoid breaking the cleanup thread
                    pass
        
        threading.Thread(target=cleanup_thread, daemon=True).start()
    
    def toggle_ephemeral_mode(self):
        """Toggle ephemeral mode on/off."""
        self.ephemeral_mode = not self.ephemeral_mode
        
        if self.ephemeral_mode:
            # Enable ephemeral mode
            self.ephemeral_btn.config(bg="#ff6b6b", fg="#ffffff", text="⏱️ Ephemeral ON")  # type: ignore
            self.append_to_chat("🔥 Ephemeral mode enabled - messages will disappear after 30 seconds", is_message=True)
        else:
            # Disable ephemeral mode
            self.ephemeral_btn.config(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, text="⏱️ Ephemeral")  # type: ignore
            # Clear all ephemeral messages
            self.ephemeral_messages.clear()
    
    def remove_ephemeral_messages(self, message_ids):
        """Remove ephemeral messages from the chat display."""
        try:
            # Get all chat content
            self.chat_display.config(state=tk.NORMAL)  # type: ignore
            content = self.chat_display.get("1.0", tk.END)
            lines = content.split('\n')
            
            # Remove expired messages (they're tagged with message IDs in comments)
            filtered_lines = []
            for line in lines:
                should_keep = True
                for message_id in message_ids:
                    if f"<!-- {message_id} -->" in line:
                        should_keep = False
                        break
                # Only keep non-empty lines to eliminate gaps
                if should_keep and line.strip():
                    filtered_lines.append(line)
            
            # Update chat display with no gaps
            self.chat_display.delete("1.0", tk.END)
            if filtered_lines:
                self.chat_display.insert("1.0", '\n'.join(filtered_lines) + '\n')
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)  # type: ignore
            
            # Remove from tracking dict
            for message_id in message_ids:
                self.ephemeral_messages.pop(message_id, None)
        
        except Exception as e:
            # If removal fails, just clean up the tracking dict
            for message_id in message_ids:
                self.ephemeral_messages.pop(message_id, None)
    
    def toggle_keepalive_responses(self):
        """Toggle whether the client responds to keepalive messages."""
        if not hasattr(self, 'client') or not self.client:
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
    
    def send_malformed_message(self):
        """Send a malformed message to test error handling."""
        if not hasattr(self, 'client') or not self.client or not self.client.socket:
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
        if not hasattr(self, 'client') or not self.client or not hasattr(self.client, 'protocol'):
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
            tk.Label(dialog, text="Send Chain Key (hex):", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(anchor=tk.W, padx=10, pady=(10, 0))
            send_key_entry = tk.Entry(dialog, width=50, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            send_key_entry.pack(fill=tk.X, padx=10, pady=5)
            
            # Receive chain key input
            tk.Label(dialog, text="Receive Chain Key (hex):", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(anchor=tk.W, padx=10, pady=(10, 0))
            receive_key_entry = tk.Entry(dialog, width=50, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            receive_key_entry.pack(fill=tk.X, padx=10, pady=5)
            
            # Pre-fill with current values if available
            if hasattr(self.client.protocol, 'send_chain_key') and self.client.protocol.send_chain_key:
                send_key_entry.insert(0, self.client.protocol.send_chain_key.hex())
            if hasattr(self.client.protocol, 'receive_chain_key') and self.client.protocol.receive_chain_key:
                receive_key_entry.insert(0, self.client.protocol.receive_chain_key.hex())
            
            # Warning label
            warning_label = tk.Label(
                dialog, 
                text="WARNING: Setting custom chain keys will break the security of the connection.\nOnly use for debugging!",
                bg=self.BG_COLOR, 
                fg="#ff6b6b",
                justify=tk.LEFT
            )
            warning_label.pack(fill=tk.X, padx=10, pady=10)
            
            # Buttons frame
            buttons_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            buttons_frame.pack(fill=tk.X, padx=10, pady=10)
            
            def apply_keys():
                try:
                    # Get values from entries
                    send_key_hex = send_key_entry.get().strip()
                    receive_key_hex = receive_key_entry.get().strip()
                    
                    # Convert hex to bytes
                    if send_key_hex:
                        self.client.protocol.send_chain_key = bytes.fromhex(send_key_hex)
                    if receive_key_hex:
                        self.client.protocol.receive_chain_key = bytes.fromhex(receive_key_hex)
                    
                    self.append_to_chat("Custom chain keys applied")
                    self.update_debug_info()
                    dialog.destroy()
                except Exception as e:
                    tk.messagebox.showerror("Error", f"Invalid hex values: {e}")
            
            # Apply button
            apply_btn = tk.Button(
                buttons_frame, 
                text="Apply", 
                command=apply_keys,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR
            )
            apply_btn.pack(side=tk.RIGHT, padx=5)
            
            # Cancel button
            cancel_btn = tk.Button(
                buttons_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR
            )
            cancel_btn.pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error setting chain keys: {e}")
    
    def force_disconnect(self):
        """Forcefully kill the connection without proper shutdown."""
        if not hasattr(self, 'client') or not self.client or not self.client.socket:
            return
            
        try:
            # Ask for confirmation
            if not tk.messagebox.askyesno("Confirm", "Are you sure you want to forcefully kill the connection?\nThis will not perform a clean disconnect."):
                return
                
            # Close the socket directly without proper shutdown
            self.client.socket.close()
            
            # Update UI
            self.connected = False
            self.connect_btn.config(text="Connect")
            self.host_entry.config(state=tk.NORMAL)  # type: ignore
            self.port_entry.config(state=tk.NORMAL)  # type: ignore
            self.message_entry.config(state=tk.DISABLED)  # type: ignore
            self.send_btn.config(state=tk.DISABLED)  # type: ignore
            self.send_file_btn.config(state=tk.DISABLED)  # type: ignore
            self.ephemeral_btn.config(state=tk.DISABLED)  # type: ignore
            self.file_transfer_btn.config(state=tk.DISABLED)  # type: ignore
            
            # Disable debug action buttons
            self.keepalive_toggle_btn.config(state=tk.DISABLED)
            self.malformed_msg_btn.config(state=tk.DISABLED)
            self.set_chain_keys_btn.config(state=tk.DISABLED)
            self.force_disconnect_btn.config(state=tk.DISABLED)
            self.force_key_reset_btn.config(state=tk.DISABLED)
            self.view_fingerprints_btn.config(state=tk.DISABLED)
            self.simulate_latency_btn.config(state=tk.DISABLED)
            
            self.append_to_chat("Connection forcefully killed")
            self.update_status("Not Connected", "#ff6b6b")
            
            # Update debug info
            self.update_debug_info()
            
        except Exception as e:
            self.append_to_chat(f"Error forcing disconnect: {e}")
    
    def force_key_reset(self):
        """Force a key exchange reset."""
        if not hasattr(self, 'client') or not self.client:
            return
            
        try:
            # Ask for confirmation
            if not tk.messagebox.askyesno("Confirm", "Are you sure you want to force a key exchange reset?"):
                return
                
            # Create a reset message and send it
            self.append_to_chat("Forcing key exchange reset...")
            
            # Reset the protocol state
            if hasattr(self.client, 'protocol'):
                self.client.protocol.reset_key_exchange()
                
            # Send a key exchange reset message
            if hasattr(self.client, 'socket') and self.client.socket:
                reset_message = json.dumps({"type": MSG_TYPE_KEY_EXCHANGE_RESET}).encode('utf-8')
                send_message(self.client.socket, reset_message)
                
            self.append_to_chat("Key exchange reset initiated")
            self.update_status("Key exchange reset", "#ffa500")  # Orange for reset
            
            # Update debug info
            self.update_debug_info()
            
        except Exception as e:
            self.append_to_chat(f"Error forcing key reset: {e}")
    
    def view_key_fingerprints(self):
        """Display key fingerprints."""
        if not hasattr(self, 'client') or not self.client or not hasattr(self.client, 'protocol'):
            return
            
        try:
            # Create a dialog to display fingerprints
            dialog = tk.Toplevel(self.root)
            dialog.title("Key Fingerprints")
            dialog.geometry("600x400")
            dialog.configure(bg=self.BG_COLOR)
            
            # Make dialog modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add a label
            tk.Label(
                dialog, 
                text="Key Fingerprints", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 12, "bold")
            ).pack(pady=10)
            
            # Create a frame for the fingerprints
            fingerprint_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            fingerprint_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            # Own key fingerprint
            tk.Label(
                fingerprint_frame, 
                text="Your Key Fingerprint:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10, "bold"),
                anchor="w"
            ).pack(fill=tk.X, pady=(10, 5))
            
            own_fingerprint = "Not available"
            if hasattr(self.client.protocol, 'get_own_key_fingerprint'):
                own_fingerprint = self.client.protocol.get_own_key_fingerprint() or "Not available"
                
            own_fingerprint_text = scrolledtext.ScrolledText(
                fingerprint_frame,
                height=5,
                font=("Consolas", 10),
                bg="#2d2d2d",
                fg="#00ff00",
                wrap=tk.WORD
            )
            own_fingerprint_text.pack(fill=tk.X, pady=(0, 10))
            own_fingerprint_text.insert(tk.END, own_fingerprint)
            own_fingerprint_text.config(state=tk.DISABLED)
            
            # Peer key fingerprint
            tk.Label(
                fingerprint_frame, 
                text="Peer Key Fingerprint:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10, "bold"),
                anchor="w"
            ).pack(fill=tk.X, pady=(10, 5))
            
            peer_fingerprint = "Not available"
            if hasattr(self.client.protocol, 'get_peer_key_fingerprint'):
                peer_fingerprint = self.client.protocol.get_peer_key_fingerprint() or "Not available"
                
            peer_fingerprint_text = scrolledtext.ScrolledText(
                fingerprint_frame,
                height=5,
                font=("Consolas", 10),
                bg="#2d2d2d",
                fg="#00ff00",
                wrap=tk.WORD
            )
            peer_fingerprint_text.pack(fill=tk.X, pady=(0, 10))
            peer_fingerprint_text.insert(tk.END, peer_fingerprint)
            peer_fingerprint_text.config(state=tk.DISABLED)
            
            # Session fingerprint
            tk.Label(
                fingerprint_frame, 
                text="Session Fingerprint:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10, "bold"),
                anchor="w"
            ).pack(fill=tk.X, pady=(10, 5))
            
            session_fingerprint = "Not available"
            if hasattr(self.client.protocol, 'generate_session_fingerprint'):
                session_fingerprint = self.client.protocol.generate_session_fingerprint() or "Not available"
                
            session_fingerprint_text = scrolledtext.ScrolledText(
                fingerprint_frame,
                height=5,
                font=("Consolas", 10),
                bg="#2d2d2d",
                fg="#00ff00",
                wrap=tk.WORD
            )
            session_fingerprint_text.pack(fill=tk.X, pady=(0, 10))
            session_fingerprint_text.insert(tk.END, session_fingerprint)
            session_fingerprint_text.config(state=tk.DISABLED)
            
            # Close button
            tk.Button(
                dialog, 
                text="Close", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(pady=10)
            
        except Exception as e:
            self.append_to_chat(f"Error viewing key fingerprints: {e}")
    
    def simulate_network_latency(self):
        """Simulate network latency."""
        if not hasattr(self, 'client') or not self.client:
            return
            
        try:
            # Create a dialog to configure latency
            dialog = tk.Toplevel(self.root)
            dialog.title("Simulate Network Latency")
            dialog.geometry("400x200")
            dialog.configure(bg=self.BG_COLOR)
            
            # Make dialog modal
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add a label
            tk.Label(
                dialog, 
                text="Simulate Network Latency", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 12, "bold")
            ).pack(pady=10)
            
            # Create a frame for the latency settings
            latency_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            latency_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            # Latency slider
            tk.Label(
                latency_frame, 
                text="Latency (ms):", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, pady=(10, 5))
            
            latency_var = tk.IntVar(value=100)  # Default 100ms
            latency_slider = tk.Scale(
                latency_frame,
                from_=0,
                to=2000,
                orient=tk.HORIZONTAL,
                variable=latency_var,
                bg=self.BG_COLOR,
                fg=self.FG_COLOR,
                highlightthickness=0,
                troughcolor="#2d2d2d"
            )
            latency_slider.pack(fill=tk.X, pady=(0, 10))
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10)
            
            # Apply button
            def apply_latency():
                latency = latency_var.get()
                self.append_to_chat(f"Simulating {latency}ms network latency for the next message")
                
                # Store the latency value in the client for use when sending the next message
                self.client.simulated_latency = latency
                
                # Close the dialog
                dialog.destroy()
            
            tk.Button(
                button_frame, 
                text="Apply", 
                command=apply_latency,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                button_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error simulating network latency: {e}")
    
    def send_stale_message(self):
        """Send a stale message (with an old counter value) to test replay protection."""
        if not hasattr(self, 'client') or not self.client or not self.client.socket:
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
            tk.Label(
                dialog, 
                text="Message:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5))
            
            message_entry = tk.Entry(
                dialog,
                width=40,
                bg=self.ENTRY_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
            message_entry.insert(0, "This is a stale message")
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10)
            
            # Send button
            def send_stale():
                message_text = message_entry.get().strip()
                if not message_text:
                    tk.messagebox.showerror("Error", "Please enter a message")
                    return
                
                # Store the current message counter
                current_counter = self.client.protocol.message_counter
                
                # Set the counter to a lower value to make the message stale
                self.client.protocol.message_counter = max(0, current_counter - 10)
                
                # Create the encrypted message
                try:
                    encrypted_data = self.client.protocol.encrypt_message(message_text)
                    
                    # Send the message directly to the socket
                    send_message(self.client.socket, encrypted_data)
                    
                    self.append_to_chat(f"Sent stale message with counter {self.client.protocol.message_counter} (current: {current_counter})")
                    
                    # Restore the original counter
                    self.client.protocol.message_counter = current_counter
                    
                except Exception as e:
                    self.append_to_chat(f"Error sending stale message: {e}")
                
                dialog.destroy()
            
            tk.Button(
                button_frame, 
                text="Send", 
                command=send_stale,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                button_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error creating stale message dialog: {e}")
    
    def simulate_packet_loss(self):
        """Simulate packet loss by randomly dropping messages."""
        if not hasattr(self, 'client') or not self.client:
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
            loss_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            
            # Packet loss percentage slider
            tk.Label(
                loss_frame, 
                text="Packet Loss Percentage:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, pady=(10, 5))
            
            loss_var = tk.IntVar(value=25)  # Default 25%
            loss_slider = tk.Scale(
                loss_frame,
                from_=0,
                to=100,
                orient=tk.HORIZONTAL,
                variable=loss_var,
                bg=self.BG_COLOR,
                fg=self.FG_COLOR,
                highlightthickness=0,
                troughcolor="#2d2d2d"
            )
            loss_slider.pack(fill=tk.X, pady=(0, 10))
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10)
            
            # Apply button
            def apply_packet_loss():
                loss_percentage = loss_var.get()
                
                if loss_percentage == 0:
                    # Disable packet loss simulation
                    if hasattr(self.client, 'packet_loss_percentage'):
                        delattr(self.client, 'packet_loss_percentage')
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
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                button_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error simulating packet loss: {e}")
    
    def send_duplicate_message(self):
        """Send the same message multiple times to test duplicate detection."""
        if not hasattr(self, 'client') or not self.client or not self.client.socket:
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
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5))
            
            message_entry = tk.Entry(
                dialog,
                width=40,
                bg=self.ENTRY_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
            message_entry.insert(0, "This is a duplicate message")
            
            # Count input
            tk.Label(
                dialog, 
                text="Number of duplicates:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5))
            
            count_var = tk.IntVar(value=3)  # Default 3 duplicates
            count_slider = tk.Scale(
                dialog,
                from_=2,
                to=10,
                orient=tk.HORIZONTAL,
                variable=count_var,
                bg=self.BG_COLOR,
                fg=self.FG_COLOR,
                highlightthickness=0,
                troughcolor="#2d2d2d"
            )
            count_slider.pack(fill=tk.X, padx=20, pady=(0, 10))
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10)
            
            # Send button
            def send_duplicates():
                message_text = message_entry.get().strip()
                count = count_var.get()
                
                if not message_text:
                    tk.messagebox.showerror("Error", "Please enter a message")
                    return
                
                # Create the encrypted message
                try:
                    encrypted_data = self.client.protocol.encrypt_message(message_text)
                    
                    # Send the message multiple times
                    for i in range(count):
                        send_message(self.client.socket, encrypted_data)
                        self.append_to_chat(f"Sent duplicate {i+1}/{count}: {message_text}")
                    
                except Exception as e:
                    self.append_to_chat(f"Error sending duplicate messages: {e}")
                
                dialog.destroy()
            
            tk.Button(
                button_frame, 
                text="Send", 
                command=send_duplicates,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                button_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error creating duplicate message dialog: {e}")
    
    def set_message_counter(self):
        """Set the message counter to a specific value."""
        if not hasattr(self, 'client') or not self.client or not hasattr(self.client, 'protocol'):
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
            ).pack(fill=tk.X, padx=20, pady=(20, 5))
            
            send_counter_entry = tk.Entry(
                dialog,
                width=20,
                bg=self.ENTRY_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR
            )
            send_counter_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
            
            # Pre-fill with current value if available
            if hasattr(self.client.protocol, 'message_counter'):
                send_counter_entry.insert(0, str(self.client.protocol.message_counter))
            
            # Peer counter input
            tk.Label(
                dialog, 
                text="Peer Counter:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5))
            
            peer_counter_entry = tk.Entry(
                dialog,
                width=20,
                bg=self.ENTRY_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR
            )
            peer_counter_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
            
            # Pre-fill with current value if available
            if hasattr(self.client.protocol, 'peer_counter'):
                peer_counter_entry.insert(0, str(self.client.protocol.peer_counter))
            
            # Warning label
            warning_label = tk.Label(
                dialog, 
                text="WARNING: Setting custom counters may break message encryption.\nOnly use for debugging!",
                bg=self.BG_COLOR, 
                fg="#ff6b6b",
                justify=tk.LEFT
            )
            warning_label.pack(fill=tk.X, padx=20, pady=10)
            
            # Buttons frame
            buttons_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            buttons_frame.pack(fill=tk.X, padx=20, pady=10)
            
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
                    tk.messagebox.showerror("Error", "Please enter valid integer values")
                except Exception as e:
                    tk.messagebox.showerror("Error", f"Failed to set counters: {e}")
            
            # Apply button
            apply_btn = tk.Button(
                buttons_frame, 
                text="Apply", 
                command=apply_counters,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            )
            apply_btn.pack(side=tk.LEFT, padx=5)
            
            # Cancel button
            cancel_btn = tk.Button(
                buttons_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            )
            cancel_btn.pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error setting message counters: {e}")
    
    def test_protocol_version(self):
        """Test protocol version compatibility by sending messages with different versions."""
        if not hasattr(self, 'client') or not self.client or not self.client.socket:
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
            ).pack(fill=tk.X, padx=20, pady=(10, 5))
            
            message_entry = tk.Entry(
                dialog,
                width=40,
                bg=self.ENTRY_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR
            )
            message_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
            message_entry.insert(0, "Testing protocol version compatibility")
            
            # Version input
            tk.Label(
                dialog, 
                text="Protocol Version:", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 10),
                anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(10, 5))
            
            # Get the current protocol version
            current_version = PROTOCOL_VERSION
            
            version_entry = tk.Entry(
                dialog,
                width=10,
                bg=self.ENTRY_BG_COLOR,
                fg=self.FG_COLOR,
                insertbackground=self.FG_COLOR
            )
            version_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
            version_entry.insert(0, str(current_version - 1))  # Default to previous version
            
            # Current version label
            tk.Label(
                dialog, 
                text=f"Current version: {current_version}", 
                bg=self.BG_COLOR, 
                fg=self.FG_COLOR,
                font=("Consolas", 9),
                anchor="w"
            ).pack(fill=tk.X, padx=20, pady=(0, 10))
            
            # Button frame
            button_frame = tk.Frame(dialog, bg=self.BG_COLOR)
            button_frame.pack(fill=tk.X, pady=10)
            
            # Send button
            def send_with_version():
                message_text = message_entry.get().strip()
                try:
                    version = int(version_entry.get().strip())
                except ValueError:
                    tk.messagebox.showerror("Error", "Please enter a valid version number")
                    return
                
                if not message_text:
                    tk.messagebox.showerror("Error", "Please enter a message")
                    return
                
                # Create a message with the specified version
                try:
                    # Store the current protocol version
                    original_version = PROTOCOL_VERSION
                    
                    # Create a custom message with the specified version
                    encrypted_data = self.client.protocol.encrypt_message(message_text)
                    
                    # Decode the message to modify the version
                    message_dict = json.loads(encrypted_data.decode('utf-8'))
                    message_dict["version"] = version
                    
                    # Re-encode the message
                    modified_data = json.dumps(message_dict).encode('utf-8')
                    
                    # Send the modified message
                    send_message(self.client.socket, modified_data)
                    
                    self.append_to_chat(f"Sent message with protocol version {version} (current: {original_version})")
                    
                except Exception as e:
                    self.append_to_chat(f"Error sending message with custom version: {e}")
                
                dialog.destroy()
            
            tk.Button(
                button_frame, 
                text="Send", 
                command=send_with_version,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.LEFT, padx=5)
            
            # Cancel button
            tk.Button(
                button_frame, 
                text="Cancel", 
                command=dialog.destroy,
                bg=self.BUTTON_BG_COLOR, 
                fg=self.FG_COLOR,
                relief=tk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, 
                activeforeground=self.FG_COLOR
            ).pack(side=tk.RIGHT, padx=5)
            
        except Exception as e:
            self.append_to_chat(f"Error testing protocol version: {e}")
    
    def export_debug_log(self):
        """Export debug log to a file."""
        try:
            # Ask for a file to save to
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Debug Log"
            )
            
            if not file_path:
                return  # User cancelled
                
            # Get the debug info
            debug_info = ""
            
            # Add connection info
            debug_info += "=== CONNECTION INFO ===\n"
            if hasattr(self, 'client') and self.client:
                debug_info += f"Connected: {self.connected}\n"
                debug_info += f"Host: {self.client.host}\n"
                debug_info += f"Port: {self.client.port}\n"
                
                if hasattr(self.client, 'protocol_version'):
                    debug_info += f"Protocol Version: {self.client.protocol_version}\n"
                if hasattr(self.client, 'server_version'):
                    debug_info += f"Server Version: {self.client.server_version or 'Unknown'}\n"
                if hasattr(self.client, 'peer_version'):
                    debug_info += f"Peer Version: {self.client.peer_version or 'Unknown'}\n"
            else:
                debug_info += "Not connected\n"
                
            # Add protocol info
            debug_info += "\n=== PROTOCOL INFO ===\n"
            if hasattr(self, 'client') and self.client and hasattr(self.client, 'protocol'):
                protocol = self.client.protocol
                
                # Key exchange status
                debug_info += f"Key Exchange Complete: {hasattr(self.client, 'key_exchange_complete') and self.client.key_exchange_complete}\n"
                debug_info += f"Verification Complete: {hasattr(self.client, 'verification_complete') and self.client.verification_complete}\n"
                
                # Chain keys
                if hasattr(protocol, 'send_chain_key'):
                    debug_info += f"Send Chain Key: {protocol.send_chain_key.hex() if protocol.send_chain_key else 'None'}\n"
                if hasattr(protocol, 'recv_chain_key'):
                    debug_info += f"Receive Chain Key: {protocol.recv_chain_key.hex() if protocol.recv_chain_key else 'None'}\n"
                if hasattr(protocol, 'send_counter'):
                    debug_info += f"Send Counter: {protocol.send_counter}\n"
                if hasattr(protocol, 'recv_counter'):
                    debug_info += f"Receive Counter: {protocol.recv_counter}\n"
            else:
                debug_info += "No protocol information available\n"
                
            # Add keepalive info
            debug_info += "\n=== KEEPALIVE INFO ===\n"
            if hasattr(self, 'client') and self.client:
                if hasattr(self.client, 'last_keepalive_sent'):
                    last_sent = self.client.last_keepalive_sent
                    debug_info += f"Last Keepalive Sent: {last_sent if last_sent else 'None'}\n"
                if hasattr(self.client, 'last_keepalive_received'):
                    last_received = self.client.last_keepalive_received
                    debug_info += f"Last Keepalive Received: {last_received if last_received else 'None'}\n"
                if hasattr(self.client, 'respond_to_keepalive'):
                    debug_info += f"Respond to Keepalive: {self.client.respond_to_keepalive}\n"
            else:
                debug_info += "No keepalive information available\n"
                
            # Add chat history
            debug_info += "\n=== CHAT HISTORY ===\n"
            chat_text = self.chat_display.get("1.0", tk.END)
            debug_info += chat_text
            
            # Write to file
            with open(file_path, 'w') as f:
                f.write(debug_info)
                
            self.append_to_chat(f"Debug log exported to {file_path}")
            
        except Exception as e:
            self.append_to_chat(f"Error exporting debug log: {e}")


class GUISecureChatClient(SecureChatClient):
    """Extended SecureChatClient that works with GUI."""
    
    def __init__(self, host='localhost', port=16384, gui=None):
        super().__init__(host, port)
        self.gui = gui
        # Initialize verification_complete flag like console client
        self.verification_complete = False
        
        # Protocol version tracking
        self.protocol_version = PROTOCOL_VERSION
        self.server_version = None  # Will be set when we receive server info
        self.peer_version = None    # Will be set during key exchange
        
        # Keepalive tracking
        self.last_keepalive_received = None
        self.last_keepalive_sent = None
        self.respond_to_keepalive = True  # Flag to control whether to respond to keepalives
        
        # Socket lock for thread synchronization
        self.socket_lock = threading.Lock()
        
        # Debug features
        self.simulated_latency = 0  # No latency by default
        
    def handle_key_exchange_init(self, message_data: bytes):
        """Handle key exchange init - override to extract and store protocol version."""
        try:
            # Extract protocol version from message
            message = json.loads(message_data.decode('utf-8'))
            self.peer_version = message.get("version")
            
            # Call parent method to handle the key exchange
            super().handle_key_exchange_init(message_data)
            
            # Update debug info after key exchange init
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.update_debug_info())
                
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Key exchange init error: {e}"))
            else:
                print(f"Key exchange init error: {e}")
    
    def handle_encrypted_message(self, message_data: bytes):
        """Handle encrypted chat messages - override to send to GUI."""
        try:
            decrypted_text = self.protocol.decrypt_message(message_data)
            
            # Update debug info after decryption
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.update_debug_info())
            
            # Attempt to parse the decrypted text as a JSON message
            try:
                
                message = json.loads(decrypted_text)
                message_type = message.get("type")
                
                if message_type == MSG_TYPE_FILE_METADATA:
                    self.handle_file_metadata(decrypted_text)
                elif message_type == MSG_TYPE_FILE_ACCEPT:
                    self.handle_file_accept(decrypted_text)
                elif message_type == MSG_TYPE_FILE_REJECT:
                    self.handle_file_reject(decrypted_text)
                elif message_type == MSG_TYPE_FILE_CHUNK:
                    self.handle_file_chunk(decrypted_text)
                elif message_type == MSG_TYPE_FILE_COMPLETE:
                    self.handle_file_complete(decrypted_text)
                else:
                    # It's a regular chat message
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}",
                                                                               is_message=True))
            
            except (json.JSONDecodeError, TypeError):
                # If it's not JSON, it's a regular chat message
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}",
                                                                           is_message=True))
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Failed to decrypt message: {e}"))
            else:
                print(f"\nFailed to decrypt message: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes):
        """Handle key exchange response - override to send to GUI."""
        try:
            if hasattr(self, 'private_key'):
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.update_status("Processing key exchange", "#ffa500"))
                else:
                    print("Key exchange completed successfully.")
                
                # Extract protocol version from message
                try:
                    message = json.loads(message_data.decode('utf-8'))
                    self.server_version = message.get("version")
                    # The version in the response message is actually the peer's version, not the server's
                    self.peer_version = message.get("version")
                except:
                    pass
                
                self.protocol.process_key_exchange_response(message_data, self.private_key)
                
                # Update debug info after key exchange processing
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.update_debug_info())
            else:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        "Received key exchange response but no private key found"))
                else:
                    print("Received key exchange response but no private key found")
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Key exchange response error: {e}"))
            else:
                print(f"Key exchange response error: {e}")
    
    def handle_key_exchange_complete(self, message: dict):
        """Handle key exchange completion notification - override to use GUI."""
        self.key_exchange_complete = True
        
        # Extract server version from the message
        if "version" in message:
            self.server_version = message.get("version")
        
        # Don't call start_key_verification() here as it would block the receive thread
        # The GUI monitoring thread will detect key_exchange_complete and show the dialogue
        
        # Update debug info after key exchange completion
        if self.gui:
            self.gui.root.after(0, lambda: self.gui.update_debug_info())
    
    def initiate_key_exchange(self):
        """Initiate key exchange as the first client - override to add GUI status update."""
        if self.gui:
            self.gui.root.after(0, lambda: self.gui.update_status("Processing key exchange", "#ffa500"))
        super().initiate_key_exchange()
        
        # Update debug info after initiating key exchange
        if self.gui:
            self.gui.root.after(0, lambda: self.gui.update_debug_info())
    
    def start_key_verification(self):
        """Start the key verification process - override to prevent blocking."""
        # This method is overridden to prevent the base class from blocking
        # the receive thread with console input. The GUI handles verification
        # through the monitoring thread and verification dialogue.
        pass
    
    def handle_key_exchange_reset(self, message_data: bytes):
        """Handle key exchange reset message - override to provide GUI feedback."""
        try:
            
            message = json.loads(message_data.decode('utf-8'))
            reset_message = message.get("message", "Key exchange reset")
            
            # Reset client state
            self.key_exchange_complete = False
            self.verification_complete = False
            self.protocol.reset_key_exchange()
            
            # Reset GUI-specific verification flags
            if hasattr(self, 'verification_started'):
                delattr(self, 'verification_started')
            
            # Clear any pending file transfers
            self.pending_file_transfers.clear()
            self.active_file_metadata.clear()
            
            # Update GUI
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.update_status("Key exchange reset - waiting for new client",
                                                                      "#ff6b6b"))
                self.gui.root.after(0, lambda: self.gui.append_to_chat("⚠️ KEY EXCHANGE RESET"))
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Reason: {reset_message}"))
                # Update debug info after key exchange reset
                self.gui.root.after(0, lambda: self.gui.update_debug_info())
                self.gui.root.after(0, lambda: self.gui.append_to_chat("The secure session has been terminated."))
                self.gui.root.after(0, lambda: self.gui.append_to_chat("Waiting for a new client to connect..."))
                self.gui.root.after(0, lambda: self.gui.append_to_chat("A new key exchange will start automatically."))
            else:
                # Fallback to console behavior
                super().handle_key_exchange_reset(message_data)
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling key exchange reset: {e}"))
            else:
                print(f"Error handling key exchange reset: {e}")
    
    def handle_file_metadata(self, decrypted_message: str):
        """Handle incoming file metadata with GUI dialog."""
        try:
            metadata = self.protocol.process_file_metadata(decrypted_message)
            transfer_id = metadata["transfer_id"]
            
            # Store metadata for potential acceptance
            self.active_file_metadata[transfer_id] = metadata
            
            # Show file acceptance dialog in GUI thread
            if self.gui:
                def show_file_dialog():
                    result = messagebox.askyesno(
                            "Incoming File Transfer",
                            f"Accept file transfer?\n\n"
                            f"Filename: {metadata['filename']}\n"
                            f"Size: {bytes_to_human_readable(metadata['file_size'])}\n"
                            f"Chunks: {metadata['total_chunks']}"
                    )
                    
                    if result:
                        # Send acceptance
                        
                        accept_msg = self.protocol.create_file_accept_message(transfer_id)
                        send_message(self.socket, accept_msg)
                        self.gui.file_transfer_window.add_transfer_message(
                            f"File transfer accepted: {metadata['filename']}", transfer_id)
                    else:
                        # Send rejection
                        
                        reject_msg = self.protocol.create_file_reject_message(transfer_id)
                        send_message(self.socket, reject_msg)
                        self.gui.file_transfer_window.add_transfer_message("File transfer rejected.")
                        del self.active_file_metadata[transfer_id]
                
                self.gui.root.after(0, show_file_dialog)
            else:
                # Fallback to console behavior
                super().handle_file_metadata(decrypted_message)
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling file metadata: {e}"))
            else:
                print(f"Error handling file metadata: {e}")
    
    def handle_file_accept(self, decrypted_message: str):
        """Handle file acceptance from peer with GUI updates."""
        try:
            
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id not in self.pending_file_transfers:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                        "Received acceptance for unknown file transfer"))
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            filename = transfer_info["metadata"]["filename"]
            
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                    f"File transfer accepted. Sending {filename}...", transfer_id))
            
            # Start sending file chunks
            self._send_file_chunks(transfer_id, transfer_info["file_path"])
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling file acceptance: {e}"))
            else:
                print(f"Error handling file acceptance: {e}")
    
    def handle_file_reject(self, decrypted_message: str):
        """Handle file rejection from peer with GUI updates."""
        try:
            
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            reason = message.get("reason", "Unknown reason")
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                        f"File transfer rejected: {filename} - {reason}", transfer_id))
                del self.pending_file_transfers[transfer_id]
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling file rejection: {e}"))
            else:
                print(f"Error handling file rejection: {e}")
    
    def handle_file_chunk(self, decrypted_message: str):
        """Handle incoming file chunk with GUI progress updates."""
        try:
            chunk_info = self.protocol.process_file_chunk(decrypted_message)
            transfer_id = chunk_info["transfer_id"]
            
            if transfer_id not in self.active_file_metadata:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                        "Received chunk for unknown file transfer"))
                return
            
            metadata = self.active_file_metadata[transfer_id]
            
            # Add chunk to protocol buffer
            is_complete = self.protocol.add_file_chunk(
                    transfer_id,
                    chunk_info["chunk_index"],
                    chunk_info["chunk_data"],
                    metadata["total_chunks"]
            )
            
            # Show progress in GUI every 50 chunks
            if self.gui:
                received_chunks = len(self.protocol.received_chunks.get(transfer_id, set()))
                if received_chunks % 50 == 0:  # Update every 50 chunks
                    # Calculate bytes transferred for speed tracking
                    # For most chunks, use FILE_CHUNK_SIZE, but for the last chunk use actual size
                    if metadata["total_chunks"] == 1:
                        # Only one chunk, use actual size
                        bytes_transferred = len(chunk_info["chunk_data"])
                    else:
                        # Multiple chunks - calculate based on complete chunks and current chunk
                        complete_chunks = received_chunks - 1  # Exclude current chunk
                        bytes_transferred = (complete_chunks * SEND_CHUNK_SIZE) + len(chunk_info["chunk_data"])
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.update_transfer_progress(
                            transfer_id, metadata['filename'], received_chunks, metadata['total_chunks'],
                            bytes_transferred
                    ))
            
            if is_complete:
                # Reassemble file
                output_path = os.path.join(os.getcwd(), metadata["filename"])
                
                # Handle filename conflicts
                counter = 1
                base_name, ext = os.path.splitext(metadata["filename"])
                while os.path.exists(output_path):
                    output_path = os.path.join(os.getcwd(), f"{base_name}_{counter}{ext}")
                    counter += 1
                
                try:
                    self.protocol.reassemble_file(transfer_id, output_path, metadata["file_hash"])
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                            f"File received successfully: {output_path}", transfer_id))
                        # Clear speed when transfer completes
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                    
                    # Send completion message
                    
                    complete_msg = self.protocol.create_file_complete_message(transfer_id)
                    send_message(self.socket, complete_msg)
                
                except Exception as e:
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                            f"File reassembly failed: {e}", transfer_id))
                
                # Clean up
                del self.active_file_metadata[transfer_id]
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(
                    f"Error handling file chunk: {e}"))
            else:
                print(f"Error handling file chunk: {e}")
    
    def handle_file_complete(self, decrypted_message: str):
        """Handle file transfer completion notification with GUI updates."""
        try:
            
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                        f"File transfer completed: {filename}", transfer_id))
                    # Clear speed when transfer completes
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                del self.pending_file_transfers[transfer_id]
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(
                    f"Error handling file completion: {e}"))
            else:
                print(f"Error handling file completion: {e}")
    
    def handle_keepalive(self, message_data: bytes) -> None:
        """Handle keepalive messages from the server with GUI updates.
        
        Args:
            message_data (bytes): The raw keepalive message data.
        """
        try:
            # Update the last keepalive received time
            self.last_keepalive_received = time.time()
            
            # Update debug info if GUI exists
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.update_debug_info())
            
            # Only respond if the flag is set
            if self.respond_to_keepalive:
                # Create keepalive response message
                response_message = {
                    "version": PROTOCOL_VERSION,
                    "type": MSG_TYPE_KEEP_ALIVE_RESPONSE
                }
                response_data = json.dumps(response_message).encode('utf-8')
                
                # Send response to server with socket lock to prevent conflicts with file uploads
                with self.socket_lock:
                    send_message(self.socket, response_data)
                
                # Update the last keepalive sent time
                self.last_keepalive_sent = time.time()
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling keepalive: {e}"))
            else:
                print(f"\nError handling keepalive: {e}")
    
    def _send_file_chunks(self, transfer_id: str, file_path: str):
        """Send file chunks to peer with GUI progress updates."""
        try:
            # Get total chunks from metadata (already calculated during file_metadata creation)
            total_chunks = self.pending_file_transfers[transfer_id]["metadata"]["total_chunks"]
            chunk_generator = self.protocol.chunk_file(file_path)
            bytes_transferred = 0
            
            # Pause interval to allow keepalive responses
            pause_interval = 10  # Pause after every 10 chunks
            
            for i, chunk in enumerate(chunk_generator):
                chunk_msg = self.protocol.create_file_chunk_message(transfer_id, i, chunk)
                
                # Use socket lock to prevent conflicts with keepalive responses
                with self.socket_lock:
                    send_message(self.socket, chunk_msg)
                
                # Update bytes transferred
                bytes_transferred += len(chunk)
                
                # Show progress in GUI every 50 chunks
                if self.gui:
                    if (i + 1) % 50 == 0:  # Update every 50 chunks
                        filename = os.path.basename(file_path)
                        self.gui.root.after(0, lambda curr=i + 1, total=total_chunks, bytes_sent=bytes_transferred,
                                                      fname=filename:
                        self.gui.file_transfer_window.update_transfer_progress(transfer_id, fname, curr, total,
                                                                               bytes_sent)
                                            )
                
                # Periodically pause to allow keepalive responses to be sent
                if (i + 1) % pause_interval == 0:
                    time.sleep(0.01)  # Short pause (10ms) to allow other threads to run
            
            # Final update to ensure 100% progress is shown
            if self.gui:
                filename = os.path.basename(file_path)
                self.gui.root.after(0, lambda curr=total_chunks, total=total_chunks, bytes_sent=bytes_transferred,
                                              fname=filename:
                self.gui.file_transfer_window.update_transfer_progress(transfer_id, fname, curr, total,
                                                                       bytes_sent)
                                    )
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                    "File chunks sent successfully.", transfer_id))
                # Clear speed when transfer completes
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(
                    f"Error sending file chunks: {e}", transfer_id))
            else:
                print(f"Error sending file chunks: {e}")
    
    def send_message(self, text: str) -> bool | None:
        """Encrypt and send a chat message with optional simulated latency and packet loss."""
        if not self.key_exchange_complete:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat("Cannot send messages - key exchange not complete"))
            return False
        
        # Check verification status and warn user
        allowed, status_msg = self.protocol.should_allow_communication()
        if not allowed:
            if self.gui:
                self.gui.root.after(0, lambda msg=status_msg: self.gui.append_to_chat(f"Cannot send message: {msg}"))
            return False
        
        if not self.protocol.is_peer_key_verified() and self.gui:
            self.gui.root.after(0, lambda: self.gui.append_to_chat("Sending message to unverified peer", is_message=False))
            
        try:
            encrypted_data = self.protocol.encrypt_message(text)
            
            # Check for simulated packet loss
            if hasattr(self, 'packet_loss_percentage') and self.packet_loss_percentage > 0:
                import random
                if random.random() * 100 < self.packet_loss_percentage:
                    # Simulate packet loss by not sending the message
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(
                            f"Simulated packet loss - message dropped ({self.packet_loss_percentage}% loss rate)", 
                            is_message=False))
                    return True  # Return True to indicate "success" even though we dropped the packet
            
            # Apply simulated latency if set
            if hasattr(self, 'simulated_latency') and self.simulated_latency > 0:
                latency = self.simulated_latency
                
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        f"Simulating {latency}ms network latency...", is_message=False))
                
                # Create a thread to send the message after the simulated latency
                def delayed_send():
                    time.sleep(latency / 1000.0)  # Convert ms to seconds
                    # Use socket lock to prevent conflicts with keepalive responses and file uploads
                    with self.socket_lock:
                        send_message(self.socket, encrypted_data)
                    
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(
                            f"Message sent after {latency}ms delay", is_message=False))
                
                threading.Thread(target=delayed_send, daemon=True).start()
            else:
                # Send immediately without delay
                # Use socket lock to prevent conflicts with keepalive responses and file uploads
                with self.socket_lock:
                    send_message(self.socket, encrypted_data)
                
            return True
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Failed to send message: {e}"))
            return False


def main():
    """Main function to run the GUI chat client."""
    root = tk.Tk()
    
    # Create GUI
    gui = ChatGUI(root)
    
    # Override the client creation to use our GUI-aware version
    original_connect = gui.connect_to_server
    
    def gui_connect():
        try:
            host = gui.host_entry.get().strip() or "localhost"
            port = int(gui.port_entry.get().strip() or "16384")
            
            gui.append_to_chat(f"Connecting to {host}:{port}...")
            
            # Create GUI-aware client instance
            gui.client = GUISecureChatClient(host, port, gui)
            
            # Start connection in a separate thread
            def connect_thread():
                try:
                    if gui.client.connect():
                        gui.connected = True
                        gui.root.after(0, gui.on_connected)
                        gui.start_chat_monitoring()
                    else:
                        gui.root.after(0, lambda: gui.append_to_chat("Failed to connect to server"))
                except Exception as e:
                    gui.root.after(0, lambda e=e: gui.append_to_chat(f"Connection error: {e}"))
            
            threading.Thread(target=connect_thread, daemon=True).start()
        
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            gui.append_to_chat(f"Connection error: {e}")
    
    gui.connect_to_server = gui_connect
    
    # Start the GUI
    root.mainloop()


if __name__ == "__main__":
    main()
