import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import sys
import io
import os
import time
import winsound
from client import SecureChatClient
import json
from shared import bytes_to_human_readable, send_message, MSG_TYPE_FILE_METADATA, MSG_TYPE_FILE_ACCEPT, MSG_TYPE_FILE_REJECT,\
    MSG_TYPE_FILE_COMPLETE, MSG_TYPE_FILE_CHUNK, MSG_TYPE_DELIVERY_CONFIRMATION, SEND_CHUNK_SIZE

GUI_VERSION = 13
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
            transfers (dict): Dictionary mapping transfer IDs to transfer information.
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
        self.TEXT_BG_COLOR = "#1e1e1e"
        
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
                bg=self.TEXT_BG_COLOR,
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


# noinspection PyAttributeOutsideInit
# noinspection DuplicatedCode
class ChatGUI:
    def __init__(self, root, theme_colors=None):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")

        # Store the theme colors dictionary
        self.theme_colors = theme_colors or {}

        # Apply theme colors or use defaults
        if theme_colors is None:
            # Default dark theme colours
            self.BG_COLOR = "#2b2b2b"
            self.FG_COLOR = "#d4d4d4"
            self.ENTRY_BG_COLOR = "#3c3c3c"
            self.BUTTON_BG_COLOR = "#555555"
            self.BUTTON_ACTIVE_BG = "#6a6a6a"
            self.TEXT_BG_COLOR = "#1e1e1e"
        else:
            # Use provided theme colors
            self.BG_COLOR = theme_colors.get("BG_COLOR", "#2b2b2b")
            self.FG_COLOR = theme_colors.get("FG_COLOR", "#d4d4d4")
            self.ENTRY_BG_COLOR = theme_colors.get("ENTRY_BG_COLOR", "#3c3c3c")
            self.BUTTON_BG_COLOR = theme_colors.get("BUTTON_BG_COLOR", "#555555")
            self.BUTTON_ACTIVE_BG = theme_colors.get("BUTTON_ACTIVE_BG", "#6a6a6a")
            self.TEXT_BG_COLOR = theme_colors.get("TEXT_BG_COLOR", "#1e1e1e")

        self.root.configure(bg=self.BG_COLOR)

        # Chat client instance
        self.client = None
        self.connected = False

        # Ephemeral mode state
        self.ephemeral_mode = False
        self.ephemeral_messages = {}  # Track messages with timestamps for removal
        self.message_counter = 0  # Counter for unique message IDs
        
        # Delivery confirmation tracking
        self.sent_messages = {}  # Track sent messages: {message_counter: tag_id}
        self.sent_message_tags = {}  # Track tag IDs for sent messages: {tag_id: message_counter}

        # Notification sound settings
        self.notification_enabled = True
        self.window_focused = True  # Track if window is focused

        # File transfer window with theme colors
        self.file_transfer_window = FileTransferWindow(self.root)
        # Pass theme colors to file transfer window
        self.file_transfer_window.BG_COLOR = self.BG_COLOR
        self.file_transfer_window.FG_COLOR = self.FG_COLOR
        self.file_transfer_window.ENTRY_BG_COLOR = self.ENTRY_BG_COLOR
        self.file_transfer_window.BUTTON_BG_COLOR = self.BUTTON_BG_COLOR
        self.file_transfer_window.TEXT_BG_COLOR = self.TEXT_BG_COLOR

        # Create GUI elements
        self.create_widgets()

        # Redirect stdout to capture print statements
        self.setup_output_redirection()

        # Setup window focus tracking
        self.setup_focus_tracking()

        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_focus_tracking(self):
        """Setup window focus tracking for notification sounds."""
        def on_focus_in(event):
            self.window_focused = True
            
        def on_focus_out(event):
            self.window_focused = False
            
        # Bind focus events to the root window
        self.root.bind("<FocusIn>", on_focus_in)
        self.root.bind("<FocusOut>", on_focus_out)

    def play_notification_sound(self):
        """Play a notification sound if the window is not focused."""
        if not self.notification_enabled or self.window_focused:
            return
            
        try:
            # Play a system notification sound (non-blocking)
            if os.path.exists("notification_sound.wav"):
                threading.Thread(
                    target=lambda: winsound.PlaySound("notification_sound.wav", winsound.SND_FILENAME),
                    daemon=True
                ).start()
        except Exception:
            pass

    def create_widgets(self):
        """Create the GUI widgets."""
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

        # Status indicator (top right)
        self.status_label = tk.Label(
            conn_frame, text="Not Connected", 
            bg=self.BG_COLOR, fg="#ff6b6b", font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0)) # type: ignore

        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(
            main_frame,
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

        # Input frame
        input_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        input_frame.pack(fill=tk.X) # type: ignore

        # Message input
        self.message_entry = tk.Entry(
            input_frame, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
            insertbackground=self.FG_COLOR, relief=tk.FLAT # type: ignore
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10)) # type: ignore
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)

        # Ephemeral mode button (with gap before Send File)
        self.ephemeral_btn = tk.Button(
            input_frame, text="Ephemeral", command=self.toggle_ephemeral_mode,
            bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
            activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.ephemeral_btn.pack(side=tk.RIGHT, padx=(0, 5)) # type: ignore

        # File Transfer window button
        self.file_transfer_btn = tk.Button(
            input_frame, text="Transfers", command=self.show_file_transfer_window,
            bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
            activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.file_transfer_btn.pack(side=tk.RIGHT, padx=(0, 10)) # type: ignore

        # Send File button
        self.send_file_btn = tk.Button(
            input_frame, text="Send File", command=self.send_file,
            bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
            activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_file_btn.pack(side=tk.RIGHT, padx=(0, 5)) # type: ignore

        # Send button
        self.send_btn = tk.Button(
            input_frame, text="Send", command=self.send_message,
            bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
            activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_btn.pack(side=tk.RIGHT) # type: ignore

        # Initially disable input until connected
        self.message_entry.config(state=tk.DISABLED) # type: ignore
        self.send_btn.config(state=tk.DISABLED) # type: ignore
        self.send_file_btn.config(state=tk.DISABLED) # type: ignore
        self.ephemeral_btn.config(state=tk.DISABLED) # type: ignore
        self.file_transfer_btn.config(state=tk.DISABLED) # type: ignore
        
        # Start ephemeral message cleanup thread
        self.start_ephemeral_cleanup()

    def setup_output_redirection(self):
        """Setup output redirection to capture print statements."""
        self.output_buffer = io.StringIO()

    def append_to_chat(self, text, is_message=False):
        """Append text to the chat display."""
        self.chat_display.config(state=tk.NORMAL) # type: ignore
        formatted_time = time.strftime("%H:%M:%S")
        
        # If ephemeral mode is enabled and this is a message, track it
        if self.ephemeral_mode and is_message:
            self.message_counter += 1
            message_id = f"msg_{self.message_counter}"
            self.ephemeral_messages[message_id] = time.time()
            
            # Add invisible marker for tracking using tags
            # The tag is applied to the entire line including the newline character
            start_index = self.chat_display.index(f"end-1c")
            self.chat_display.insert(tk.END, f"[{formatted_time}] {text}\n")
            end_index = self.chat_display.index(f"end-1c")
            self.chat_display.tag_add(message_id, start_index, end_index)
        else:
            self.chat_display.insert(tk.END, f"[{formatted_time}] {text}\n")
        
        # Play notification sound if this is a message from another user
        if is_message and text.startswith("Other user:"):
            self.play_notification_sound()
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED) # type: ignore

    def append_to_chat_with_delivery_status(self, text, message_counter=None, is_message=False):
        """Append text to chat display with delivery status tracking for sent messages."""
        self.chat_display.config(state=tk.NORMAL) # type: ignore
        formatted_time = time.strftime("%H:%M:%S")
        
        # Create unique tag for this message if we have a message counter
        tag_id = None
        if message_counter is not None:
            self.message_counter += 1
            tag_id = f"sent_msg_{self.message_counter}"
            
            # Track this sent message
            self.sent_messages[message_counter] = tag_id
            self.sent_message_tags[tag_id] = message_counter
        
        # Get the starting position for the message
        start_index = self.chat_display.index("end-1c")
        
        # Insert the message with a delivery status placeholder
        if message_counter is not None:
            # For sent messages, add a placeholder for delivery status
            message_text = f"[{formatted_time}] {text} ⏳\n"
        else:
            # For other messages, use normal format
            message_text = f"[{formatted_time}] {text}\n"
        
        self.chat_display.insert(tk.END, message_text)
        
        # Apply tag if we have one
        if tag_id:
            end_index = self.chat_display.index("end-1c")
            self.chat_display.tag_add(tag_id, start_index, end_index)
            
            # Handle ephemeral mode for sent messages
            if self.ephemeral_mode and is_message:
                self.ephemeral_messages[tag_id] = time.time()
        
        # Play notification sound if this is a message from another user
        if is_message and text.startswith("Other user:"):
            self.play_notification_sound()
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED) # type: ignore

    def update_message_delivery_status(self, message_counter):
        """Update the delivery status of a sent message to show it was delivered."""
        if message_counter in self.sent_messages:
            tag_id = self.sent_messages[message_counter]
            
            self.chat_display.config(state=tk.NORMAL) # type: ignore
            
            # Get the text range for this tag
            try:
                ranges = self.chat_display.tag_ranges(tag_id)
                if ranges:
                    start, end = ranges[0], ranges[1]
                    current_text = self.chat_display.get(start, end)
                    
                    # Replace the ⏳ with ✔️
                    updated_text = current_text.replace(" ⏳", " ✔️")
                    
                    # Delete the old text and insert the updated text
                    self.chat_display.delete(start, end)
                    self.chat_display.insert(start, updated_text)
                    
                    # Reapply the tag to the updated text
                    new_end = self.chat_display.index(f"{start} + {len(updated_text)}c")
                    self.chat_display.tag_add(tag_id, start, new_end)
                    
            except tk.TclError:
                # Tag might not exist anymore, ignore
                pass
            
            self.chat_display.config(state=tk.DISABLED) # type: ignore

    def update_status(self, status_text, color=None):
        """Update the status indicator with new text and color.
        
        If color is provided, it will be used directly.
        Otherwise, the color will be determined based on the status text.
        """
        # Map status text to theme color variables
        status_map = {
            "Not Connected": "STATUS_NOT_CONNECTED",
            "Connecting...": "STATUS_CONNECTING",
            "Connected, waiting for other client": "STATUS_WAITING",
            "Verifying fingerprint": "STATUS_VERIFYING",
            "Verified, Secure": "STATUS_VERIFIED_SECURE",
            "Not Verified, Secure": "STATUS_NOT_VERIFIED_SECURE",
            "Processing key exchange": "STATUS_PROCESSING_KEY_EXCHANGE",
            "Key exchange reset - waiting for new client": "STATUS_KEY_EXCHANGE_RESET"
        }
        
        # If color is not provided, look up in theme colors
        if color is None:
            status_key = status_map.get(status_text)
            if status_key and status_key in self.theme_colors:
                color = self.theme_colors[status_key]
            else:
                # Default color if status not recognized
                color = self.theme_colors.get("STATUS_NOT_CONNECTED", "#ff6b6b")
                
        self.status_label.config(text=status_text, fg=color) # type: ignore

    def show_file_transfer_window(self):
        """Show the file transfer progress window."""
        self.file_transfer_window.show_window()

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

            self.update_status("Connecting...")

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
                        self.root.after(0, lambda: self.update_status("Not Connected"))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.append_to_chat(f"Connection error: {e}"))
                    self.root.after(0, lambda: self.update_status("Not Connected"))

            threading.Thread(target=connect_thread, daemon=True).start()

        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            self.update_status("Not Connected")
        except Exception as e:
            self.append_to_chat(f"Connection error: {e}")
            self.update_status("Not Connected")

    def on_connected(self):
        """Called when successfully connected."""
        self.connected = True
        self.connect_btn.config(text="Disconnect")
        self.host_entry.config(state=tk.DISABLED) # type: ignore
        self.port_entry.config(state=tk.DISABLED) # type: ignore
        self.message_entry.config(state=tk.NORMAL) # type: ignore
        self.send_btn.config(state=tk.NORMAL) # type: ignore
        self.send_file_btn.config(state=tk.NORMAL) # type: ignore
        self.ephemeral_btn.config(state=tk.NORMAL) # type: ignore
        self.file_transfer_btn.config(state=tk.NORMAL) # type: ignore
        self.message_entry.focus()
        self.update_status("Connected, waiting for other client")
    
    def disconnect_from_server(self):
        """Disconnect from the server."""
        if self.client:
            self.client.disconnect()
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.host_entry.config(state=tk.NORMAL) # type: ignore
        self.port_entry.config(state=tk.NORMAL) # type: ignore
        self.message_entry.config(state=tk.DISABLED) # type: ignore
        self.send_btn.config(state=tk.DISABLED) # type: ignore
        self.send_file_btn.config(state=tk.DISABLED) # type: ignore
        self.ephemeral_btn.config(state=tk.DISABLED) # type: ignore
        self.file_transfer_btn.config(state=tk.DISABLED) # type: ignore
        self.append_to_chat("Disconnected from server.")
        self.update_status("Not Connected")
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

                    time.sleep(0.1)

            except Exception as e:
                self.root.after(0, lambda: self.append_to_chat(f"Monitor error: {e}"))

        threading.Thread(target=monitor_thread, daemon=True).start()

    def show_verification_dialog(self):
        """Show the key verification dialogue."""
        if not self.client or not hasattr(self.client, 'protocol'):
            return

        # Update status to show we're now verifying the fingerprint
        self.update_status("Verifying fingerprint")

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
                self.update_status("Verified, Secure")
            else:
                self.append_to_chat("You did not verify the peer's key.")
                self.update_status("Not Verified, Secure")

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
            # Get the message counter before sending (it will be incremented during send)
            if hasattr(self.client, 'protocol') and self.client.protocol:
                next_message_counter = self.client.protocol.message_counter + 1
            else:
                next_message_counter = None
                
            if self.client.send_message(message):
                # Display the sent message with delivery tracking
                if hasattr(self.client, 'protocol') and self.client.protocol.is_peer_key_verified():
                    display_text = f"You: {message}"
                else:
                    display_text = f"You (unverified): {message}"
                
                # Add the message with delivery tracking
                self.append_to_chat_with_delivery_status(display_text, next_message_counter, is_message=True)
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
                except Exception:
                    # Silently continue on errors to avoid breaking the cleanup thread
                    pass
        
        threading.Thread(target=cleanup_thread, daemon=True).start()

    def toggle_ephemeral_mode(self):
        """Toggle ephemeral mode on/off."""
        if not self.ephemeral_mode:
            # About to enable ephemeral mode
            self.ephemeral_mode = True
            self.ephemeral_btn.config(bg="#ff6b6b", fg="#ffffff", text="Ephemeral ON") # type: ignore
            self.append_to_chat("Ephemeral mode enabled - messages will disappear after 30 seconds", is_message=True)
        else:
            # About to disable ephemeral mode
            self.append_to_chat("Ephemeral mode disabled.", is_message=True)
            self.ephemeral_mode = False
            self.ephemeral_btn.config(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, text="Ephemeral") # type: ignore
            
            # Remove all existing ephemeral messages
            all_message_ids = list(self.ephemeral_messages.keys())
            if all_message_ids:
                self.remove_ephemeral_messages(all_message_ids)

    def remove_ephemeral_messages(self, message_ids):
        """Remove ephemeral messages from the chat display."""
        try:
            self.chat_display.config(state=tk.NORMAL) # type: ignore
            for message_id in message_ids:
                # Find the tagged message range
                tag_ranges = self.chat_display.tag_ranges(message_id)
                if tag_ranges:
                    # Delete the tagged text
                    self.chat_display.delete(tag_ranges[0], tag_ranges[1])
                
                # Remove from tracking dict
                self.ephemeral_messages.pop(message_id, None)
            
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED) # type: ignore
            
        except Exception as e:
            # If removal fails, just clean up the tracking dict
            for message_id in message_ids:
                self.ephemeral_messages.pop(message_id, None)
    
class GUISecureChatClient(SecureChatClient):
    """Extended SecureChatClient that works with GUI."""

    def __init__(self, host='localhost', port=16384, gui=None):
        super().__init__(host, port)
        self.gui = gui
        # Initialize verification_complete flag like console client
        self.verification_complete = False

    def handle_encrypted_message(self, message_data: bytes):
        """Handle encrypted chat messages - override to send to GUI."""
        try:
            decrypted_text = self.protocol.decrypt_message(message_data)
            
            # Get the message counter that was just processed for delivery confirmation
            received_message_counter = self.protocol.peer_counter
            
            # Attempt to parse the decrypted text as a JSON message
            try:
                
                message: dict = json.loads(decrypted_text)
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
                elif message_type == MSG_TYPE_DELIVERY_CONFIRMATION:
                    self.handle_delivery_confirmation(message)
                else:
                    # It's a regular chat message
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}", is_message=True))
                    # Send delivery confirmation for text messages only
                    self._send_delivery_confirmation(received_message_counter)
            
            except (json.JSONDecodeError, TypeError):
                # If it's not JSON, it's a regular chat message
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}", is_message=True))
                # Send delivery confirmation for text messages only
                self._send_delivery_confirmation(received_message_counter)

        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Failed to decrypt message: {e}"))
            else:
                print(f"\nFailed to decrypt message: {e}")
    
    def _send_delivery_confirmation(self, confirmed_counter: int) -> None:
        """Send a delivery confirmation for a received text message."""
        print(f"\nSent a delivery confirmation for {confirmed_counter} messages")
        try:
            confirmation_data = self.protocol.create_delivery_confirmation_message(confirmed_counter)
            send_message(self.socket, confirmation_data)
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error sending delivery confirmation: {e}"))
            else:
                print(f"\nError sending delivery confirmation: {e}")

    def handle_delivery_confirmation(self, message_data: dict) -> None:
        """Handle delivery confirmation messages from the peer - override to update GUI."""
        try:
            confirmed_counter = message_data.get("confirmed_counter")
            # Update the GUI to show the message was delivered
            if self.gui and confirmed_counter:
                self.gui.root.after(0, lambda: self.gui.update_message_delivery_status(confirmed_counter))
            else:
                # Fallback to console output if no GUI
                print(f"\n✓ Message {confirmed_counter} delivered")
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling delivery confirmation: {e}"))
            else:
                print(f"\nError handling delivery confirmation: {e}")

    def handle_key_exchange_init(self, message_data: bytes):
        """Handle key exchange initiation - override to display warnings in GUI."""
        try:
            _, ciphertext, version_warning = self.protocol.process_key_exchange_init(message_data)
            
            # Display version warning in GUI if present
            if version_warning and self.gui:
                self.gui.root.after(0, lambda warning=version_warning: self.gui.append_to_chat(f"⚠️ {warning}"))
            elif version_warning:
                print(f"\n{version_warning}")
                
            response = self.protocol.create_key_exchange_response(ciphertext)
            
            # Send response back through server
            send_message(self.socket, response)
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Key exchange init error: {e}"))
            else:
                print(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes):
        """Handle key exchange response - override to send to GUI."""
        try:
            if hasattr(self, 'private_key'):
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.update_status("Processing key exchange"))
                else:
                    print("Key exchange completed successfully.")
                
                _, version_warning = self.protocol.process_key_exchange_response(message_data, self.private_key)
                
                # Display version warning in GUI if present
                if version_warning and self.gui:
                    self.gui.root.after(0, lambda warning=version_warning: self.gui.append_to_chat(f"⚠️ {warning}"))
                elif version_warning:
                    print(f"\n{version_warning}")
                    
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.update_status("Key exchange completed"))
            else:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat("Received key exchange response but no private key found"))
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
        # Don't call start_key_verification() here as it would block the receive thread
        # The GUI monitoring thread will detect key_exchange_complete and show the dialogue

    def initiate_key_exchange(self):
        """Initiate key exchange as the first client - override to add GUI status update."""
        if self.gui:
            self.gui.root.after(0, lambda: self.gui.update_status("Processing key exchange"))
        super().initiate_key_exchange()

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
                self.gui.root.after(0, lambda: self.gui.update_status("Key exchange reset - waiting for new client"))
                self.gui.root.after(0, lambda: self.gui.append_to_chat("⚠️ KEY EXCHANGE RESET"))
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Reason: {reset_message}"))
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
                        self.gui.file_transfer_window.add_transfer_message(f"File transfer accepted: {metadata['filename']}", transfer_id)
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
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message("Received acceptance for unknown file transfer"))
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            filename = transfer_info["metadata"]["filename"]
            
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File transfer accepted. Sending {filename}...", transfer_id))
            
            # Start sending file chunks in a separate thread to avoid blocking message processing
            chunk_thread = threading.Thread(
                target=self._send_file_chunks,
                args=(transfer_id, transfer_info["file_path"]),
                daemon=True
            )
            chunk_thread.start()
            
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
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File transfer rejected: {filename} - {reason}", transfer_id))
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
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message("Received chunk for unknown file transfer"))
                return
            
            metadata = self.active_file_metadata[transfer_id]
            
            # Add chunk to protocol buffer
            is_complete = self.protocol.add_file_chunk(
                transfer_id,
                chunk_info["chunk_index"],
                chunk_info["chunk_data"],
                metadata["total_chunks"]
            )
            
            # Show progress in GUI
            if self.gui:
                received_chunks = len(self.protocol.received_chunks.get(transfer_id, set()))
                # Calculate bytes transferred for speed tracking
                # For most chunks, use FILE_CHUNK_SIZE, but for the last chunk use actual size
                if metadata["total_chunks"] == 1:
                    # Only one chunk, use actual size
                    bytes_transferred = len(chunk_info["chunk_data"])
                else:
                    # Multiple chunks - calculate based on complete chunks and current chunk
                    complete_chunks = received_chunks - 1  # Exclude current chunk
                    bytes_transferred = (complete_chunks * SEND_CHUNK_SIZE) + len(chunk_info["chunk_data"])
                
                # Update GUI with transfer progress every 50 chunks
                if self.gui and received_chunks % 50 == 0:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.update_transfer_progress(
                        transfer_id, metadata['filename'], received_chunks, metadata['total_chunks'], bytes_transferred
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
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File received successfully: {output_path}", transfer_id))
                        # Clear speed when transfer completes
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                    
                    # Send completion message
                    complete_msg = self.protocol.create_file_complete_message(transfer_id)
                    send_message(self.socket, complete_msg)
                    
                except Exception as e:
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File reassembly failed: {e}", transfer_id))
                
                # Clean up
                del self.active_file_metadata[transfer_id]
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(f"Error handling file chunk: {e}"))
            else:
                print(f"Error handling file chunk: {e}")
    
    def handle_file_chunk_binary(self, chunk_info: dict):
        """Handle incoming file chunk (optimized binary format) with GUI progress updates."""
        try:
            transfer_id = chunk_info["transfer_id"]
            
            if transfer_id not in self.active_file_metadata:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message("Received chunk for unknown file transfer"))
                return
            
            metadata = self.active_file_metadata[transfer_id]
            
            # Add chunk to protocol buffer
            is_complete = self.protocol.add_file_chunk(
                transfer_id,
                chunk_info["chunk_index"],
                chunk_info["chunk_data"],
                metadata["total_chunks"]
            )
            
            # Show progress in GUI
            if self.gui:
                received_chunks = len(self.protocol.received_chunks.get(transfer_id, set()))
                # Calculate bytes transferred for speed tracking
                # For most chunks, use SEND_CHUNK_SIZE, but for the last chunk use actual size
                if metadata["total_chunks"] == 1:
                    # Only one chunk, use actual size
                    bytes_transferred = len(chunk_info["chunk_data"])
                else:
                    # Multiple chunks - calculate based on complete chunks and current chunk
                    complete_chunks = received_chunks - 1  # Exclude current chunk
                    bytes_transferred = (complete_chunks * SEND_CHUNK_SIZE) + len(chunk_info["chunk_data"])
                
                # Update GUI with transfer progress every 50 chunks
                if received_chunks % 50 == 0 or received_chunks == 1:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.update_transfer_progress(
                        transfer_id, metadata['filename'], received_chunks, metadata['total_chunks'], bytes_transferred
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
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File received successfully: {output_path}", transfer_id))
                        # Clear speed when transfer completes
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                    
                    # Send completion message
                    complete_msg = self.protocol.create_file_complete_message(transfer_id)
                    send_message(self.socket, complete_msg)
                    
                except Exception as e:
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File reassembly failed: {e}", transfer_id))
                
                # Clean up
                del self.active_file_metadata[transfer_id]
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(f"Error handling binary file chunk: {e}"))
            else:
                print(f"Error handling binary file chunk: {e}")
    
    def handle_file_complete(self, decrypted_message: str):
        """Handle file transfer completion notification with GUI updates."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(f"File transfer completed: {filename}", transfer_id))
                    # Clear speed when transfer completes
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                del self.pending_file_transfers[transfer_id]
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(f"Error handling file completion: {e}"))
            else:
                print(f"Error handling file completion: {e}")
    
    def _send_file_chunks(self, transfer_id: str, file_path: str):
        """Send file chunks to peer with GUI progress updates."""
        try:
            # Get total chunks from metadata (already calculated during file_metadata creation)
            total_chunks = self.pending_file_transfers[transfer_id]["metadata"]["total_chunks"]
            chunk_generator = self.protocol.chunk_file(file_path)
            bytes_transferred = 0
            
            for i, chunk in enumerate(chunk_generator):
                chunk_msg = self.protocol.create_file_chunk_message(transfer_id, i, chunk)
                send_message(self.socket, chunk_msg)
                
                # Update bytes transferred
                bytes_transferred += len(chunk)
                
                # Show progress in GUI every 50 chunks
                if self.gui:
                    if i % 50 == 0:
                        filename = os.path.basename(file_path)
                        self.gui.root.after(0, lambda curr=i+1, total=total_chunks, bytes_sent=bytes_transferred, fname=filename:
                            self.gui.file_transfer_window.update_transfer_progress(transfer_id, fname, curr, total, bytes_sent)
                        )
            
            # Final update to ensure 100% progress is shown
            if self.gui:
                filename = os.path.basename(file_path)
                self.gui.root.after(0, lambda curr=total_chunks, total=total_chunks, bytes_sent=bytes_transferred, fname=filename:
                    self.gui.file_transfer_window.update_transfer_progress(transfer_id, fname, curr, total, bytes_sent)
                )
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message("File chunks sent successfully.", transfer_id))
                # Clear speed when transfer completes
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(f"Error sending file chunks: {e}", transfer_id))
            else:
                print(f"Error sending file chunks: {e}")


def load_theme_colors():
    """
    Load theme colors from themes.json file.
    If the file doesn't exist, ask the user if they want to create it with default colors.
    Returns a dictionary of color values.
    """
    # Default dark theme colors
    default_colors = {
        "BG_COLOR":                       "#2b2b2b",
        "FG_COLOR":                       "#d4d4d4",
        "ENTRY_BG_COLOR":                 "#3c3c3c",
        "BUTTON_BG_COLOR":                "#555555",
        "BUTTON_ACTIVE_BG":               "#6a6a6a",
        "TEXT_BG_COLOR":                  "#1e1e1e",
        
        "STATUS_NOT_CONNECTED":           "#ff6b6b",
        "STATUS_CONNECTING":              "#ffa500",
        "STATUS_WAITING":                 "#ffff00",
        "STATUS_VERIFYING":               "#ffa500",
        "STATUS_VERIFIED_SECURE":         "#00ff00",
        "STATUS_NOT_VERIFIED_SECURE":     "#ffff00",
        "STATUS_PROCESSING_KEY_EXCHANGE": "#ffa500",
        "STATUS_KEY_EXCHANGE_RESET":      "#ffff00"
    }
    
    # Check if themes.json exists
    if not os.path.exists("themes.json"):
        # Ask user if they want to generate one with current defaults
        if messagebox.askyesno("Theme Configuration", 
                              "No themes.json file found. Would you like to create one with the default colors?"):
            try:
                with open("themes.json", "w") as f:
                    json.dump(default_colors, f, indent=4)
                messagebox.showinfo("Theme Created", "themes.json has been created with default colors.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create themes.json: {e}")
        return default_colors
    
    # Load colors from themes.json
    try:
        with open("themes.json", "r") as f:
            theme_colors = json.load(f)
            
        # Validate theme format
        required_colors = ["BG_COLOR", "FG_COLOR", "ENTRY_BG_COLOR", "BUTTON_BG_COLOR", "BUTTON_ACTIVE_BG"]
        missing_colors = [color for color in required_colors if color not in theme_colors]
        
        if missing_colors:
            messagebox.showwarning("Theme Warning", 
                                  f"Missing colors in themes.json: {', '.join(missing_colors)}. Using defaults for these.")
            for color in missing_colors:
                theme_colors[color] = default_colors[color]
                
        return theme_colors
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load themes.json: {e}")
        return default_colors

def main():
    """Main function to run the GUI chat client."""
    root = tk.Tk()
    
    # Load theme colors
    theme_colors = load_theme_colors()
    
    # Create GUI
    gui = ChatGUI(root, theme_colors)

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
