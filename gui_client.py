# pylint: disable=trailing-whitespace
# pylint: disable=line-too-long
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import tkinter as tk
import uuid
from tkinter import scrolledtext, messagebox, filedialog

try:
    import winsound
    WINSOUND_AVAILABLE = True
except ImportError:
    WINSOUND_AVAILABLE = False
    winsound = None
    
try:
    from PIL import Image, ImageTk, ImageGrab
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None  # type: ignore
    ImageTk = None  # type: ignore
    ImageGrab = None  # type: ignore

# Plyer for system notifications
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    notification = None  # type: ignore

# py-spellchecker for spell checking
try:
    from spellchecker import SpellChecker
    SPELLCHECKER_AVAILABLE = True
except ImportError:
    SPELLCHECKER_AVAILABLE = False
    SpellChecker = None  # type: ignore

# tkinterdnd2 for drag-and-drop file support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    TKINTERDND2_AVAILABLE = True
except ImportError:
    TKINTERDND2_AVAILABLE = False
    DND_FILES = None  # type: ignore
    TkinterDnD = None  # type: ignore

from client import SecureChatClient
from shared import bytes_to_human_readable, send_message, MessageType, SEND_CHUNK_SIZE

GUI_VERSION = 17

def get_image_from_clipboard() -> Image.Image | None:
    """Get an image from the clipboard."""
    if not PIL_AVAILABLE or not ImageGrab:
        return None
    try:
        image = ImageGrab.grabclipboard()
        if isinstance(image, Image.Image):
            return image
        else:
            return None
    except Exception:
        return None


def display_image(image: Image.Image, root):
    """Display an image in a new Tkinter window, scaling it down if it's too large."""
    if not PIL_AVAILABLE or not ImageTk:
        messagebox.showerror("Error", "PIL is not available. Cannot display image.")
        return
    if image is None:
        return
    
    # Define max dimensions as 80% of the screen size
    max_width = int(root.winfo_screenwidth() * 0.8)
    max_height = int(root.winfo_screenheight() * 0.8)
    
    img_width, img_height = image.size
    to_display_image = image
    
    # Check if the image needs to be resized
    if img_width > max_width or img_height > max_height:
        # Calculate the scaling ratio to fit within the max dimensions
        ratio = min(max_width / img_width, max_height / img_height)
        new_width = int(img_width * ratio)
        new_height = int(img_height * ratio)
        
        # Resize the image using a high-quality downsampling filter
        to_display_image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    window: tk.Toplevel = tk.Toplevel(root)
    # Update the window title to show original and scaled dimensions
    if to_display_image.size != image.size:
        window.title(
            f"Image (scaled from {img_width}x{img_height} to {to_display_image.width}x{to_display_image.height})")
    else:
        window.title(f"Image ({img_width}x{img_height})")
    
    window.transient(root)
    
    # Convert the (possibly resized) PIL image to a PhotoImage
    photo = ImageTk.PhotoImage(to_display_image, master=root)
    
    label = tk.Label(window, image=photo)  # type: ignore
    # Keep a reference to the image to prevent it from being garbage collected
    label.image = photo
    label.pack()


class FileTransferWindow:
    """Separate window for file transfer progress and status updates."""
    
    def __init__(self, parent_root):
        # noinspection PyUnresolvedReferences
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
            top_frame.pack(fill=tk.X, padx=10, pady=5) # type: ignore
            
            # Speed label in top right
            self.speed_label = tk.Label(
                    top_frame,
                    text="Speed: 0.0 MiB/s",
                    bg=self.BG_COLOR,
                    fg="#4CAF50",
                    font=("Consolas", 10, "bold")
            )
            self.speed_label.pack(side=tk.RIGHT) # type: ignore
            
            # Title label
            title_label = tk.Label(
                    top_frame,
                    text="File Transfers",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            )
            title_label.pack(side=tk.LEFT) # type: ignore
            
            # Main frame for transfer list
            main_frame = tk.Frame(self.window, bg=self.BG_COLOR)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5) # type: ignore
            
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
            self.transfer_list.pack(fill=tk.BOTH, expand=True) # type: ignore
            
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
    
    def add_transfer_message(self, message):
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
        self.add_transfer_message(message)
    
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
        self.root.geometry("900x600")
        
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
        
        # Windows system notification settings
        self.windows_notifications_enabled = True
        
        # File transfer window with theme colors
        self.file_transfer_window = FileTransferWindow(self.root)
        # Pass theme colors to file transfer window
        self.file_transfer_window.BG_COLOR = self.BG_COLOR
        self.file_transfer_window.FG_COLOR = self.FG_COLOR
        self.file_transfer_window.ENTRY_BG_COLOR = self.ENTRY_BG_COLOR
        self.file_transfer_window.BUTTON_BG_COLOR = self.BUTTON_BG_COLOR
        self.file_transfer_window.TEXT_BG_COLOR = self.TEXT_BG_COLOR
        
        # Spellcheck functionality
        self.spell_checker = SpellChecker()
        self.spellcheck_timer = None
        self.spellcheck_enabled = True
        self.misspelled_tags = set()  # Track tags for misspelled words
        
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
        
        # Bind Control+Q for emergency close at window level
        self.root.bind("<Control-q>", lambda event: self.emergency_close())
    
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
    
    def show_windows_notification(self, message_text):
        """Show a Windows system notification if the window is not focused."""
        if not self.windows_notifications_enabled or self.window_focused:
            return
        
        try:
            # Extract the actual message content (remove "Other user: " prefix)
            display_message = message_text.replace("Other user: ", "")
            
            # Show notification in a separate thread to avoid blocking
            def show_notification():
                try:
                    notification.notify(
                            title="Secure Chat Notification",
                            message=display_message,
                            app_name="Secure Chat Client",
                            timeout=5,  # Notification will disappear after 5 seconds
                            app_icon=None  # You can specify an icon file if desired
                    )
                except Exception:
                    pass
            
            threading.Thread(target=show_notification, daemon=True).start()
        except Exception:
            pass
    
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
        self.connect_btn.pack(side=tk.LEFT, padx=(10, 0)) # type: ignore
        
        # Sound toggle button
        self.sound_btn = tk.Button(
                conn_frame, text="Notif sounds ON", command=self.toggle_sound_notifications,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 10)
        )
        self.sound_btn.pack(side=tk.LEFT, padx=(10, 0))  # type: ignore
        
        # Windows notifications toggle button
        self.windows_notif_btn = tk.Button(
                conn_frame, text="System notifs ON", command=self.toggle_windows_notifications,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 10)
        )
        self.windows_notif_btn.pack(side=tk.LEFT, padx=(10, 0)) # type: ignore
        
        # Status indicator (top right)
        self.status_label = tk.Label(
                conn_frame, text="Not Connected",
                bg=self.BG_COLOR, fg="#ff6b6b", font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0))  # type: ignore
        
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
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))  # type: ignore
        if TKINTERDND2_AVAILABLE:
            self.chat_display.drop_target_register(DND_FILES) # type: ignore
            self.chat_display.dnd_bind('<<Drop>>', self.handle_drop) # type: ignore
        
        # Input frame
        self.input_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        self.input_frame.pack(fill=tk.X)  # type: ignore
        
        # Message input
        self.message_entry = tk.Text(
                self.input_frame, height=1, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR, width=15,
                insertbackground=self.FG_COLOR, relief=tk.FLAT, wrap=tk.NONE  # type: ignore
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))  # type: ignore
        
        # Configure text tags for spellcheck
        self.message_entry.tag_configure("misspelled", underline=True, underlinefg="red")
        
        # Bind events
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        self.message_entry.bind("<Control-v>", self.on_paste)
        self.message_entry.bind("<KeyRelease>", self.on_text_change)
        self.message_entry.bind("<Button-1>", self.on_text_change)
        self.message_entry.bind("<Button-3>", self.show_spellcheck_menu)
        
        # Ephemeral mode button (with gap before Send File)
        self.ephemeral_btn = tk.Button(
                self.input_frame, text="Ephemeral", command=self.toggle_ephemeral_mode,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.ephemeral_btn.pack(side=tk.RIGHT, padx=(0, 5))  # type: ignore
        
        # File Transfer window button
        self.file_transfer_btn = tk.Button(
                self.input_frame, text="Transfers", command=self.show_file_transfer_window,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                font=("Consolas", 9)
        )
        self.file_transfer_btn.pack(side=tk.RIGHT, padx=(0, 10))  # type: ignore
        
        # Send File button
        self.send_file_btn = tk.Button(
                self.input_frame, text="Send File", command=self.send_file,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT,  # type: ignore
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_file_btn.pack(side=tk.RIGHT, padx=(0, 5))  # type: ignore
        
        # Send button
        self.send_btn = tk.Button(
                self.input_frame, text="Send", command=self.send_message,
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
    
    def handle_drop(self, event):
        """Handle file drop events."""
        if not TKINTERDND2_AVAILABLE:
            self.append_to_chat("Drag-and-drop support is not available.")
            return
        if not self.connected or not self.client:
            return
        
        if not hasattr(self.client, 'verification_complete') or not self.client.verification_complete:
            self.append_to_chat("Cannot send files - verification not complete")
            return
        
        # The event.data attribute contains a string of file paths
        # It can be a single path or multiple paths separated by spaces
        # File paths with spaces are enclosed in curly braces {}
        file_paths_str = event.data
        
        # Simple parsing for now, assuming single file drop
        # A more robust parser would be needed for multiple files with spaces
        file_path = file_paths_str.strip()
        if file_path.startswith('{') and file_path.endswith('}'):
            file_path = file_path[1:-1]
        
        if os.path.exists(file_path):
            self.confirm_and_send_file(file_path)
    
    def confirm_and_send_file(self, file_path):
        """Ask for confirmation and then send the file."""
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            result = messagebox.askyesno(
                    "Send File",
                    f"Send file '{file_name}' ({bytes_to_human_readable(file_size)})?"
            )
            
            if result:
                self.append_to_chat(f"Sending file: {file_name}")
                self.client.send_file(file_path)
        except Exception as e:
            self.append_to_chat(f"File send error: {e}")
    
    def setup_output_redirection(self):
        """Setup output redirection to capture print statements."""
        self.output_buffer = io.StringIO()
    
    def append_to_chat(self, text, is_message=False):
        """Append text to the chat display."""
        text = str(text)
        self.chat_display.config(state=tk.NORMAL)  # type: ignore
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
        
        # Play notification sound and show Windows notification if this is a message from another user
        if is_message and text.startswith("Other user:"):
            self.play_notification_sound()
            self.show_windows_notification(text)
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)  # type: ignore
    
    def append_to_chat_with_delivery_status(self, text, message_counter=None, is_message=False):
        """Append text to chat display with delivery status tracking for sent messages."""
        self.chat_display.config(state=tk.NORMAL)  # type: ignore
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
        
        # Play notification sound and show Windows notification if this is a message from another user
        if is_message and text.startswith("Other user:"):
            self.play_notification_sound()
            self.show_windows_notification(text)
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)  # type: ignore
    
    def update_message_delivery_status(self, message_counter):
        """Update the delivery status of a sent message to show it was delivered."""
        if message_counter in self.sent_messages:
            tag_id = self.sent_messages[message_counter]
            
            self.chat_display.config(state=tk.NORMAL)  # type: ignore
            
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
            
            self.chat_display.config(state=tk.DISABLED)  # type: ignore
    
    def update_status(self, status_text, color=None):
        """Update the status indicator with new text and color.
        
        If color is provided, it will be used directly.
        Otherwise, the color will be determined based on the status text.
        """
        # Map status text to theme color variables
        status_map = {
            "Not Connected":                               "STATUS_NOT_CONNECTED",
            "Connecting...":                               "STATUS_CONNECTING",
            "Connected, waiting for other client":         "STATUS_WAITING",
            "Verifying fingerprint":                       "STATUS_VERIFYING",
            "Verified, Secure":                            "STATUS_VERIFIED_SECURE",
            "Not Verified, Secure":                        "STATUS_NOT_VERIFIED_SECURE",
            "Processing key exchange":                     "STATUS_PROCESSING_KEY_EXCHANGE",
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
        
        self.status_label.config(text=status_text, fg=color)  # type: ignore
    
    def show_file_transfer_window(self):
        """Show the file transfer progress window."""
        self.file_transfer_window.show_window()
    
    def toggle_connection(self):
        """Toggle connection to the server."""
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()
    
    def toggle_sound_notifications(self):
        """Toggle sound notifications on/off."""
        self.notification_enabled = not self.notification_enabled
        if self.notification_enabled:
            self.sound_btn.config(text="Notif sounds ON")
        else:
            self.sound_btn.config(text="Notif sounds OFF")
    
    def toggle_windows_notifications(self):
        """Toggle Windows system notifications on/off."""
        self.windows_notifications_enabled = not self.windows_notifications_enabled
        if hasattr(self, 'windows_notif_btn'):
            if self.windows_notifications_enabled:
                self.windows_notif_btn.config(text="Win notifs ON")
            else:
                self.windows_notif_btn.config(text="Win notifs OFF")
    
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
                except Exception as er:
                    self.root.after(0, lambda error=er: self.append_to_chat(f"Connection error: {error}"))
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
        self.host_entry.config(state=tk.DISABLED)  # type: ignore
        self.port_entry.config(state=tk.DISABLED)  # type: ignore
        self.message_entry.config(state=tk.NORMAL)  # type: ignore
        self.send_btn.config(state=tk.NORMAL)  # type: ignore
        self.send_file_btn.config(state=tk.NORMAL)  # type: ignore
        self.ephemeral_btn.config(state=tk.NORMAL)  # type: ignore
        self.file_transfer_btn.config(state=tk.NORMAL)  # type: ignore
        self.message_entry.focus()
        self.update_status("Connected, waiting for other client")
    
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
        """Show the key verification dialogue using non-intrusive notification."""
        if not self.client or not hasattr(self.client, 'protocol'):
            return
        
        # Update status to show we're now verifying the fingerprint
        self.update_status("Verifying fingerprint")
        
        try:
            fingerprint = self.client.protocol.get_own_key_fingerprint()
            
            self.play_notification_sound()
            
            # Show Windows notification if enabled
            self.show_windows_notification("Key exchange complete - verification required")
            
            self.append_to_chat("KEY EXCHANGE COMPLETE!")
            self.append_to_chat(f"Fingerprint: {fingerprint}")
            self.append_to_chat("")
            self.append_to_chat("VERIFICATION REQUIRED:")
            self.append_to_chat("1. Compare the fingerprint above with the other person through a")
            self.append_to_chat("   separate secure channel (phone call, in person, etc.)")
            self.append_to_chat("2. Type '/y' if the fingerprints match exactly")
            self.append_to_chat("3. Type '/n' if they don't match or you're unsure")
            self.append_to_chat("")
            self.append_to_chat("⚠️  Please verify the key to start secure messaging!")
            
            # Store the verification state for later processing
            self.client.verification_pending = True
        
        except Exception as e:
            self.append_to_chat(f"Verification error: {e}")
    
    def send_message(self, event=None):
        """Send a message."""
        # Prevent the default newline insertion on Return key press
        if event and event.keysym == "Return":
            # Allow Shift+Return to insert a newline for multi-line messages in the future
            if not event.state & 0x0001:  # Check if Shift key is not pressed
                pass
            else:
                return None  # Do not send, allow newline
        
        if not self.connected or not self.client:
            return "break"
        
        message = self.message_entry.get("1.0", "end-1c").strip()
        if not message:
            return "break"
        
        # Handle special commands (these work even during verification)
        if message.lower() == '/quit':
            self.disconnect_from_server()
            return "break"
        if message.lower() == '/verify':
            self.show_verification_dialog()
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        # Handle verification commands
        if message.lower() in ['/vy', '/verify yes', '/yes', '/y']:
            if hasattr(self.client, 'verification_pending') and self.client.verification_pending:
                try:
                    self.client.confirm_key_verification(True)
                    self.client.verification_pending = False
                    self.append_to_chat("✅ You verified the peer's key.")
                    self.update_status("Verified, Secure")
                    self.append_to_chat("You can now send messages!")
                except Exception as e:
                    self.append_to_chat(f"Verification error: {e}")
                self.message_entry.delete("1.0", tk.END)
                return "break"
            elif hasattr(self.client, 'pending_file_requests') and self.client.pending_file_requests:
                # Handle file transfer acceptance when no verification is pending
                transfer_id = list(self.client.pending_file_requests.keys())[-1]
                metadata = self.client.pending_file_requests[transfer_id]
                try:
                    # Send acceptance
                    accept_msg = self.client.protocol.create_file_accept_message(transfer_id)
                    send_message(self.client.socket, accept_msg)
                    self.file_transfer_window.add_transfer_message(
                        f"File transfer accepted: {metadata['filename']}")
                    self.append_to_chat(f"✅ Accepted file transfer: {metadata['filename']}")
                    # Remove from pending requests
                    del self.client.pending_file_requests[transfer_id]
                except Exception as e:
                    self.append_to_chat(f"Error accepting file transfer: {e}")
                self.message_entry.delete("1.0", tk.END)
                return "break"
            else:
                self.append_to_chat("No verification or file transfer pending.")
                self.message_entry.delete("1.0", tk.END)
                return "break"
        
        if message.lower() in ['/vn', '/verify no', '/no', '/n']:
            if hasattr(self.client, 'verification_pending') and self.client.verification_pending:
                try:
                    self.client.confirm_key_verification(False)
                    self.client.verification_pending = False
                    self.append_to_chat("❌ You did not verify the peer's key.")
                    self.update_status("Not Verified, Secure")
                    self.append_to_chat("You can now send messages!")
                except Exception as e:
                    self.append_to_chat(f"Verification error: {e}")
                self.message_entry.delete("1.0", tk.END)
                return "break"
            elif hasattr(self.client, 'pending_file_requests') and self.client.pending_file_requests:
                # Handle file transfer rejection when no verification is pending
                transfer_id = list(self.client.pending_file_requests.keys())[-1]
                metadata = self.client.pending_file_requests[transfer_id]
                try:
                    # Send rejection
                    reject_msg = self.client.protocol.create_file_reject_message(transfer_id)
                    send_message(self.client.socket, reject_msg)
                    self.file_transfer_window.add_transfer_message("File transfer rejected.")
                    self.append_to_chat(f"❌ Rejected file transfer: {metadata['filename']}")
                    # Remove from pending requests and active metadata
                    del self.client.pending_file_requests[transfer_id]
                    if transfer_id in self.client.active_file_metadata:
                        del self.client.active_file_metadata[transfer_id]
                except Exception as e:
                    self.append_to_chat(f"Error rejecting file transfer: {e}")
                self.message_entry.delete("1.0", tk.END)
                return "break"
            else:
                self.append_to_chat("No verification or file transfer pending.")
                self.message_entry.delete("1.0", tk.END)
                return "break"
        
        # Handle file transfer commands
        if message.lower() in ['/accept', '/y']:
            if hasattr(self.client, 'pending_file_requests') and self.client.pending_file_requests:
                # Accept the most recent file transfer request
                transfer_id = list(self.client.pending_file_requests.keys())[-1]
                metadata = self.client.pending_file_requests[transfer_id]
                try:
                    # Send acceptance
                    accept_msg = self.client.protocol.create_file_accept_message(transfer_id)
                    send_message(self.client.socket, accept_msg)
                    self.file_transfer_window.add_transfer_message(
                        f"File transfer accepted: {metadata['filename']}")
                    self.append_to_chat(f"✅ Accepted file transfer: {metadata['filename']}")
                    # Remove from pending requests
                    del self.client.pending_file_requests[transfer_id]
                except Exception as e:
                    self.append_to_chat(f"Error accepting file transfer: {e}")
            else:
                self.append_to_chat("No pending file transfer requests.")
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower() in ['/reject', '/n']:
            if hasattr(self.client, 'pending_file_requests') and self.client.pending_file_requests:
                # Reject the most recent file transfer request
                transfer_id = list(self.client.pending_file_requests.keys())[-1]
                metadata = self.client.pending_file_requests[transfer_id]
                try:
                    # Send rejection
                    reject_msg = self.client.protocol.create_file_reject_message(transfer_id)
                    send_message(self.client.socket, reject_msg)
                    self.file_transfer_window.add_transfer_message("File transfer rejected.")
                    self.append_to_chat(f"❌ Rejected file transfer: {metadata['filename']}")
                    # Remove from pending requests and active metadata
                    del self.client.pending_file_requests[transfer_id]
                    if transfer_id in self.client.active_file_metadata:
                        del self.client.active_file_metadata[transfer_id]
                except Exception as e:
                    self.append_to_chat(f"Error rejecting file transfer: {e}")
            else:
                self.append_to_chat("No pending file transfer requests.")
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        # Check if verification is complete (like console client does)
        if not hasattr(self.client, 'verification_complete') or not self.client.verification_complete:
            self.append_to_chat("Cannot send messages - verification not complete")
            return "break"
        
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
        
        self.message_entry.delete("1.0", tk.END)
        return "break"  # Prevents the default newline insertion
    
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
                self.confirm_and_send_file(file_path)
        
        except Exception as e:
            self.append_to_chat(f"File send error: {e}")
    
    def on_key_press(self, event):
        """Handle key press events in message entry."""
        # Allow normal typing when connected
        # Note: Control+Q is handled at the window level, not here
        pass
    
    def on_paste(self, event):
        """Handle paste events in message entry - check for images."""
        if not self.connected or not self.client:
            return "break"  # Prevent default paste behavior
        
        # Check if verification is complete
        if not hasattr(self.client, 'verification_complete') or not self.client.verification_complete:
            return "break"  # Prevent default paste behavior
        
        try:
            # Check if there's an image in the clipboard
            clipboard_image = get_image_from_clipboard()
            
            if clipboard_image is not None:
                # There's an image in the clipboard, handle it
                self.handle_clipboard_image(clipboard_image)
                return "break"  # Prevent default paste behavior
            
            # No image, allow normal text paste
            return None  # Allow default paste behavior
        
        except Exception as e:
            self.append_to_chat(f"Error handling paste: {e}")
            return "break"  # Prevent default paste behavior on error
    
    def handle_clipboard_image(self, image):
        """Handle pasted clipboard image by saving to temp file and sending."""
        try:
            
            # Create a temporary file with a unique name
            temp_dir = tempfile.gettempdir()
            temp_filename = f"clipboard_image_{uuid.uuid4().hex[:8]}.png"
            temp_path = os.path.join(temp_dir, temp_filename)
            
            # Save the image to the temporary file
            image.save(temp_path, "PNG")
            
            # Get file info
            file_size = os.path.getsize(temp_path)
            
            # Confirm image sending
            result = messagebox.askyesno(
                    "Send Image",
                    f"Send clipboard image as '{temp_filename}' ({bytes_to_human_readable(file_size)})?"
            )
            
            if result:
                self.append_to_chat(f"Sending clipboard image: {temp_filename}")
                self.client.send_file(temp_path)
                
                # Schedule cleanup of temp file after a delay (to allow file transfer to complete)
                def cleanup_temp_file():
                    try:
                        time.sleep(5)  # Wait 5 seconds before cleanup
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except Exception:
                        pass  # Ignore cleanup errors
                
                threading.Thread(target=cleanup_temp_file, daemon=True).start()
            else:
                # User declined, clean up temp file immediately
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception:
                    pass  # Ignore cleanup errors
        
        except Exception as e:
            self.append_to_chat(f"Error handling clipboard image: {e}")
    
    def on_text_change(self, event=None):
        """Handle text changes in message entry for spellcheck."""
        if not self.spellcheck_enabled:
            return
        
        # Cancel existing timer if any
        if self.spellcheck_timer:
            self.root.after_cancel(self.spellcheck_timer)
        
        # Start new timer for 500ms delay
        self.spellcheck_timer = self.root.after(500, self.perform_spellcheck)
    
    def perform_spellcheck(self):
        """Perform spellcheck on the message entry text."""
        if not self.spellcheck_enabled:
            return
        
        try:
            # Get current text
            text = self.message_entry.get("1.0", tk.END).strip()
            
            # Clear existing misspelled tags
            for tag in self.misspelled_tags:
                self.message_entry.tag_delete(tag)
            self.misspelled_tags.clear()
            
            if not text:
                return
            
            # Split text into words and check spelling
            words = re.findall(r'\b[a-zA-Z]+\b', text)
            misspelled = self.spell_checker.unknown(words)
            
            if not misspelled:
                return
            
            # Find and tag misspelled words
            for word in misspelled:
                # Find all occurrences of this word
                start_pos = "1.0"
                while True:
                    pos = self.message_entry.search(word, start_pos, tk.END)
                    if not pos:
                        break
                    
                    # Check if this is a whole word (not part of another word)
                    char_before = self.message_entry.get(f"{pos}-1c") if pos != "1.0" else " "
                    char_after = self.message_entry.get(f"{pos}+{len(word)}c")
                    
                    if not char_before.isalpha() and not char_after.isalpha():
                        # Create unique tag for this occurrence
                        tag_name = f"misspelled_{len(self.misspelled_tags)}"
                        end_pos = f"{pos}+{len(word)}c"
                        
                        self.message_entry.tag_add(tag_name, pos, end_pos)
                        self.message_entry.tag_configure(tag_name, underline=True, underlinefg="red")
                        self.misspelled_tags.add(tag_name)
                    
                    start_pos = f"{pos}+1c"
        
        except Exception as e:
            # Silently ignore spellcheck errors to avoid disrupting user experience
            pass
    
    def show_spellcheck_menu(self, event):
        """Show context menu with spelling suggestions on right-click."""
        if not self.spellcheck_enabled:
            return
        
        try:
            # Get the position of the click
            click_pos = self.message_entry.index(f"@{event.x},{event.y}")
            
            # Get the entire line of text
            line_start = self.message_entry.index(f"{click_pos} linestart")
            line_end = self.message_entry.index(f"{click_pos} lineend")
            line_text = self.message_entry.get(line_start, line_end)
            
            # Find the word at the click position using regex
            click_col = int(click_pos.split('.')[1])
            word_match = None
            for match in re.finditer(r'\b[a-zA-Z]+\b', line_text):
                if match.start() <= click_col < match.end():
                    word_match = match
                    break
            
            if not word_match:
                return
            
            word = word_match.group(0)
            word_start = f"{line_start}+{word_match.start()}c"
            word_end = f"{line_start}+{word_match.end()}c"
            
            if not word or word not in self.spell_checker.unknown([word]):
                return  # Word is correctly spelled or empty
            
            # Create context menu
            context_menu = tk.Menu(self.root, tearoff=0)
            
            # Get suggestions
            suggestions = list(self.spell_checker.candidates(word))[:5]  # Limit to 5 suggestions
            
            if suggestions:
                for suggestion in suggestions:
                    context_menu.add_command(
                        label=suggestion,
                        command=lambda s=suggestion, start=word_start, end=word_end: self.replace_word(start, end, s)
                    )
                context_menu.add_separator()
            
            # Add "Add to dictionary" option
            context_menu.add_command(
                label="Add to dictionary",
                command=lambda w=word: self.add_to_dictionary(w)
            )
            
            # Show the menu
            context_menu.tk_popup(event.x_root, event.y_root)
        
        except Exception as e:
            # Silently ignore menu errors
            pass
    
    def replace_word(self, start_pos, end_pos, replacement):
        """Replace a word with the selected suggestion."""
        try:
            self.message_entry.delete(start_pos, end_pos)
            self.message_entry.insert(start_pos, replacement)
            # Trigger spellcheck after replacement
            self.on_text_change()
        except Exception:
            pass
    
    def add_to_dictionary(self, word):
        """Add a word to the personal dictionary."""
        try:
            self.spell_checker.word_frequency.load_words([word])
            # Trigger spellcheck to remove red underline
            self.on_text_change()
        except Exception:
            pass
    
    def emergency_close(self):
        """Handle emergency close (Control+Q) - send emergency message and close immediately."""
        try:
            if self.connected and self.client:
                # Send emergency close message as quickly as possible
                self.client.send_emergency_close()
                # Force immediate disconnect without waiting
                self.client.connected = False
                if self.client.socket:
                    self.client.socket.close()
            # Close the application immediately
            self.root.quit()
            self.root.destroy()
        except Exception as e:
            # Even if there's an error, still close the application
            print(f"Error during emergency close: {e}")
            self.root.quit()
            self.root.destroy()
    
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
            self.ephemeral_btn.config(bg="#ff6b6b", fg="#ffffff", text="Ephemeral ON")  # type: ignore
            self.append_to_chat("Ephemeral mode enabled - messages will disappear after 30 seconds", is_message=True)
        else:
            # About to disable ephemeral mode
            self.append_to_chat("Ephemeral mode disabled.", is_message=True)
            self.ephemeral_mode = False
            self.ephemeral_btn.config(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, text="Ephemeral")  # type: ignore
            
            # Remove all existing ephemeral messages
            all_message_ids = list(self.ephemeral_messages.keys())
            if all_message_ids:
                self.remove_ephemeral_messages(all_message_ids)
    
    def remove_ephemeral_messages(self, message_ids):
        """Remove ephemeral messages from the chat display."""
        try:
            self.chat_display.config(state=tk.NORMAL)  # type: ignore
            for message_id in message_ids:
                # Find the tagged message range
                tag_ranges = self.chat_display.tag_ranges(message_id)
                if tag_ranges:
                    # Delete the tagged text
                    self.chat_display.delete(tag_ranges[0], tag_ranges[1])
                
                # Remove from tracking dict
                self.ephemeral_messages.pop(message_id, None)
            
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)  # type: ignore
        
        except Exception:
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
    
    def _is_image_file(self, file_path: str) -> bool:
        """Check if a file is an image based on its extension."""
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.ico'}
        _, ext = os.path.splitext(file_path.lower())
        return ext in image_extensions
    
    def _display_received_image(self, file_path: str):
        """Display a received image file in a separate window."""
        try:
            if self.gui and self._is_image_file(file_path):
                # Load and display the image
                image = Image.open(file_path)
                self.gui.root.after(0, lambda: display_image(image, self.gui.root))
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error displaying received image: {e}"))
    
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
                
                if message_type == MessageType.FILE_METADATA:
                    self.handle_file_metadata(decrypted_text)
                elif message_type == MessageType.FILE_ACCEPT:
                    self.handle_file_accept(decrypted_text)
                elif message_type == MessageType.FILE_REJECT:
                    self.handle_file_reject(decrypted_text)
                elif message_type == MessageType.FILE_COMPLETE:
                    self.handle_file_complete(decrypted_text)
                elif message_type == MessageType.DELIVERY_CONFIRMATION:
                    self.handle_delivery_confirmation(message)
                else:
                    # It's a regular chat message
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}",
                                                                               is_message=True))
                    # Send delivery confirmation for text messages only
                    self._send_delivery_confirmation(received_message_counter)
            
            except (json.JSONDecodeError, TypeError):
                # If it's not JSON, it's a regular chat message
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}",
                                                                           is_message=True))
                # Send delivery confirmation for text messages only
                self._send_delivery_confirmation(received_message_counter)
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Failed to decrypt message: {e}"))
            else:
                print(f"\nFailed to decrypt message: {e}")
    
    def _send_delivery_confirmation(self, confirmed_counter: int) -> None:
        """Send a delivery confirmation for a received text message."""
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
                self.gui.root.after(0,
                                    lambda e=e: self.gui.append_to_chat(f"Error handling delivery confirmation: {e}"))
            else:
                print(f"\nError handling delivery confirmation: {e}")
    
    def handle_emergency_close(self, message_data: bytes) -> None:
        """Handle emergency close message from the other client - override to display in GUI."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            close_message = message.get("message", "Emergency close received")
            
            if self.gui:
                # Display emergency close message in GUI
                self.gui.root.after(0, lambda: self.gui.append_to_chat("🚨 EMERGENCY CLOSE RECEIVED"))
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"The other client has activated emergency close."))
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Message: {close_message}"))
                self.gui.root.after(0, lambda: self.gui.append_to_chat("Connection will be terminated immediately."))
            else:
                # Fallback to console output if no GUI
                print(f"\n{'=' * 50}")
                print("🚨 EMERGENCY CLOSE RECEIVED")
                print(f"The other client has activated emergency close.")
                print(f"Message: {close_message}")
                print("Connection will be terminated immediately.")
                print(f"{'=' * 50}")
            
            # Immediately disconnect
            self.disconnect()
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Error handling emergency close: {e}"))
            else:
                print(f"Error handling emergency close: {e}")
    
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
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        "Received key exchange response but no private key found"))
                else:
                    print("Received key exchange response but no private key found")
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.append_to_chat(f"Key exchange response error: {e}"))
            else:
                print(f"Key exchange response error: {e}")
    
    def handle_key_exchange_complete(self):
        """Handle key exchange completion notification - override to use GUI."""
        self.key_exchange_complete = True
        # Don't call start_key_verification() here as it would block the receive thread
        # The GUI monitoring thread will detect key_exchange_complete and show the dialogue
    
    def initiate_key_exchange(self):
        """Initiate key exchange as the first client - override to add GUI status update."""
        if self.gui:
            self.gui.root.after(0, lambda: self.gui.update_status("Processing key exchange"))
        super().initiate_key_exchange()
        
    
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
            
            if self.gui:
                def show_file_notification():
                    # Play notification sound
                    self.gui.play_notification_sound()
                    
                    # Show Windows notification if enabled
                    self.gui.show_windows_notification(f"Incoming file transfer: {metadata['filename']}")
                    
                    # Display file transfer information in chat
                    self.gui.append_to_chat("📁 INCOMING FILE TRANSFER")
                    self.gui.append_to_chat(f"Filename: {metadata['filename']}")
                    self.gui.append_to_chat(f"Size: {bytes_to_human_readable(metadata['file_size'])}")
                    self.gui.append_to_chat(f"Chunks: {metadata['total_chunks']}")
                    self.gui.append_to_chat("")
                    self.gui.append_to_chat("Type '/accept' or '/y' to accept the file transfer")
                    self.gui.append_to_chat("Type '/reject' or '/n' to reject the file transfer")
                    self.gui.append_to_chat("")
                    
                    # Store the transfer ID for command processing
                    if not hasattr(self, 'pending_file_requests'):
                        self.pending_file_requests = {}
                    self.pending_file_requests[transfer_id] = metadata
                
                self.gui.root.after(0, show_file_notification)
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
                    f"File transfer accepted. Sending {filename}..."))
            
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
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                        f"File transfer rejected: {filename} - {reason}"))
                del self.pending_file_transfers[transfer_id]
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda err=e: self.gui.append_to_chat(f"Error handling file rejection: {err}"))
            else:
                print(f"Error handling file rejection: {e}")
    
    
    def handle_file_chunk_binary(self, chunk_info: dict):
        """Handle incoming file chunk (optimized binary format) with GUI progress updates."""
        try:
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
                
                # Update GUI with transfer progress every 10 chunks
                if received_chunks % 10 == 0 or received_chunks == 1:
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.update_transfer_progress(
                            transfer_id, metadata['filename'], received_chunks, metadata['total_chunks'],
                            bytes_transferred
                    ))
            
            if is_complete:
                # Final progress update to ensure 100% is shown
                if self.gui:
                    final_bytes_transferred = metadata["file_size"]
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.update_transfer_progress(
                        transfer_id, metadata['filename'], metadata['total_chunks'], metadata['total_chunks'],
                        final_bytes_transferred
                    ))
                
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
                            f"File received successfully: {output_path}"))
                        # Clear speed when transfer completes
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                    
                    # Display image if it's an image file
                    self._display_received_image(output_path)
                    
                    # Send completion message
                    complete_msg = self.protocol.create_file_complete_message(transfer_id)
                    send_message(self.socket, complete_msg)
                
                except Exception as e:
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                            f"File reassembly failed: {e}"))
                
                # Clean up
                del self.active_file_metadata[transfer_id]
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(
                    f"Error handling binary file chunk: {e}"))
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
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                        f"File transfer completed: {filename}"))
                    # Clear speed when transfer completes
                    self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
                del self.pending_file_transfers[transfer_id]
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(
                    f"Error handling file completion: {e}"))
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
                
                # Show progress in GUI every 10 chunks
                if self.gui:
                    if i % 10 == 0:
                        filename = os.path.basename(file_path)
                        self.gui.root.after(0, lambda curr=i, total=total_chunks, bytes_sent=bytes_transferred,
                                                      fname=filename:
                        self.gui.file_transfer_window.update_transfer_progress(transfer_id, fname, curr, total,
                                                                               bytes_sent)
                                            )
            
            # Final update to ensure 100% progress is shown
            if self.gui:
                filename = os.path.basename(file_path)
                self.gui.root.after(0, lambda curr=total_chunks, total=total_chunks, bytes_sent=bytes_transferred,
                                              fname=filename:
                self.gui.file_transfer_window.update_transfer_progress(transfer_id, fname, curr, total, bytes_sent)
                                    )
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.add_transfer_message(
                    "File chunks sent successfully."))
                # Clear speed when transfer completes
                self.gui.root.after(0, lambda: self.gui.file_transfer_window.clear_speed())
        
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda e=e: self.gui.file_transfer_window.add_transfer_message(
                    f"Error sending file chunks: {e}"))
            else:
                print(f"Error sending file chunks: {e}")
    
    def handle_server_full(self) -> None:
        """Handle server full notification - override to display in GUI."""
        if self.gui:
            self.gui.root.after(0, lambda: self.gui.append_to_chat("Server is full. Please try again later."))
        else:
            print("Server is full. Please try again later.")
        
        self.disconnect()


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
    if TKINTERDND2_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    root.title("Secure Chat Client")
    
    # Load theme colors
    theme_colors = load_theme_colors()
    
    # Create GUI
    gui = ChatGUI(root, theme_colors)
    
    # Override the client creation to use our GUI-aware version
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
                except Exception as er:
                    gui.root.after(0, lambda error=er: gui.append_to_chat(f"Connection error: {error}"))
            
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
