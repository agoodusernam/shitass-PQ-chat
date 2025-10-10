# pylint: disable=trailing-whitespace, line-too-long
import base64
import json
import os
import re
import tempfile
import threading
import time
import tkinter as tk
import uuid
import wave
from collections import deque
from tkinter import scrolledtext, messagebox, filedialog
from typing import Callable, Any, Literal, ParamSpec

import config_handler
import config_manager

assert config_manager  # remove unused import warning
import configs
import shared

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
    Image = None
    ImageTk = None
    ImageGrab = None

# Plyer for system notifications
try:
    from plyer import notification
    
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    notification = None

# py-spellchecker for spell checking
try:
    from spellchecker import SpellChecker
    
    SPELLCHECKER_AVAILABLE = True
except ImportError:
    SPELLCHECKER_AVAILABLE = False
    SpellChecker = None

# tkinterdnd2 for drag-and-drop file support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    
    TKINTERDND2_AVAILABLE = True
except ImportError:
    TKINTERDND2_AVAILABLE = False
    DND_FILES = None
    TkinterDnD = None

try:
    import pyaudio
    
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False
    pyaudio = None

from client import SecureChatClient
from shared import bytes_to_human_readable, send_message, MessageType

P = ParamSpec('P')


class Ltk:
    """
    Literal types for Tkinter constants because type checking YAY
    """
    
    def __init__(self):
        self.W: Literal["w"] = "w"
        self.X: Literal["x"] = "x"
        self.Y: Literal["y"] = "y"
        self.BOTH: Literal["both"] = "both"
        self.RIGHT: Literal["right"] = "right"
        self.LEFT: Literal["left"] = "left"
        self.DISABLED: Literal["disabled"] = "disabled"
        self.NORMAL: Literal["normal"] = "normal"
        self.ACTIVE: Literal["active"] = "active"
        self.FLAT: Literal["flat"] = "flat"
        self.HORIZONTAL: Literal["horizontal"] = "horizontal"
        self.VERTICAL: Literal["vertical"] = "vertical"
        self.WORD: Literal["word"] = "word"
        self.NONE: Literal["none"] = "none"


ltk: Ltk = Ltk()


def get_image_from_clipboard() -> Image.Image | None:
    """Get an image from the clipboard."""
    if not PIL_AVAILABLE or not ImageGrab:
        return None
    try:
        image = ImageGrab.grabclipboard()
        if isinstance(image, Image.Image):
            return image
        
        return None
    except (OSError, ValueError):
        # Clipboard unsupported or empty / contains invalid data
        return None
    except Exception:  # Fallback: unexpected clipboard handling error
        # Intentional broad catch: we don't want clipboard issues to break the app
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
    
    label: tk.Label = tk.Label(window, image=photo) # type: ignore
    # Keep a reference to the image to prevent it from being garbage collected
    label.image = photo
    label.pack()


class FileTransferWindow:
    """Separate window for file transfer progress and status updates."""
    
    def __init__(self, parent_root: tk.Tk, theme_colors=None, theme_colours=None):
        # noinspection PyUnresolvedReferences
        """
        Initialise the file transfer window manager.
                
        Args:
            parent_root (tk.Tk): The parent root window that this transfer window
                will be associated with.
            theme_colors (dict): Dictionary of theme colours to use.
            
        Attributes:
            parent_root (tk.Tk): Reference to the parent window.
            window (tk.Toplevel): The actual transfer window (created on demand).
            transfers (dict): Dictionary mapping transfers IDs to transfer information.
            speed_label (tk.Label): Label widget displaying the current transfer speed.
            transfer_list (scrolledtext.ScrolledText): Text widget showing transfer messages.
            last_update_time (float): Timestamp of the last speed calculation update.
            last_bytes_transferred (int): Bytes transferred at last speed update.
            current_speed (float): Current transfer speed in bytes per second.
            BG_COLOR (str): Background colour for dark theme.
            FG_COLOR (str): Foreground text colour for dark theme.
            ENTRY_BG_COLOR (str): Background colour for entry widgets.
            BUTTON_BG_COLOR (str): Background colour for button widgets.
        """
        if theme_colours is not None:
            theme_colors = theme_colours
        if not isinstance(theme_colors, dict):
            theme_colors: dict[str, str] = {}
        self.parent_root = parent_root
        self.window: tk.Toplevel | None = None
        self.speed_label: tk.Label | None = None
        self.transfer_list: scrolledtext.ScrolledText | None = None
        
        # Speed calculation variables
        self.last_update_time: float = time.time()
        self.last_bytes_transferred: int = 0
        self.current_speed: float = 0.0
        
        # Theme colors (use provided theme or defaults)
        if theme_colors:
            self.BG_COLOR = theme_colors["BG_COLOR"]
            self.FG_COLOR = theme_colors["FG_COLOR"]
            self.ENTRY_BG_COLOR = theme_colors["ENTRY_BG_COLOR"]
            self.BUTTON_BG_COLOR = theme_colors["BUTTON_BG_COLOR"]
            self.TEXT_BG_COLOR = theme_colors["TEXT_BG_COLOR"]
            self.SPEED_LABEL_COLOR = theme_colors["SPEED_LABEL_COLOR"]
        else:
            # Default dark theme colors
            self.BG_COLOR = "#2b2b2b"
            self.FG_COLOR = "#d4d4d4"
            self.ENTRY_BG_COLOR = "#3c3c3c"
            self.BUTTON_BG_COLOR = "#555555"
            self.TEXT_BG_COLOR = "#1e1e1e"
            self.SPEED_LABEL_COLOR = "#4CAF50"
    
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
            top_frame.pack(fill=ltk.X, padx=10, pady=5)
            
            # Speed label in top right
            self.speed_label = tk.Label(
                    top_frame,
                    text="Speed: 0.0 MiB/s",
                    bg=self.BG_COLOR,
                    fg=self.SPEED_LABEL_COLOR,
                    font=("Consolas", 10, "bold")
            )
            self.speed_label.pack(side=ltk.RIGHT)
            
            # Title label
            title_label = tk.Label(
                    top_frame,
                    text="File Transfers",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold")
            )
            title_label.pack(side=ltk.LEFT)
            
            # Main frame for transfer list
            main_frame = tk.Frame(self.window, bg=self.BG_COLOR)
            main_frame.pack(fill=ltk.BOTH, expand=True, padx=10, pady=5)
            
            # Scrollable text area for transfer updates
            self.transfer_list = scrolledtext.ScrolledText(
                    main_frame,
                    state=ltk.DISABLED,
                    wrap=ltk.WORD,
                    height=20,
                    font=("Consolas", 9),
                    bg=self.TEXT_BG_COLOR,
                    fg=self.FG_COLOR,
                    insertbackground=self.FG_COLOR,
                    relief=ltk.FLAT
            )
            self.transfer_list.pack(fill=ltk.BOTH, expand=True)
            
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
    
    def add_transfer_message(self, message: str):
        """Add a message to the transfer window."""
        self.create_window()
        
        if self.transfer_list:
            self.transfer_list.config(state=ltk.NORMAL)
            timestamp = time.strftime("%H:%M:%S")
            self.transfer_list.insert(tk.END, f"[{timestamp}] {message}\n")
            self.transfer_list.see(tk.END)
            self.transfer_list.config(state=ltk.DISABLED)
        
        # Show window if not visible
        if self.window.state() == 'withdrawn':
            self.show_window()
    
    def update_transfer_progress(self, /, filename: str, current: int, total: int, bytes_transferred: int = -1,
                                 comp_text: str = ""):
        """
        Update the progress of a file transfer.
        :param filename: The name of the file being transferred.
        :param current: The current progress in chunks.
        :param total: The total number of chunks.
        :param bytes_transferred: Total bytes transferred so far (for speed calculation).
        :param comp_text: Optional compression status text. (e.g., "compressed", "uncompressed")
        :return:
        """
        """Update progress for a specific transfer."""
        progress = (current / total) * 100 if total > 0 else 0
        
        # Calculate speed if bytes_transferred is provided
        if bytes_transferred != -1:
            self.update_speed(bytes_transferred)
        
        # Include compression status if provided
        compression_info = f" ({comp_text})" if comp_text != "" else ""
        message = f"{filename}: {progress:.1f}% ({current}/{total} chunks){compression_info}"
        self.add_transfer_message(message)
    
    def update_speed(self, total_bytes_transferred: int):
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


# noinspection PyBroadException
class ChatGUI:
    """
    Graphical User Interface for a secure chat client.

    This class defines a Tkinter-based GUI for a secure chat client, offering
    functionality for managing chat connections, configuring settings, sending
    notifications, and interacting with various components such as spellchecking
    and file transfers. It provides features like ephemeral messages, theme-based
    design, voice calling (if supported), and system notifications, enhancing the
    user experience.
    
    """
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("950x600")
        
        # Store the theme colors dictionary
        self.theme_colors = load_theme_colors()
        
        self.BG_COLOR = self.theme_colors["BG_COLOR"]
        self.FG_COLOR = self.theme_colors["FG_COLOR"]
        self.ENTRY_BG_COLOR = self.theme_colors["ENTRY_BG_COLOR"]
        self.BUTTON_BG_COLOR = self.theme_colors["BUTTON_BG_COLOR"]
        self.BUTTON_ACTIVE_BG = self.theme_colors["BUTTON_ACTIVE_BG"]
        self.TEXT_BG_COLOR = self.theme_colors["TEXT_BG_COLOR"]
        
        self.root.configure(bg=self.BG_COLOR)
        
        # Chat client instance
        self.client: GUISecureChatClient | None = None
        self.connected = False
        self.peer_nickname = "Other user"
        self.config: config_handler.ConfigHandler = config_handler.ConfigHandler()
        
        # Ephemeral mode state
        # Modes: "OFF", "LOCAL", "GLOBAL"
        self.ephemeral_mode: str = "OFF"
        self.ephemeral_global_owner_id: str = ""
        self.local_client_id: str = str(uuid.uuid4())
        self.ephemeral_messages: dict[str, float] = {}  # Track messages with timestamps for removal
        self.message_counter: int = 0
        
        # Delivery confirmation tracking
        self.sent_messages = {}  # Track sent messages: {message_counter: tag_id}
        self.sent_message_tags = {}  # Track tag IDs for sent messages: {tag_id: message_counter}
        
        # Notification sound settings
        self.notification_enabled = self.config["notification_sound"]
        self.window_focused = True
        
        # Windows system notification settings
        self.windows_notifications_enabled = self.config["system_notifications"] and PLYER_AVAILABLE
        
        # Additional settings
        self.allow_voice_calls = self.config["allow_voice_calls"] and PYAUDIO_AVAILABLE
        self.auto_display_images = self.config["auto_display_images"] and PIL_AVAILABLE
        
        # File transfer window with theme colors
        self.file_transfer_window = FileTransferWindow(self.root, self.theme_colors)
        
        # Spellcheck functionality
        self.spell_checker: SpellChecker | None = SpellChecker() if SpellChecker is not None else None
        self.spellcheck_timer: str = ""
        self.spellcheck_enabled: bool = SPELLCHECKER_AVAILABLE
        self.misspelled_tags: set[str] = set()
        
        # Create GUI elements
        self.create_widgets()
        
        # Setup window focus tracking
        self.setup_focus_tracking()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def on_tk_thread(self, func: Callable[P, Any], /, *args: P.args, **kwargs: P.kwargs) -> None:
        """Run a function on the Tkinter main thread."""
        self.root.after(0, lambda: func(*args, **kwargs)) # type: ignore
        return None
    
    def no_types_tk_thread(self, func: Callable, /, *args, **kwargs) -> None:
        """Run a function on the Tkinter main thread (no type checking)."""
        self.root.after(0, lambda: func(*args, **kwargs)) # type: ignore
        return None
    
    def setup_focus_tracking(self):
        """Setup window focus tracking for notification sounds."""
        
        def on_focus_in(_):
            self.window_focused = True
        
        def on_focus_out(_):
            self.window_focused = False
        
        # Bind focus events to the root window
        self.root.bind("<FocusIn>", on_focus_in)
        self.root.bind("<FocusOut>", on_focus_out)
        
        # Bind Control+Q for emergency close at window level
        self.root.bind("<Control-q>", self.emergency_close)
    
    def play_notification_sound(self):
        """Play a notification sound if the window is not focused."""
        if not self.notification_enabled or self.window_focused:
            return
        
        try:
            if os.path.exists(configs.MESSAGE_NOTIF_SOUND_FILE) and WINSOUND_AVAILABLE and winsound:
                threading.Thread(
                        target=winsound.PlaySound,
                        args=(configs.MESSAGE_NOTIF_SOUND_FILE, winsound.SND_FILENAME),
                        daemon=True
                ).start()
        except (FileNotFoundError, OSError) as e:
            # Non-critical: sound file missing or device error
            pass
        except Exception:
            # Unexpected winsound failure is ignored to avoid disrupting UX
            pass
    
    def show_windows_notification(self, message_text: str):
        """Show a Windows system notification if the window is not focused."""
        if not self.windows_notifications_enabled or self.window_focused or not PLYER_AVAILABLE or not notification:
            return
        
        try:
            display_message = message_text.replace("Other user: ", "")
            
            def show_notification():
                try:
                    notification.notify(
                            title="Secure Chat Notification",
                            message=display_message,
                            app_name="Secure Chat Client",
                            timeout=5,
                            app_icon=None
                    )
                except (ValueError, OSError):
                    # Notification backend error (non-fatal)
                    pass
                except Exception:
                    # Unexpected plyer error - ignored to avoid breaking UI thread
                    pass
            
            threading.Thread(target=show_notification, daemon=True).start()
        except (RuntimeError, OSError):
            # Thread start or system limitation; safe to ignore
            pass
        except Exception:
            # Unexpected outer failure; non-critical
            pass
    
    # noinspection PyAttributeOutsideInit
    def create_widgets(self):
        """Create the GUI widgets."""
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
        
        if PYAUDIO_AVAILABLE:
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
                bg=self.BG_COLOR, fg=self.theme_colors.get("STATUS_NOT_CONNECTED", "#ff6b6b"),
                font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=ltk.RIGHT, padx=(10, 0))
        
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(
                main_frame,
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
        if TKINTERDND2_AVAILABLE:
            self.chat_display.drop_target_register(DND_FILES)  # type: ignore
            self.chat_display.dnd_bind('<<Drop>>', self.handle_drop)  # type: ignore
        
        # Input frame
        self.input_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        self.input_frame.pack(fill=ltk.X)
        
        # Message input
        self.message_entry = tk.Text(
                self.input_frame, height=1, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR, width=15,
                insertbackground=self.FG_COLOR, relief=ltk.FLAT, wrap=ltk.NONE
        )
        self.message_entry.pack(side=ltk.LEFT, fill=ltk.X, expand=True, padx=(0, 10))
        
        # Configure text tags for spellcheck
        self.message_entry.tag_configure("misspelled", underline=True,
                                         underlinefg=self.theme_colors.get("SPELLCHECK_ERROR_COLOR", "red"))
        
        # Bind events
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        self.message_entry.bind("<Control-v>", self.on_paste)
        self.message_entry.bind("<KeyRelease>", self.on_text_change)
        self.message_entry.bind("<Button-1>", self.on_text_change)
        self.message_entry.bind("<Button-3>", self.show_spellcheck_menu)
        
        # Ephemeral mode dropdown (OFF, LOCAL, GLOBAL)
        self.ephemeral_mode_var = tk.StringVar(value="OFF")
        self.ephemeral_menu = tk.OptionMenu(
                self.input_frame,
                self.ephemeral_mode_var,
                "OFF", "LOCAL", "GLOBAL",
                command=self.on_ephemeral_change
        )
        # Basic styling to match theme (not all OptionMenu elements honor bg/fg across platforms)
        try:
            self.ephemeral_menu.config(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR,
                                       activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                                       relief=ltk.FLAT)
        except (tk.TclError, AttributeError):
            # Some platforms/widgets may not support styling all attributes
            pass
        except Exception:
            # Ignore unexpected styling issues; purely cosmetic
            pass
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
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_file_btn.pack(side=ltk.RIGHT, padx=(0, 5))
        
        # Bind button click event to detect shift key
        self.send_file_btn.bind("<Button-1>", self.on_send_file_click)
        
        # Send button
        self.send_btn = tk.Button(
                self.input_frame, text="Send", command=self.send_message,
                bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR
        )
        self.send_btn.pack(side=ltk.RIGHT)
        
        # Initially disable input until connected
        self.message_entry.config(state=ltk.DISABLED)
        self.send_btn.config(state=ltk.DISABLED)
        self.send_file_btn.config(state=ltk.DISABLED)
        try:
            self.ephemeral_menu.config(state=ltk.DISABLED)
        except Exception:
            pass
        self.file_transfer_btn.config(state=ltk.DISABLED)
        
        # Start ephemeral message cleanup thread
        self.start_ephemeral_cleanup()
    
    def handle_drop(self, event):
        """Handle file drop events."""
        if not TKINTERDND2_AVAILABLE:
            self.append_to_chat("Drag-and-drop support is not available.")
            return
        if not self.connected or not self.client:
            return
        
        if not self.client.verification_complete:
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
            self.confirm_and_send_file(file_path, compress=True)  # Default to compressed for drag-and-drop
    
    def confirm_and_send_file(self, file_path, compress=True):
        """Ask for confirmation and then send the file."""
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            compression_text = "compressed" if compress else "uncompressed"
            result = messagebox.askyesno(
                    "Send File",
                    f"Send file '{file_name}' ({bytes_to_human_readable(file_size)}) {compression_text}?"
            )
            
            if result:
                self.append_to_chat(f"Sending file: {file_name} ({compression_text})")
                self.client.send_file(file_path, compress=compress)
        except (FileNotFoundError, PermissionError) as e:
            self.append_to_chat(f"File send error (file access): {e}")
        except (OSError, ValueError) as e:
            self.append_to_chat(f"File send error (I/O): {e}")
        except Exception as e:
            self.append_to_chat(f"File send error (unexpected): {e}")
    
    def append_to_chat(self, text, is_message=False, show_time=True):
        """
        Append text to the chat display.
        Automatically runs on the Tkinter thread.
        """
        self.on_tk_thread(self._append_to_chat, text, is_message, show_time)
    
    def _append_to_chat(self, text, is_message=False, show_time=True):
        """
        Append text to the chat display.
        Must be run on the Tkinter thread.
        """
        text = str(text)
        self.chat_display.config(state=ltk.NORMAL)
        formatted_time = time.strftime("%H:%M:%S")
        
        # If ephemeral mode is enabled and this is a message, track it
        if (self.ephemeral_mode in ("LOCAL", "GLOBAL")) and is_message:
            self.message_counter += 1
            message_id = f"msg_{self.message_counter}"
            self.ephemeral_messages[message_id] = time.time()
            
            # Add invisible marker for tracking using tags
            # The tag is applied to the entire line including the newline character
            start_index = self.chat_display.index("end-1c")
            if show_time:
                self.chat_display.insert(tk.END, f"[{formatted_time}] {text}\n")
            else:
                self.chat_display.insert(tk.END, f"{text}\n")
            end_index = self.chat_display.index("end-1c")
            self.chat_display.tag_add(message_id, start_index, end_index)
        else:
            if show_time:
                self.chat_display.insert(tk.END, f"[{formatted_time}] {text}\n")
            else:
                self.chat_display.insert(tk.END, f"{text}\n")
        
        # Play notification sound and show Windows notification if this is a message from another user
        if is_message and text.startswith("Other user:"):
            self.play_notification_sound()
            self.show_windows_notification(text)
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=ltk.DISABLED)
    
    def append_to_chat_with_delivery_status(self, text: str, message_counter: int):
        """Append text to chat display with delivery status tracking for sent messages."""
        self.chat_display.config(state=ltk.NORMAL)
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
            if (self.ephemeral_mode in ("LOCAL", "GLOBAL")):
                self.ephemeral_messages[tag_id] = time.time()
        
        # Play notification sound and show Windows notification if this is a message from another user
        if text.startswith("Other user:"):
            self.play_notification_sound()
            self.show_windows_notification(text)
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=ltk.DISABLED)
    
    def update_message_delivery_status(self, message_counter):
        """Update the delivery status of a sent message to show it was delivered."""
        if message_counter in self.sent_messages:
            tag_id = self.sent_messages[message_counter]
            
            self.chat_display.config(state=ltk.NORMAL)
            
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
            
            self.chat_display.config(state=ltk.DISABLED)
    
    def update_status(self, status_text, color=None):
        """
        Update the status indicator with new text and color.
        Automatically runs on the Tkinter thread.
        """
        self.on_tk_thread(self._update_status, status_text, color)
    
    def _update_status(self, status_text, color=None):
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
                color = self.theme_colors["STATUS_NOT_CONNECTED"]
        
        self.status_label.config(text=status_text, fg=color)
    
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
        if hasattr(self, "sound_btn") and getattr(self, "sound_btn", None):
            if self.notification_enabled:
                self.sound_btn.config(text="Notif sounds ON")
            else:
                self.sound_btn.config(text="Notif sounds OFF")
    
    def toggle_windows_notifications(self):
        """Toggle Windows system notifications on/off."""
        self.windows_notifications_enabled = not self.windows_notifications_enabled
    
    def save_and_destroy_config_window(self):
        """Save settings from the config window and close it."""
        self.config_from_vars()
        try:
            if hasattr(self, "config_window") and self.config_window and self.config_window.winfo_exists():
                self.config_window.destroy()
        except Exception:
            pass
        return
    
    def config_from_vars(self):
        """Update config settings from internal variables"""
        self.config["notification_sound"] = self.notification_enabled
        self.config["system_notifications"] = self.windows_notifications_enabled
        self.config["auto_display_images"] = self.auto_display_images
        self.config["allow_voice_calls"] = self.allow_voice_calls
        if self.client:
            self.config["allow_file_transfer"] = self.client.allow_file_transfers
            self.config["delivery_receipts"] = self.client.send_delivery_receipts
            self.config["peer_nickname_change"] = self.client.nickname_change_allowed
        self.config.save()
        if self.client:
            self.client.protocol.config.reload()
        return
    
    # noinspection PyAttributeOutsideInit
    def open_config_dialog(self):
        """Open a small configuration window with common settings."""
        try:
            if hasattr(self, "config_window") and self.config_window and self.config_window.winfo_exists():
                self.config_window.lift()
                self.config_window.focus_set()
                return
        except Exception:
            pass
        
        self.config_window = tk.Toplevel(self.root)
        self.config_window.title("Configuration")
        try:
            self.config_window.configure(bg=self.BG_COLOR)
        except Exception:
            pass
        self.config_window.resizable(False, False)
        
        container = tk.Frame(self.config_window, bg=self.BG_COLOR)
        container.pack(padx=10, pady=10, fill=ltk.BOTH, expand=True)
        
        # Tk variables reflecting current settings
        self.var_sound_notif: tk.BooleanVar = tk.BooleanVar(value=self.notification_enabled)
        self.var_system_notif: tk.BooleanVar = tk.BooleanVar(value=self.windows_notifications_enabled)
        self.var_auto_images: tk.BooleanVar = tk.BooleanVar(value=self.client.display_images if self.client else True)
        self.var_allow_calls: tk.BooleanVar = tk.BooleanVar(value=self.allow_voice_calls)
        self.var_allow_file_transfers: tk.BooleanVar = tk.BooleanVar(
                value=self.client.allow_file_transfers if self.client else True)
        self.var_send_delivery_receipts: tk.BooleanVar = tk.BooleanVar(
                value=self.client.send_delivery_receipts if self.client else True)
        self.var_nickname_change_allowed = tk.BooleanVar(
                value=self.client.nickname_change_allowed if self.client else False)
        # New: Peer nickname StringVar for manual setting
        try:
            current_peer_nick: str = (self.client.peer_nickname if self.client else self.peer_nickname)
        except Exception:
            current_peer_nick: str = self.peer_nickname
        self.var_peer_nickname: tk.StringVar = tk.StringVar(value=current_peer_nick)
        
        # Checkbuttons
        cb1 = tk.Checkbutton(
                container,
                text="Notification sounds",
                variable=self.var_sound_notif,
                command=lambda: setattr(self, 'notification_enabled', self.var_sound_notif.get()),
        )
        
        cb2 = tk.Checkbutton(
                container,
                text="System notifications",
                variable=self.var_system_notif,
                command=lambda: setattr(self, 'windows_notifications_enabled', self.var_system_notif.get()),
        )
        
        cb3 = tk.Checkbutton(
                container,
                text="Auto-display images",
                variable=self.var_auto_images,
                command=lambda: (
                    setattr(self.client, 'display_images', self.var_auto_images.get()) if self.client else None),
        )
        
        cb4 = tk.Checkbutton(
                container,
                text="Allow voice calls",
                variable=self.var_allow_calls,
                command=lambda: setattr(self, 'allow_voice_calls', self.var_allow_calls.get()),
        )
        
        cb5 = tk.Checkbutton(
                container,
                text="Allow file transfers",
                variable=self.var_allow_file_transfers,
                command=lambda: (setattr(self.client, 'allow_file_transfers',
                                         self.var_allow_file_transfers.get()) if self.client else True),
        )
        
        cb6 = tk.Checkbutton(
                container,
                text="Send delivery receipts",
                variable=self.var_send_delivery_receipts,
                command=lambda: (setattr(self.client, 'send_delivery_receipts',
                                         self.var_send_delivery_receipts.get()) if self.client else True),
        )
        
        cb7 = tk.Checkbutton(
                container,
                text="Allow peer to change their nickname",
                variable=self.var_nickname_change_allowed,
                command=lambda: (setattr(self.client, 'nickname_change_allowed',
                                         self.var_nickname_change_allowed.get()) if self.client else True),
        )
        
        # Try to style to match theme (some platforms may ignore)
        for cb in (cb1, cb2, cb3, cb4, cb5, cb6, cb7):
            try:
                cb.configure(bg=self.BG_COLOR, fg=self.FG_COLOR, selectcolor=self.BUTTON_BG_COLOR,
                             activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR)
            except Exception:
                pass
            cb.pack(anchor="w", pady=2)
        
        # Peer nickname controls
        nick_frame = tk.Frame(container, bg=self.BG_COLOR)
        try:
            tk.Label(nick_frame, text="Peer nickname:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side="left",
                                                                                                 padx=(0, 6))
        except Exception:
            tk.Label(nick_frame, text="Peer nickname:").pack(side="left", padx=(0, 6))
        
        try:
            nick_entry = tk.Entry(nick_frame, textvariable=self.var_peer_nickname, bg=self.ENTRY_BG_COLOR,
                                  fg=self.FG_COLOR, insertbackground=self.FG_COLOR)
        except Exception:
            nick_entry = tk.Entry(nick_frame, textvariable=self.var_peer_nickname)
        nick_entry.pack(side="left", fill=ltk.X, expand=True)
        
        def apply_peer_nickname():
            try:
                new_nick = (self.var_peer_nickname.get() or "").strip()
                if not new_nick:
                    new_nick = "Other user"
                # Update both GUI cache and client (if available)
                self.peer_nickname = new_nick
                if self.client:
                    self.client.peer_nickname = new_nick
                
                self.append_to_chat(f"[SYSTEM] Peer nickname set to: {new_nick}", is_message=False, show_time=False)
            except Exception:
                try:
                    messagebox.showerror("Error", "Failed to set peer nickname")
                except Exception:
                    pass
        
        try:
            apply_btn = tk.Button(nick_frame, text="Apply", command=apply_peer_nickname, bg=self.BUTTON_BG_COLOR,
                                  fg=self.FG_COLOR, activebackground=self.BUTTON_ACTIVE_BG,
                                  activeforeground=self.FG_COLOR)
        except Exception:
            apply_btn = tk.Button(nick_frame, text="Apply", command=apply_peer_nickname)
        apply_btn.pack(side="left", padx=(6, 0))
        nick_frame.pack(fill=ltk.X, pady=(8, 4))
        
        # Close button
        close_btn = tk.Button(
                container,
                text="Close",
                command=self.save_and_destroy_config_window,
                bg=self.BUTTON_BG_COLOR,
                fg=self.FG_COLOR,
                relief=ltk.FLAT,
                activebackground=self.BUTTON_ACTIVE_BG,
                activeforeground=self.FG_COLOR,
        )
        close_btn.pack(pady=(8, 0), anchor="e")
    
    def start_call(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        
        if not self.client:
            messagebox.showwarning("Warning", "Client not initialized")
            return
        
        if not self.client.verification_complete:
            messagebox.showwarning("Warning", "Cannot start call - verification not complete")
            return
        
        self.voice_call_btn.config(state=ltk.DISABLED)
        
        VOICE_SAMPLE_RATE = 44100
        CHUNK = int(VOICE_SAMPLE_RATE * 0.01)
        FORMAT = pyaudio.paInt32
        self.client.request_voice_call(rate=44100, chunk_size=CHUNK, audio_format=FORMAT)
    
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
            self.client = GUISecureChatClient(self, host, port)
            if not self.client.connect():
                self.on_tk_thread(self.append_to_chat, "Connection failed.")
                self.on_tk_thread(self.update_status, "Not Connected")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def on_connected(self):
        """Called when successfully connected."""
        self.connected = True
        self.connect_btn.config(text="Disconnect")
        self.host_entry.config(state=ltk.DISABLED)
        self.port_entry.config(state=ltk.DISABLED)
        self.message_entry.config(state=ltk.NORMAL)
        self.send_btn.config(state=ltk.NORMAL)
        self.send_file_btn.config(state=ltk.NORMAL)
        self.ephemeral_menu.config(state=ltk.NORMAL)
        self.file_transfer_btn.config(state=ltk.NORMAL)
        self.message_entry.focus()
        self.update_status("Connected, waiting for other client")
        self.start_chat_monitoring()
    
    def disconnect_from_server(self):
        """Disconnect from the server."""
        self.client.disconnect()
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.host_entry.config(state=ltk.NORMAL)
        self.port_entry.config(state=ltk.NORMAL)
        self.message_entry.config(state=ltk.DISABLED)
        self.send_btn.config(state=ltk.DISABLED)
        self.send_file_btn.config(state=ltk.DISABLED)
        try:
            self.ephemeral_menu.config(state=ltk.DISABLED)
        except Exception:
            pass
        self.file_transfer_btn.config(state=ltk.DISABLED)
        self.append_to_chat("Disconnected from server.")
        self.update_status("Not Connected")
    
    def start_chat_monitoring(self):
        """Start monitoring the chat client for messages and status updates."""
        
        def monitor_thread():
            try:
                while self.connected and self.client and self.client.connected:
                    # Check if key exchange is complete and verification is needed
                    if (self.client.key_exchange_complete and
                            not self.client.verification_started):
                        # Mark that we've started verification to avoid repeated prompts
                        self.client.verification_started = True
                        
                        # Show verification dialogue
                        self.on_tk_thread(self.show_verification_dialog)
                    
                    time.sleep(0.1)
            
            except Exception as e:
                self.append_to_chat(f"Monitor error: {e}")
        
        threading.Thread(target=monitor_thread, daemon=True).start()
    
    def show_verification_dialog(self):
        """
        Show the key verification dialogue using non-intrusive notification.
        Must be run from the main Tkinter thread.
        """
        if not self.client:
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
            self.append_to_chat("Please verify the key to start secure messaging!")
            
            # Store the verification state for later processing
            self.client.verification_pending = True
        
        except Exception as e:
            self._append_to_chat(f"Verification error: {e}")
    
    def verify_yes(self) -> None:
        """Handle '/y' command to confirm key verification."""
        try:
            self.client.confirm_key_verification(True)
            self.client.verification_pending = False
            self.append_to_chat("✅ You verified the peer's key.")
            self.update_status("Verified, Secure")
            self.append_to_chat("You can now send messages!")
        except Exception as e:
            self.append_to_chat(f"Verification error: {e}")
        
        return None
    
    def verify_no(self) -> None:
        """Handle '/n' command to deny key verification."""
        try:
            self.client.confirm_key_verification(False)
            self.client.verification_pending = False
            self.append_to_chat("You did not verify the peer's key.")
            self.update_status("Not Verified, Secure")
            self.append_to_chat("You can now send messages!")
        except Exception as e:
            self.append_to_chat(f"Verification error: {e}")
        self.message_entry.delete("1.0", tk.END)
        return None
    
    def file_transfer_yes(self) -> None:
        # Handle file transfer acceptance when no verification is pending
        transfer_id = list(self.client.pending_file_requests.keys())[-1]
        metadata = self.client.pending_file_requests[transfer_id]
        try:
            # Prompt for save location with filename pre-filled
            initial_file = metadata.get('filename', 'received_file')
            _, ext = os.path.splitext(initial_file)
            selected_path = filedialog.asksaveasfilename(
                    title="Save incoming file as...",
                    initialfile=initial_file,
                    defaultextension=ext if ext else "",
                    filetypes=[("All files", "*.*")]
            )
            if not selected_path:
                self.file_transfer_no()
                return None
            # Persist chosen save path for later reassembly
            if transfer_id in self.client.active_file_metadata:
                self.client.active_file_metadata[transfer_id]['save_path'] = selected_path
            else:
                metadata['save_path'] = selected_path
            
            # Send acceptance
            self.client.protocol.queue_message(("encrypt_json", {
                "type":        MessageType.FILE_ACCEPT,
                "transfer_id": transfer_id,
            }))
            self.client.protocol.send_dummy_messages = False
            
            self.file_transfer_window.add_transfer_message(
                    f"File transfer accepted: {metadata['filename']}")
            
            self.append_to_chat(f"Accepted file transfer: {metadata['filename']}")
            # Remove from pending requests
            del self.client.pending_file_requests[transfer_id]
        
        except Exception as e:
            self.append_to_chat(f"Error accepting file transfer: {e}")
        
        self.message_entry.delete("1.0", tk.END)
        return None
    
    def file_transfer_no(self) -> None:
        # Handle file transfer rejection when no verification is pending
        transfer_id = list(self.client.pending_file_requests.keys())[-1]
        metadata = self.client.pending_file_requests[transfer_id]
        try:
            # Send rejection
            self.client.protocol.queue_message(("encrypt_json", {
                "type":        MessageType.FILE_REJECT,
                "transfer_id": transfer_id,
                "reason":      "User declined",
            }))
            self.file_transfer_window.add_transfer_message("File transfer rejected.")
            self.append_to_chat(f"Rejected file transfer: {metadata['filename']}")
            # Remove from pending requests and active metadata
            del self.client.pending_file_requests[transfer_id]
            if transfer_id in self.client.active_file_metadata:
                del self.client.active_file_metadata[transfer_id]
        
        except Exception as e:
            self.append_to_chat(f"Error rejecting file transfer: {e}")
        
        return None
    
    def send_message(self, event=None):
        """
        Send a message.
        Must be run from the main Tkinter thread.
        """
        # Prevent the default newline insertion on Return key press
        if event and event.keysym == "Return":
            # Allow Shift+Return to insert a newline for multi-line messages in the future
            if event.state & 0x0001:  # Check if Shift key is not pressed
                return None  # Do not send, allow newline
        
        if not self.connected or not self.client:
            return "break"
        
        message = self.message_entry.get("1.0", "end-1c").strip()
        if not message:
            return "break"
        
        # Handle special commands (these work even during verification)
        if message.lower() == '/quit':
            self.disconnect_from_server()
            self.message_entry.delete("1.0", tk.END)
            return "break"
        if message.lower() == '/verify':
            self.show_verification_dialog()
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower() == '/rekey':
            if self.client.verification_complete:
                self.append_to_chat("Generating fresh keys")
                self.client.initiate_rekey()
            else:
                self.append_to_chat("Cannot rekey - verification not complete")
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower() == '/help':
            self.append_to_chat("Available commands:")
            self.append_to_chat("/help - Show this help message")
            self.append_to_chat("/verify - Show the key verification instructions")
            self.append_to_chat("/y or /yes - Confirm key verification or accept file transfer")
            self.append_to_chat("/n or /no - Deny key verification or reject file transfer")
            self.append_to_chat("/rekey - Generate a new key pair and restart key exchange (requires prior verification)")
            self.append_to_chat("/quit - Disconnect and exit the application")
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        # Handle verification commands
        if message.lower() in ['/vy', '/verify yes', '/yes', '/y', '/accept']:
            self.message_entry.delete("1.0", tk.END)
            if self.client.verification_pending:
                self.verify_yes()
                return "break"
            
            elif self.client.pending_file_requests:
                self.file_transfer_yes()
                return "break"
            
            else:
                self.append_to_chat("No verification or file transfer pending.")
                return "break"
        
        if message.lower() in ['/vn', '/verify no', '/no', '/n', '/reject']:
            self.message_entry.delete("1.0", tk.END)
            if self.client.verification_pending:
                self.verify_no()
                return "break"
            if self.client.pending_file_requests:
                self.file_transfer_no()
                return "break"
            else:
                self.append_to_chat("No verification or file transfer pending.")
                self.message_entry.delete("1.0", tk.END)
                return "break"
        
        if message.lower().strip() == '/shrug':
            shrug = "¯\\_(ツ)_/¯"
            self.client.protocol.queue_message(shrug)
            self.append_to_chat(shrug)
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower().strip() == '/tableflip':
            tableflip = "(╯°□°)╯︵ ┻━┻"
            self.client.protocol.queue_message(tableflip)
            self.append_to_chat(tableflip)
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower().strip() == '/unflip':
            unflip = "┬─┬ノ( º _ ºノ)"
            self.client.protocol.queue_message(unflip)
            self.append_to_chat(unflip)
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower().strip() == '/lenny':
            lenny = "( ͡° ͜ʖ ͡°)"
            self.client.protocol.queue_message(lenny)
            self.append_to_chat(lenny)
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        if message.lower().strip().startswith('/nick '):
            new_nick = message[6:].strip()
            if new_nick:
                self.client.protocol.queue_message(("encrypt_json", {
                    "type":     MessageType.NICKNAME_CHANGE,
                    "nickname": new_nick,
                }))
                self.append_to_chat(f"Nickname changed to: {new_nick}")
            else:
                self.append_to_chat("Usage: /nick <new_nickname>")
            self.message_entry.delete("1.0", tk.END)
            return "break"
        
        # Check if verification is complete
        if not self.client.verification_complete:
            self.append_to_chat("Cannot send messages - verification not complete")
            return "break"
        
        # Send the message
        try:
            # Get the message counter before sending (it will be incremented during send)
            if self.client:
                next_message_counter = self.client.protocol.message_counter + 1
            else:
                next_message_counter = None
            
            if self.client.send_message(message):
                # Display the sent message with delivery tracking
                if self.client.protocol.peer_key_verified:
                    display_text = f"You: {message}"
                else:
                    display_text = f"You (unverified): {message}"
                
                # Add the message with delivery tracking
                self.append_to_chat_with_delivery_status(display_text, next_message_counter)
            else:
                self.append_to_chat("Failed to send message")
        
        except Exception as e:
            self.append_to_chat(f"Send error: {e}")
        
        self.message_entry.delete("1.0", tk.END)
        return "break"  # Prevents the default newline insertion
    
    def on_send_file_click(self, event):
        """Handle send file button click with shift key detection."""
        # Detect if shift key is held
        shift_held = bool(event.state & 0x1)  # Check shift key state
        self.send_file(compress=not shift_held)
        return "break"  # Prevent default button command from executing
    
    def send_file(self, compress=True):
        """Send a file using file dialog."""
        if not self.connected or not self.client:
            return
        
        # Check if verification is complete
        if not self.client.verification_complete:
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
                self.confirm_and_send_file(file_path, compress=compress)
        
        except Exception as e:
            self.append_to_chat(f"File send error: {e}")
    
    def on_key_press(self, *_):
        """Handle key press events in message entry."""
        # Allow normal typing when connected
        # Note: Control+Q is handled at the window level, not here
        pass
    
    def on_paste(self, event):
        """Handle paste events in message entry - check for images."""
        if not self.connected or not self.client:
            return "break"  # Prevent default paste behavior
        
        # Check if verification is complete
        if not self.client.verification_complete:
            return "break"  # Prevent default paste behavior
        
        try:
            # Check if there's an image in the clipboard
            clipboard_image = get_image_from_clipboard()
            if clipboard_image is None:
                return None  # Allow default paste behavior
            
            # There's an image in the clipboard, handle it
            self.handle_clipboard_image(clipboard_image)
            return "break"  # Prevent default paste behavior
        
        
        except Exception as e:
            self._append_to_chat(f"Error handling paste: {e}")
            return "break"  # Prevent default paste behavior on error
    
    def handle_clipboard_image(self, image: Image.Image) -> None:
        """
        Handle pasted clipboard image by saving to temp file and sending.
        Must be run from the main Tkinter thread.
        """
        if self.client is None:
            return
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
                self._append_to_chat(f"Sending clipboard image: {temp_filename}")
                self.client.send_file(temp_path)
            
            
            else:
                # User declined, clean up temp file immediately
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception:
                    pass  # Ignore cleanup errors, it's only a temp file anyway
        
        except Exception as e:
            self._append_to_chat(f"Error handling clipboard image: {e}")
    
    def on_text_change(self, *_):
        """Handle text changes in message entry for spellcheck."""
        if not SPELLCHECKER_AVAILABLE:
            return
        
        # Cancel existing timer if any
        if self.spellcheck_timer:
            self.root.after_cancel(self.spellcheck_timer)
        
        # Start new timer for 400 ms delay
        self.spellcheck_timer = self.root.after(400, self.perform_spellcheck) # type: ignore
    
    def perform_spellcheck(self):
        """Perform spellcheck on the message entry text."""
        if not SPELLCHECKER_AVAILABLE:
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
                        self.message_entry.tag_configure(tag_name, underline=True,
                                                         underlinefg=self.theme_colors.get("SPELLCHECK_ERROR_COLOR",
                                                                                           "red"))
                        self.misspelled_tags.add(tag_name)
                    
                    start_pos = f"{pos}+1c"
        
        except:
            # Silently ignore spellcheck errors to avoid disrupting user experience
            pass
    
    def show_spellcheck_menu(self, event):
        """Show context menu with spelling suggestions on right-click."""
        if not SPELLCHECKER_AVAILABLE:
            return
        
        try:
            # Get the position of the click
            click_pos = self.message_entry.index(f"@{event.x},{event.y}")
            
            # Get the entire line of text
            line_start: str = self.message_entry.index(f"{click_pos} linestart")
            line_end: str = self.message_entry.index(f"{click_pos} lineend")
            line_text: str = self.message_entry.get(line_start, line_end)
            
            # Find the word at the click position using regex
            click_col: int = int(click_pos.split('.')[1])
            word_match: re.Match[str] | None = None
            for match in re.finditer(r'\b[a-zA-Z]+\b', line_text):
                if match.start() <= click_col < match.end():
                    word_match = match
                    break
            
            if not word_match:
                return
            
            word: str = word_match.group(0)
            word_start: str = f"{line_start}+{word_match.start()}c"
            word_end: str = f"{line_start}+{word_match.end()}c"
            
            if not word or word not in self.spell_checker.unknown([word]):
                return  # Word is correctly spelled or empty
            
            # Create context menu
            context_menu: tk.Menu = tk.Menu(self.root, tearoff=0)
            
            # Get suggestions
            suggestions: list[str | None] = list(self.spell_checker.candidates(word))[:5]  # Limit to 5 suggestions
            
            if suggestions:
                for suggestion in suggestions:
                    if suggestion is None:
                        continue
                    context_menu.add_command(
                            label=suggestion,
                            command=lambda s=suggestion, start=word_start, end=word_end: self.replace_word(start, end,
                                                                                                           s)
                    )
                context_menu.add_separator()
            
            # Add "Add to dictionary" option
            context_menu.add_command(
                    label="Add to dictionary",
                    command=lambda w=word: self.add_to_dictionary(w)
            )
            
            # Show the menu
            context_menu.tk_popup(event.x_root, event.y_root)
        
        except Exception:
            # Silently ignore menu errors
            pass
    
    def replace_word(self, start_pos: str, end_pos: str, replacement: str):
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
    
    def emergency_close(self, *args):
        """Handle emergency close (Control+Q) - send emergency message and close immediately."""
        try:
            if self.connected and self.client:
                self.client.protocol.send_emergency_close()
                # Force immediate disconnect without waiting
                self.client.connected = False
                if self.client.socket:
                    self.client.socket.close()
            # Close the application immediately
            self.on_tk_thread(self.root.quit)
            os._exit(1)
        except Exception as e:
            # Even if there's an error, still close the application
            print(f"Error during emergency close: {e}")
            os._exit(1)
    
    def on_closing(self):
        """Handle window closing."""
        if self.connected:
            self.client.disconnect()
        self.root.destroy()
    
    def start_ephemeral_cleanup(self):
        """Start the background thread to clean up ephemeral messages."""
        
        def cleanup_thread():
            while True:
                try:
                    if (self.ephemeral_mode in ("LOCAL", "GLOBAL")) and self.ephemeral_messages:
                        current_time = time.time()
                        # Find messages older than 30 seconds
                        expired_message_ids = []
                        for message_id, timestamp in list(self.ephemeral_messages.items()):
                            if current_time - timestamp >= 30.0:
                                expired_message_ids.append(message_id)
                        
                        # Remove expired messages
                        if expired_message_ids:
                            self.on_tk_thread(self.remove_ephemeral_messages, expired_message_ids)
                    
                    time.sleep(1.0)  # Check every second
                except Exception:
                    # Silently continue on errors to avoid breaking the cleanup thread
                    pass
        
        threading.Thread(target=cleanup_thread, daemon=True).start()
    
    def on_ephemeral_change(self, value):
        """Handle dropdown selection for ephemeral mode: OFF, LOCAL, GLOBAL."""
        try:
            selected = str(value).upper()
        except Exception:
            selected = "OFF"
        # Enforce owner lock when currently in GLOBAL owned by someone else
        if self.ephemeral_mode == "GLOBAL" and self.ephemeral_global_owner_id and self.ephemeral_global_owner_id != self.local_client_id:
            if selected != "GLOBAL":
                # Revert selection and inform user
                self.root.after(0, self.ephemeral_mode_var.set, "GLOBAL")
                self.append_to_chat("Global ephemeral mode was enabled by the other user. Only they can disable it.")
                return
        # Apply selection
        if selected == "LOCAL":
            # If we were the GLOBAL owner, inform peer to disable global
            was_global_owner = (
                    self.ephemeral_mode == "GLOBAL" and self.ephemeral_global_owner_id == self.local_client_id)
            previous_owner = self.ephemeral_global_owner_id
            self.ephemeral_mode = "LOCAL"
            self.ephemeral_global_owner_id = None
            self.append_to_chat("Local ephemeral mode enabled - your messages will disappear after 30 seconds")
            # Broadcast OFF if we were the global owner
            if was_global_owner and self.connected and self.client and self.client.key_exchange_complete:
                self.send_ephemeral_mode_change("OFF", previous_owner)
            self.update_ephemeral_ui()
        elif selected == "GLOBAL":
            # Require secure session to announce globally
            if not (self.connected and self.client and self.client.key_exchange_complete):
                self.append_to_chat("Cannot enable global ephemeral before secure session is established.")
                self.root.after(0, self.ephemeral_mode_var.set, self.ephemeral_mode)
                return
            self.ephemeral_mode = "GLOBAL"
            self.ephemeral_global_owner_id = self.local_client_id
            self.append_to_chat("Global ephemeral mode enabled - only you can disable it")
            # Broadcast to peer
            self.send_ephemeral_mode_change("GLOBAL", self.ephemeral_global_owner_id)
            self.update_ephemeral_ui()
        else:
            # OFF
            if self.ephemeral_mode == "GLOBAL" and self.ephemeral_global_owner_id and self.ephemeral_global_owner_id != self.local_client_id:
                # Not allowed to turn off
                self.append_to_chat("Only the user who enabled global ephemeral mode can disable it.")
                self.root.after(0, self.ephemeral_mode_var.set, "GLOBAL")
                return
            # Turn off locally and broadcast OFF if we are the owner
            was_global_owner = (
                    self.ephemeral_mode == "GLOBAL" and self.ephemeral_global_owner_id == self.local_client_id)
            self.ephemeral_mode = "OFF"
            previous_owner = self.ephemeral_global_owner_id
            self.ephemeral_global_owner_id = None
            self.append_to_chat("Ephemeral mode disabled.")
            # Remove all existing ephemeral messages locally
            all_message_ids = list(self.ephemeral_messages.keys())
            if all_message_ids:
                self.remove_ephemeral_messages(all_message_ids)
            # Broadcast OFF if we owned the global state
            if was_global_owner and self.connected and self.client and self.client.key_exchange_complete:
                self.send_ephemeral_mode_change("OFF", previous_owner)
            self.update_ephemeral_ui()
    
    def send_ephemeral_mode_change(self, mode: str, owner_id: str | None):
        """Send an encrypted EPHEMERAL_MODE_CHANGE message to the peer."""
        try:
            if not (self.client and self.client.socket and self.client.protocol):
                return
            payload = {
                "type":     MessageType.EPHEMERAL_MODE_CHANGE,
                "mode":     mode,
                "owner_id": owner_id,
            }
            self.client.protocol.queue_message(("encrypt_json", payload))
        except Exception as e:
            self.append_to_chat(f"Error sending ephemeral mode change: {e}")
    
    def update_ephemeral_ui(self):
        """Update dropdown UI state and color based on current ephemeral mode and ownership."""
        try:
            # Color feedback
            if self.ephemeral_mode == "GLOBAL":
                bg = self.theme_colors["EPHEMERAL_GLOBAL_BG"]
                fg = self.theme_colors["EPHEMERAL_GLOBAL_FG"]
            elif self.ephemeral_mode == "LOCAL":
                bg = self.theme_colors["EPHEMERAL_LOCAL_BG"]
                fg = self.theme_colors["EPHEMERAL_LOCAL_FG"]
            else:
                bg = self.BUTTON_BG_COLOR
                fg = self.FG_COLOR
            self.ephemeral_menu.config(bg=bg, fg=fg, activebackground=self.BUTTON_ACTIVE_BG,
                                       activeforeground=fg)
        except Exception:
            pass
        # Lock control if global owned by peer
        try:
            if self.ephemeral_mode == "GLOBAL" and self.ephemeral_global_owner_id and self.ephemeral_global_owner_id != self.local_client_id:
                self.ephemeral_menu.config(state=ltk.DISABLED)
            else:
                self.ephemeral_menu.config(state=ltk.NORMAL)
        except Exception:
            pass
    
    def remove_ephemeral_messages(self, message_ids):
        """Remove ephemeral messages from the chat display."""
        try:
            self.chat_display.config(state=ltk.NORMAL)
            for message_id in message_ids:
                # Find the tagged message range
                tag_ranges = self.chat_display.tag_ranges(message_id)
                if tag_ranges:
                    # Delete the tagged text
                    self.chat_display.delete(tag_ranges[0], tag_ranges[1])
                
                # Remove from tracking dict
                self.ephemeral_messages.pop(message_id, None)
            
            self.chat_display.see(tk.END)
            self.chat_display.config(state=ltk.DISABLED)
        
        except Exception:
            # If removal fails, just clean up the tracking dict
            for message_id in message_ids:
                self.ephemeral_messages.pop(message_id, None)
    
    def prompt_voice_call(self):
        """
        Handle incoming voice call request by prompting the user to accept or reject.
        Also plays a ringing sound effect
        GUI exclusive feature
        """
        keep_ringing = True
        
        # Create a modal dialog to prompt the user to accept or reject
        def on_accept():
            self.client.on_user_response(True, configs.VOICE_RATE, configs.VOICE_CHUNK,
                                         configs.VOICE_FORMAT)
            prompt.destroy()
            nonlocal keep_ringing
            keep_ringing = False
            message = {
                "rate":         configs.VOICE_RATE,
                "chunk_size":   configs.VOICE_CHUNK,
                "audio_format": configs.VOICE_FORMAT,
            }
            # Spoof an accept message to start the call
            self.client.handle_voice_call_accept(json.dumps(message))
        
        def on_reject():
            self.client.on_user_response(False, 0, 0, 0)
            prompt.destroy()
            
            nonlocal keep_ringing
            keep_ringing = False
        
        # Play a simple ringing sound in a separate thread
        def play_ringtone():
            try:
                if not os.path.exists(configs.RINGTONE_FILE):
                    print("Ringtone file not found.")
                    return
                
                with wave.open(configs.RINGTONE_FILE, "rb") as w:
                    p = pyaudio.PyAudio()
                    stream = p.open(format=p.get_format_from_width(w.getsampwidth()),
                                    channels=w.getnchannels(),
                                    rate=w.getframerate(),
                                    output=True)
                    
                    while len(data := w.readframes(1024)) and keep_ringing:
                        stream.write(data)
                    
                    stream.close()
                    p.terminate()
                    if keep_ringing:
                        # Auto-reject the call when ringtone playback finishes without user action
                        try:
                            self.on_tk_thread(on_reject)
                        except Exception:
                            try:
                                on_reject()
                            except Exception:
                                pass
            
            except Exception:
                print("Failed to play ringtone.")
                try:
                    if stream.is_active():
                        stream.close()
                        p.terminate()
                except Exception:
                    pass  # Stream is probably already closed
        
        threading.Thread(target=play_ringtone).start()
        
        prompt = tk.Toplevel(self.root)
        prompt.title("Incoming Voice Call")
        prompt.geometry("300x150")
        prompt.resizable(False, False)
        prompt.grab_set()  # Make it modal
        prompt.transient(self.root)  # Set to be on top of the main window
        prompt.configure(bg=self.BG_COLOR)
        tk.Label(prompt, text="Incoming voice call...", bg=self.BG_COLOR, fg=self.FG_COLOR,
                 font=("Arial", 12)).pack(pady=10)
        tk.Button(prompt, text="Accept", command=on_accept, bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR,
                  width=10).pack(pady=5)
        tk.Button(prompt, text="Reject", command=on_reject, bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR,
                  width=10).pack(pady=5)
        
        prompt.transient(self.root)


class GUISecureChatClient(SecureChatClient):
    """Extended SecureChatClient that works with GUI."""
    
    def __init__(self, gui: "ChatGUI", host='localhost', port=16384):
        super().__init__(host, port)
        self.display_images: bool = self.protocol.config["auto_display_images"]
        self.voice_data_queue: deque[bytes] = deque()
        self.voice_call_active: bool = False
        self.gui: "ChatGUI" = gui
        # Initialize verification flags and state properly
        self.verification_complete: bool = False
        self.verification_started: bool = False
        self.verification_pending: bool = False
        # Initialize file transfer state
        self.pending_file_requests: dict[Any, Any] = {}
    
    def connect(self) -> bool:
        # Call base connect (starts receive thread)
        ok = super().connect()
        if ok:
            # Inform GUI (thread-safe dispatch if needed)
            self.gui.on_tk_thread(self.gui.on_connected)
        return ok
    
    @staticmethod
    def _is_image_file(file_path: str) -> bool:
        """Check if a file is an image based on its extension."""
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.ico'}
        _, ext = os.path.splitext(file_path.lower())
        return ext in image_extensions
    
    def _display_received_image(self, file_path: str):
        """Display a received image file in a separate window, if enabled by settings."""
        try:
            if self._is_image_file(file_path):
                # Load and display the image
                image = Image.open(file_path)
                self.gui.root.after(0, display_image, image, self.gui.root)
        except Exception as e:
            self.gui.append_to_chat(f"Error displaying received image: {e}")
    
    def display_regular_message(self, message: str, error=False, prefix: str = "") -> None:
        """Display a regular chat message."""
        if error:
            self.gui.append_to_chat(f"Error: {message}")
        elif prefix != "":
            self.gui.append_to_chat(f"{prefix}: {message}", is_message=True, show_time=False)
        else:
            self.gui.append_to_chat(f"{self.peer_nickname}: {message}", is_message=True)
    
    def on_server_disconnect(self, reason: str) -> None:
        """Show server disconnect reason in the GUI as a system message and disconnect."""
        
        # Append as system message in chat
        self.gui.append_to_chat(f"[SYSTEM] Server disconnected: {reason}", is_message=False, show_time=False)
        self.gui.disconnect_from_server()
    
    def request_voice_call(self, rate: int, chunk_size: int, audio_format: int):
        """
        Start a voice call session with the specified audio parameters.
        GUI exclusive feature
        """
        to_send = {
            "type":         MessageType.VOICE_CALL_INIT,
            "rate":         rate,
            "chunk_size":   chunk_size,
            "audio_format": audio_format,
        }
        self.protocol.queue_message(("encrypt_json", to_send))
    
    def handle_voice_call_init(self, message_data: str) -> None:
        """
        Handle incoming voice call request.
        Prompt the user to accept or reject the call (unless disabled in settings).
        GUI exclusive feature
        """
        try:
            # Auto-reject if voice calls are disabled in settings
            if not self.gui.allow_voice_calls:
                try:
                    self.protocol.queue_message(("encrypt_json", {"type": MessageType.VOICE_CALL_REJECT}))
                except Exception:
                    pass
                self.gui.append_to_chat("Auto-rejected incoming voice call (disabled in settings).")
                return
            
            # Prompt user in the GUI thread
            self.gui.on_tk_thread(self.gui.prompt_voice_call)
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling voice call init: {e}")
    
    def on_user_response(self, accepted: bool, rate: int, chunk_size: int, audio_format: int):
        if accepted:
            self.protocol.queue_message(("encrypt_json", {
                "type":         MessageType.VOICE_CALL_ACCEPT,
                "rate":         rate,
                "chunk_size":   chunk_size,
                "audio_format": audio_format,
            }))
            self.gui.voice_call_btn.config(state=ltk.DISABLED)
        else:
            self.protocol.queue_message(("encrypt_json", {
                "type": MessageType.VOICE_CALL_REJECT,
            }))
            self.gui.append_to_chat("Rejected voice call")
    
    def handle_voice_call_accept(self, message_data: str):
        """
        Handle acceptance of a voice call request.
        Start the send and receive threads for voice data.
        Voice data bypasses the queue as it needs to be realtime
        """
        try:
            message = json.loads(message_data)
            
            rate = int(message.get("rate", 44100))
            chunk_size = int(message.get("chunk_size", rate * 0.01))
            audio_format = int(message.get("audio_format", pyaudio.paInt32))
            self.protocol.send_dummy_messages = False
            self.voice_call_active = True
            
            in_p = pyaudio.PyAudio()
            in_stream = in_p.open(rate=rate, channels=1, format=audio_format, input=True)
            
            out_p = pyaudio.PyAudio()
            out_stream = out_p.open(rate=rate, channels=1, format=audio_format, output=True)
            
            threading.Thread(target=self.send_voice_thread, args=(in_p, in_stream, chunk_size), daemon=True).start()
            threading.Thread(target=self.receive_voice_thread, args=(out_p, out_stream), daemon=True).start()
            
            # Switch the GUI button to 'End Call'
            try:
                self.gui.no_types_tk_thread(
                        self.gui.voice_call_btn.config,
                        text="End Call",
                        state=ltk.NORMAL,
                        command=self.end_call
                )
            except Exception:
                pass
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling voice call accept: {e}")
    
    def send_voice_thread(self, p: pyaudio.PyAudio, stream: pyaudio.Stream, chunk_size: int):
        try:
            while self.voice_call_active and self.connected:
                chunk = stream.read(chunk_size, exception_on_overflow=False)
                self.send_voice_data(chunk)
            else:
                # Clean up on exit
                stream.close()
                p.terminate()
        
        
        except Exception as e:
            self.gui.append_to_chat(f"Voice send error: {e}")
        
        finally:
            try:
                if not stream.is_stopped():
                    stream.close()
                    p.terminate()
            
            except Exception:
                # Stream already closed
                pass
    
    def receive_voice_thread(self, p: pyaudio.PyAudio, stream: pyaudio.Stream):
        try:
            while self.voice_call_active and self.connected:
                if self.voice_data_queue:
                    chunk = self.voice_data_queue.popleft()
                    stream.write(chunk)
                else:
                    time.sleep(0.005)
            else:
                # Clean up on exit
                stream.close()
                p.terminate()
        except Exception as e:
            self.gui.append_to_chat(f"Voice receive error: {e}")
        
        finally:
            try:
                if not stream.is_stopped():
                    stream.close()
                    p.terminate()
            except Exception:
                pass
    
    def handle_voice_call_reject(self):
        """Handle rejection of a voice call request."""
        self.gui.append_to_chat(f"Voice call rejected")
        self.gui.voice_call_btn.config(state=ltk.NORMAL)
    
    def handle_voice_call_data(self, decrypted_text: str) -> None:
        """Handle incoming voice call data (console feedback)."""
        try:
            if not self.voice_call_active:
                return
            # Directly enqueue the raw audio data for playback
            self.voice_data_queue.append(base64.b64decode(json.loads(decrypted_text)["audio_data"]))
        except Exception as e:
            self.gui.append_to_chat(f"Error handling voice call data: {e}")
    
    def end_call(self, notify_peer: bool = True) -> None:
        """End the current voice call from this side and notify the peer."""
        try:
            if not self.voice_call_active:
                return
            # Stop local sending/receiving
            self.voice_call_active = False
            self.protocol.send_dummy_messages = True
            # Clear any buffered audio
            
            self.voice_data_queue.clear()
            # Notify peer
            try:
                if notify_peer:
                    self.protocol.queue_message(("encrypt_json", {"type": MessageType.VOICE_CALL_END}))
            except Exception as e:
                self.gui.append_to_chat(f"Error notifying peer of call end: {e}")
            # Reset UI button back to 'Voice Call'
            try:
                self.gui.no_types_tk_thread(
                        self.gui.voice_call_btn.config,
                        text="Voice Call",
                        state=ltk.NORMAL,
                        command=self.gui.start_call
                )
            except Exception:
                pass
            self.gui.append_to_chat("Voice call ended")
        except Exception as e:
            self.gui.append_to_chat(f"Error ending call: {e}")
    
    def handle_voice_call_end(self) -> None:
        """Handle incoming end-call message from the peer."""
        try:
            if self.voice_call_active:
                self.voice_call_active = False
            try:
                self.protocol.send_dummy_messages = True
            except Exception:
                pass
            try:
                self.voice_data_queue.clear()
            except Exception:
                pass
            # Update UI
            try:
                self.gui.no_types_tk_thread(
                        self.gui.voice_call_btn.config,
                        text="Voice Call",
                        state=ltk.NORMAL,
                        command=self.gui.start_call
                )
            except Exception:
                pass
            self.gui.append_to_chat("Peer ended the voice call")
        except Exception as e:
            self.gui.append_to_chat(f"Error handling call end: {e}")
    
    def handle_delivery_confirmation(self, message_data: str) -> None:
        """Handle delivery confirmation messages from the peer - override to update GUI."""
        try:
            confirmed_counter = json.loads(message_data).get("confirmed_counter")
            # Update the GUI to show the message was delivered
            if confirmed_counter:
                self.gui.on_tk_thread(self.gui.update_message_delivery_status, confirmed_counter)
            else:
                # Fallback to console output if no GUI
                print(f"\n✓ Message {confirmed_counter} delivered")
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling delivery confirmation: {e}")
    
    def handle_ephemeral_mode_change(self, decrypted_message: str) -> None:
        """Override: apply peer's ephemeral mode changes to GUI state."""
        try:
            message = json.loads(decrypted_message)
            if message.get("type") != MessageType.EPHEMERAL_MODE_CHANGE:
                return
            mode = str(message.get("mode", "OFF")).upper()
            owner_id = message.get("owner_id")
            
            if not self.gui:
                # No GUI attached; nothing to update visually
                return
            
            def set_global():
                self.gui.ephemeral_mode = "GLOBAL"
                self.gui.ephemeral_global_owner_id = owner_id
                self.gui.ephemeral_mode_var.set("GLOBAL")
                self.gui.append_to_chat("Peer enabled GLOBAL ephemeral mode. Only the enabler can disable it.")
                self.gui.update_ephemeral_ui()
            
            def set_off_from_owner():
                # Switch OFF only when performed by the recorded owner
                self.gui.ephemeral_mode = "OFF"
                self.gui.ephemeral_global_owner_id = ""
                self.gui.ephemeral_mode_var.set("OFF")
                self.gui.append_to_chat("Peer disabled GLOBAL ephemeral mode.")
                # Remove existing ephemeral messages locally
                ids = list(self.gui.ephemeral_messages.keys())
                if ids:
                    self.gui.remove_ephemeral_messages(ids)
                self.gui.update_ephemeral_ui()
            
            if mode == "GLOBAL":
                self.gui.on_tk_thread(set_global)
            elif mode == "OFF":
                # Only honour OFF from the owner who enabled GLOBAL
                if self.gui.ephemeral_mode == "GLOBAL" and self.gui.ephemeral_global_owner_id == owner_id:
                    self.gui.on_tk_thread(set_off_from_owner)
                else:
                    self.gui.append_to_chat(
                            "Peer attempted to disable GLOBAL ephemeral mode but is not the owner; ignoring.")
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling ephemeral mode change: {e}")
    
    def handle_emergency_close(self) -> None:
        """Handle emergency close message from the other client - override to display in GUI."""
        try:
            # Display emergency close message in GUI
            self.gui.append_to_chat("EMERGENCY CLOSE RECEIVED")
            self.gui.append_to_chat("The other client has activated emergency close.")
            self.gui.append_to_chat("Connection will be terminated immediately.")
            
            # Show popup notification
            self.gui.on_tk_thread(messagebox.showwarning,
                                "Emergency Close Activated",
                                "The other client has activated emergency close.\nThe connection will be terminated immediately."
                                )
            
            # Use the GUI's emergency close function to properly close everything
            self.gui.emergency_close()
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling emergency close: {e}")
            # Force disconnect
            self.gui.emergency_close()
    
    def handle_key_exchange_init(self, message_data: bytes):
        """Handle key exchange initiation - override to display warnings in GUI."""
        try:
            _, ciphertext, version_warning = self.protocol.process_key_exchange_init(message_data)
            
            # Display version warning in GUI if present
            if version_warning and self.gui:
                self.gui.append_to_chat(f"{version_warning}")
            elif version_warning:
                print(f"\n{version_warning}")
            
            response = self.protocol.create_key_exchange_response(ciphertext)
            
            # Send response back through server
            send_message(self.socket, response)
        
        except Exception as e:
            self.gui.append_to_chat(f"Key exchange init error: {e}")
    
    def handle_key_exchange_response(self, message_data: bytes) -> bool:
        """Handle key exchange response - override to send to GUI. """
        self.gui.update_status("Processing key exchange")
        success = super().handle_key_exchange_response(message_data)
        if success:
            self.gui.update_status("Key exchange completed")
        
        return success
    
    def handle_key_exchange_complete(self):
        """Handle key exchange completion notification - override to use GUI."""
        self.key_exchange_complete = True
        # Don't call start_key_verification() here as it would block the receive thread
        # The GUI monitoring thread will detect key_exchange_complete and show the dialogue
    
    def initiate_key_exchange(self):
        """Initiate key exchange as the first client - override to add GUI status update."""
        self.gui.update_status("Processing key exchange")
        super().initiate_key_exchange()
    
    def handle_key_exchange_reset(self, message_data: bytes):
        """Handle key exchange reset message - override to provide GUI feedback."""
        try:
            message = json.loads(message_data.decode('utf-8'))
            reset_message = message.get("message", "Key exchange reset")
            self.end_call(notify_peer=False)
            
            # Reset client state
            self.key_exchange_complete = False
            self.verification_complete = False
            self.protocol.reset_key_exchange()
            
            # Reset GUI-specific verification flags
            if self.verification_started:
                self.verification_started = False
            
            # Clear any pending file transfers
            self.pending_file_transfers.clear()
            self.active_file_metadata.clear()
            
            # Update GUI
            self.gui.update_status("Key exchange reset - waiting for new client")
            self.gui.append_to_chat("KEY EXCHANGE RESET")
            self.gui.append_to_chat(f"Reason: {reset_message}")
            self.gui.append_to_chat("The secure session has been terminated.")
            self.gui.append_to_chat("Waiting for a new client to connect...")
            self.gui.append_to_chat("A new key exchange will start automatically.")
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling key exchange reset: {e}")
    
    def handle_file_metadata(self, decrypted_message: str):
        """Handle incoming file metadata with GUI dialog."""
        try:
            metadata = self.protocol.process_file_metadata(decrypted_message)
            transfer_id = metadata["transfer_id"]
            
            if not self.allow_file_transfers:
                self.display_regular_message("Auto-rejected incoming file transfer (disabled in settings).",
                                             prefix="[SYSTEM]")
                self.protocol.queue_message(("encrypt_json", {
                    "type":        MessageType.FILE_REJECT,
                    "transfer_id": transfer_id,
                    "reason":      "User disabled file transfers",
                }))
                return
            
            # Store metadata for potential acceptance
            self.active_file_metadata[transfer_id] = metadata
            
            def show_file_notification():
                # Play notification sound
                self.gui.play_notification_sound()
                
                # Show Windows notification if enabled
                self.gui.show_windows_notification(f"Incoming file transfer: {metadata['filename']}")
                
                # Display file transfer information in chat
                self.gui.append_to_chat("INCOMING FILE TRANSFER")
                self.gui.append_to_chat(f"Filename: {metadata['filename']}")
                self.gui.append_to_chat(f"Size: {bytes_to_human_readable(metadata['file_size'])}")
                self.gui.append_to_chat(f"Chunks: {metadata['total_chunks']}")
                self.gui.append_to_chat("")
                self.gui.append_to_chat("Type '/accept' or '/y' to accept the file transfer")
                self.gui.append_to_chat("Type '/reject' or '/n' to reject the file transfer")
                self.gui.append_to_chat("")
                
                # Store the transfer ID for command processing
                self.pending_file_requests[transfer_id] = metadata
            
            self.gui.on_tk_thread(show_file_notification)
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling file metadata: {e}")
    
    def handle_file_accept(self, decrypted_message: str):
        """Handle file acceptance from peer with GUI updates."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id not in self.pending_file_transfers:
                self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                      "Received acceptance for unknown file transfer")
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            filename = transfer_info["metadata"]["filename"]
            
            self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                  f"File transfer accepted. Sending {filename}...")
            
            self.protocol.send_dummy_messages = False
            # Start sending file chunks in a separate thread to avoid blocking message processing
            chunk_thread = threading.Thread(
                    target=self._send_file_chunks,
                    args=(transfer_id, transfer_info["file_path"]),
                    daemon=True
            )
            chunk_thread.start()
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling file acceptance: {e}")
    
    def handle_file_reject(self, decrypted_message: str):
        """Handle file rejection from peer with GUI updates."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            reason = message.get("reason", "Unknown reason")
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                      f"File transfer rejected: {filename} - {reason}")
                self.gui.append_to_chat(f"File transfer rejected: {filename} - {reason}")
                del self.pending_file_transfers[transfer_id]
        
        except Exception as e:
            self.gui.append_to_chat(f"Error handling file rejection: {e}")
    
    def handle_file_chunk_binary(self, chunk_info: dict):
        """Handle incoming file chunk (optimized binary format) with GUI progress updates."""
        try:
            transfer_id = chunk_info["transfer_id"]
            
            if transfer_id not in self.active_file_metadata:
                self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                      "Received chunk for unknown file transfer")
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
            received_chunks = len(self.protocol.received_chunks.get(transfer_id, set()))
            # Calculate bytes transferred for speed tracking
            # Use processed_size from metadata for accurate progress calculation
            processed_size = metadata.get("processed_size", metadata["file_size"])
            if metadata["total_chunks"] == 1:
                # Only one chunk, use actual size
                bytes_transferred = len(chunk_info["chunk_data"])
            else:
                # Multiple chunks - estimate based on received chunks and total processed size
                progress_ratio = received_chunks / metadata["total_chunks"]
                bytes_transferred = int(processed_size * progress_ratio)
            
            # Update GUI with transfer progress every 10 chunks or for small transfers
            if received_chunks % 10 == 0 or received_chunks == 1 or metadata["total_chunks"] <= 10:
                self.gui.on_tk_thread(self.gui.file_transfer_window.update_transfer_progress,
                                      filename=metadata['filename'], current=received_chunks,
                                      total=metadata['total_chunks'], bytes_transferred=bytes_transferred)
            
            if is_complete:
                # Final progress update to ensure 100% is shown
                # Use processed_size for final progress to match the transfer type
                final_bytes_transferred = metadata.get("processed_size", metadata["file_size"])
                self.gui.on_tk_thread(self.gui.file_transfer_window.update_transfer_progress,
                                      filename=metadata['filename'], current=metadata['total_chunks'],
                                      total=metadata['total_chunks'],
                                      bytes_transferred=final_bytes_transferred
                                      )
                
                # Reassemble file
                # Use user-selected save path if provided; otherwise default to CWD with conflict handling
                if 'save_path' in metadata and metadata['save_path']:
                    output_path = metadata['save_path']
                else:
                    output_path = os.path.join(os.getcwd(), metadata["filename"])
                    # Handle filename conflicts
                    counter = 1
                    base_name, ext = os.path.splitext(metadata["filename"])
                    while os.path.exists(output_path):
                        output_path = os.path.join(os.getcwd(), f"{base_name}_{counter}{ext}")
                        counter += 1
                
                try:
                    # Get compression status from metadata
                    compressed = metadata.get("compressed", True)  # Default to compressed for backward compatibility
                    self.protocol.reassemble_file(transfer_id, output_path, metadata["file_hash"],
                                                  compressed=compressed)
                    
                    compression_text = "compressed" if compressed else "uncompressed"
                    self.gui.root.after(0, self.gui.file_transfer_window.add_transfer_message,
                                        f"File received successfully ({compression_text}): {output_path}")
                    # Clear speed when transfer completes
                    self.gui.file_transfer_window.clear_speed()
                    
                    # Display image if it's an image file
                    if self.display_images:
                        self._display_received_image(output_path)
                    
                    # Send completion message via queue
                    complete_msg = {
                        "type":        MessageType.FILE_COMPLETE,
                        "transfer_id": transfer_id
                    }
                    self.protocol.queue_message(("encrypt_json", complete_msg))
                
                except Exception as e:
                    self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                          f"File reassembly failed: {e}")
                
                # Clean up
                del self.active_file_metadata[transfer_id]
        
        except Exception as e:
            self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                  f"Error handling binary file chunk: {e}")
    
    def handle_file_complete(self, decrypted_message: str):
        """Handle file transfer completion notification with GUI updates."""
        try:
            message = json.loads(decrypted_message)
            transfer_id = message["transfer_id"]
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                      f"File transfer completed: {filename}")
                
                self.gui.file_transfer_window.clear_speed()
                del self.pending_file_transfers[transfer_id]
                self.protocol.send_dummy_messages = True
        
        except Exception as e:
            self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                  f"Error handling file completion: {e}")
    
    def _send_file_chunks(self, transfer_id: str, file_path: str):
        """Send file chunks to peer with GUI progress updates."""
        try:
            # Get transfer info including compression setting
            transfer_info = self.pending_file_transfers[transfer_id]
            total_chunks = transfer_info["metadata"]["total_chunks"]
            compress = transfer_info.get("compress", True)
            
            chunk_generator = self.protocol.chunk_file(file_path, compress=compress)
            bytes_transferred = 0
            
            for i, chunk in enumerate(chunk_generator):
                # Queue chunk instruction; loop will encrypt and send
                shared.send_message(self.socket, self.protocol.create_file_chunk_message(transfer_id,
                                                                                         i, chunk))
                
                # Update bytes transferred
                bytes_transferred += len(chunk)
                
                # Show progress in GUI more frequently for better user experience
                # Update every chunk for small transfers, every 5 chunks for medium, every 10 for large
                update_frequency = 1 if total_chunks <= 10 else (5 if total_chunks <= 50 else 10)
                if (i + 1) % update_frequency == 0 or (i + 1) == total_chunks:
                    filename = os.path.basename(file_path)
                    current_chunk = i + 1
                    compression_text = "compressed" if compress else "uncompressed"
                    self.gui.on_tk_thread(self.gui.file_transfer_window.update_transfer_progress,
                                          filename=filename, current=current_chunk, total=total_chunks, bytes_transferred=bytes_transferred,
                                          comp_text=compression_text)
            
            # Final update to ensure 100% progress is shown
            filename = os.path.basename(file_path)
            compression_text = "compressed" if compress else "uncompressed"
            self.gui.on_tk_thread(self.gui.file_transfer_window.update_transfer_progress, filename=filename,
                                  current=total_chunks, total=total_chunks, bytes_transferred=bytes_transferred,
                                  comp_text=compression_text)
            self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                  f"File chunks sent successfully ({compression_text}).")
            # Clear speed when transfer completes
            self.gui.file_transfer_window.clear_speed()
        
        except Exception as e:
            self.gui.on_tk_thread(self.gui.file_transfer_window.add_transfer_message,
                                  f"Error sending file chunks: {e}")
    
    def send_voice_data(self, audio_data: bytes):
        """Send voice data to the peer during an active voice call."""
        try:
            if not (self.voice_call_active and self.protocol):
                return
            
            message = json.dumps({
                "type":       MessageType.VOICE_CALL_DATA,
                "audio_data": base64.b64encode(audio_data).decode('utf-8'),
            })
            shared.send_message(self.socket, self.protocol.encrypt_message(message))
        except Exception as e:
            self.gui.append_to_chat(f"Error sending voice data: {e}")
    
    def handle_server_full(self) -> None:
        """Handle server full notification - override to display in GUI."""
        self.gui.append_to_chat("Server is full. Please try again later.")
        
        self.disconnect()


def load_theme_colors() -> dict[str, str]:
    """
    Load theme colors from theme.json file.
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
        "STATUS_KEY_EXCHANGE_RESET":      "#ffff00",
        
        "SPEED_LABEL_COLOR":              "#4CAF50",
        "EPHEMERAL_ACTIVE_BG":            "#ff6b6b",
        "EPHEMERAL_ACTIVE_FG":            "#ffffff",
        "EPHEMERAL_GLOBAL_BG":            "#6bff6b",
        "EPHEMERAL_GLOBAL_FG":            "#ffffff",
        "SPELLCHECK_ERROR_COLOR":         "#ff0000"
    }
    
    # Check if theme.json exists
    if not os.path.exists("theme.json"):
        # Ask user if they want to generate one with current defaults
        if messagebox.askyesno("Theme Configuration",
                               "No theme.json file found. Would you like to create one with the default colors?"):
            try:
                with open("theme.json", "w", encoding="utf-8") as f:
                    json.dump(default_colors, f, indent=4)
                messagebox.showinfo("Theme Created", "theme.json has been created with default colors.")
            except PermissionError:
                messagebox.showerror("Error", "Permission denied when trying to create theme.json.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create theme.json: {e}")
        return default_colors
    
    # Load colors from theme.json
    try:
        with open("theme.json", "r", encoding="utf-8") as f:
            theme_colors = json.load(f)
        
        # Validate theme format
        required_colors = [
            "BG_COLOR", "FG_COLOR", "ENTRY_BG_COLOR", "BUTTON_BG_COLOR",
            "BUTTON_ACTIVE_BG", "TEXT_BG_COLOR", "STATUS_NOT_CONNECTED",
            "STATUS_CONNECTING", "STATUS_WAITING", "STATUS_VERIFYING",
            "STATUS_VERIFIED_SECURE", "STATUS_NOT_VERIFIED_SECURE",
            "STATUS_PROCESSING_KEY_EXCHANGE", "STATUS_KEY_EXCHANGE_RESET",
            "SPEED_LABEL_COLOR", "EPHEMERAL_ACTIVE_BG", "EPHEMERAL_ACTIVE_FG",
            "SPELLCHECK_ERROR_COLOR"
        ]
        missing_colors = [color for color in required_colors if color not in theme_colors]
        
        if missing_colors:
            messagebox.showwarning("Theme Warning",
                                   f"Missing colors in theme.json: {', '.join(missing_colors)}. Using defaults for " +
                                   "these and saving the default values for the missing values.")
            for color in missing_colors:
                theme_colors[color] = default_colors[color]
            
            with open("theme.json", "w", encoding="utf-8") as f:
                json.dump(theme_colors, f, indent=4)
        
        return theme_colors
    except PermissionError:
        messagebox.showerror("Error", "Permission denied when trying to read theme.json. Using default colors.")
        return default_colors
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Invalid JSON format in theme.json. Using default colors.")
        return default_colors
    except UnicodeDecodeError:
        messagebox.showerror("Error", "Invalid characters in theme.json. Using default colors.")
        return default_colors
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load theme.json: {e}")
        return default_colors


def main():
    """Main function to run the GUI chat client."""
    if TKINTERDND2_AVAILABLE:
        import tkinterdnd2
        
        root: tk.Tk | tkinterdnd2.Tk = TkinterDnD.Tk()
        root.title("Secure Chat Client")
    else:
        root = tk.Tk()
        root.title("Secure Chat Client, no DnD support")
    
    # Create GUI
    gui: ChatGUI = ChatGUI(root)
    
    # Start the GUI
    root.mainloop()


if __name__ == "__main__":
    main()
