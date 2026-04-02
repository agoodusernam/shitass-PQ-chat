import json
import os
import re
import tempfile
import threading
import time
import tkinter as tk
import uuid
import wave
from collections.abc import Iterable
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from typing import Any, Callable, Literal, ParamSpec

from SecureChatABCs.client_base import ClientBase
from SecureChatABCs.ui_base import UIBase, UICapability
from config.config import ConfigHandler
from protocol.utils import bytes_to_human_readable

P = ParamSpec("P")

# Check for optional dependencies
try:
    import PIL
    from PIL import Image, ImageGrab, ImageTk
    
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None  # type: ignore
    ImageTk = None  # type: ignore
    ImageGrab = None  # type: ignore
    PIL = None  # type: ignore

try:
    from plyer import notification  # type: ignore
    
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False
    notification = None

try:
    from spellchecker import SpellChecker
    
    SPELLCHECKER_AVAILABLE = True
except ImportError:
    SPELLCHECKER_AVAILABLE = False
    SpellChecker = None  # type: ignore

try:
    import pyaudio
    
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False
    pyaudio = None  # type: ignore

try:
    # noinspection PyUnresolvedReferences
    from tkinterdnd2 import DND_FILES, TkinterDnD
    
    TKINTERDND2_AVAILABLE = True
except ImportError:
    TKINTERDND2_AVAILABLE = False
    TkinterDnD = None  # type: ignore
    DND_FILES = None  # type: ignore


class Ltk:
    """
    Literal types for Tkinter constants because type checking YAY
    """
    NO = FALSE = OFF = 0
    YES = TRUE = ON = 1
    
    # -anchor and -sticky
    N: Literal['n'] = 'n'
    S: Literal['s'] = 's'
    W: Literal['w'] = 'w'
    E: Literal['e'] = 'e'
    NW: Literal['nw'] = 'nw'
    SW: Literal['sw'] = 'sw'
    NE: Literal['ne'] = 'ne'
    SE: Literal['se'] = 'se'
    NS: Literal['ns'] = 'ns'
    EW: Literal['ew'] = 'ew'
    NSEW: Literal['nsew'] = 'nsew'
    CENTER: Literal['center'] = 'center'
    
    # -fill
    NONE: Literal['none'] = 'none'
    X: Literal['x'] = 'x'
    Y: Literal['y'] = 'y'
    BOTH: Literal['both'] = 'both'
    
    # -side
    LEFT: Literal['left'] = 'left'
    TOP: Literal['top'] = 'top'
    RIGHT: Literal['right'] = 'right'
    BOTTOM: Literal['bottom'] = 'bottom'
    
    # -relief
    RAISED: Literal['raised'] = 'raised'
    SUNKEN: Literal['sunken'] = 'sunken'
    FLAT: Literal['flat'] = 'flat'
    RIDGE: Literal['ridge'] = 'ridge'
    GROOVE: Literal['groove'] = 'groove'
    SOLID: Literal['solid'] = 'solid'
    
    # -orient
    HORIZONTAL: Literal['horizontal'] = 'horizontal'
    VERTICAL: Literal['vertical'] = 'vertical'
    
    # -tabs
    NUMERIC: Literal['numeric'] = 'numeric'
    
    # -wrap
    CHAR: Literal['char'] = 'char'
    WORD: Literal['word'] = 'word'
    
    # -align
    BASELINE: Literal['baseline'] = 'baseline'
    
    # -bordermode
    INSIDE: Literal['inside'] = 'inside'
    OUTSIDE: Literal['outside'] = 'outside'
    
    # Special tags, marks and insert positions
    SEL: Literal['sel'] = 'sel'
    SEL_FIRST: Literal['sel.first'] = 'sel.first'
    SEL_LAST: Literal['sel.last'] = 'sel.last'
    END: Literal['end'] = 'end'
    INSERT: Literal['insert'] = 'insert'
    CURRENT: Literal['current'] = 'current'
    ANCHOR: Literal['anchor'] = 'anchor'
    ALL: Literal['all'] = 'all'  # e.g. Canvas.delete(ALL)
    
    # Text widget and button states
    NORMAL: Literal['normal'] = 'normal'
    DISABLED: Literal['disabled'] = 'disabled'
    ACTIVE: Literal['active'] = 'active'
    # Canvas state
    HIDDEN: Literal['hidden'] = 'hidden'
    
    # Menu item types
    CASCADE: Literal['cascade'] = 'cascade'
    CHECKBUTTON: Literal['checkbutton'] = 'checkbutton'
    COMMAND: Literal['command'] = 'command'
    RADIOBUTTON: Literal['radiobutton'] = 'radiobutton'
    SEPARATOR: Literal['separator'] = 'separator'
    
    # Selection modes for list boxes
    SINGLE: Literal['single'] = 'single'
    BROWSE: Literal['browse'] = 'browse'
    MULTIPLE: Literal['multiple'] = 'multiple'
    EXTENDED: Literal['extended'] = 'extended'
    
    # Activestyle for list boxes
    # NONE='none' is also valid
    DOTBOX: Literal['dotbox'] = 'dotbox'
    UNDERLINE: Literal['underline'] = 'underline'
    
    # Various canvas styles
    PIESLICE: Literal['pieslice'] = 'pieslice'
    CHORD: Literal['chord'] = 'chord'
    ARC: Literal['arc'] = 'arc'
    FIRST: Literal['first'] = 'first'
    LAST: Literal['last'] = 'last'
    BUTT: Literal['butt'] = 'butt'
    PROJECTING: Literal['projecting'] = 'projecting'
    ROUND: Literal['round'] = 'round'
    BEVEL: Literal['bevel'] = 'bevel'
    MITER: Literal['miter'] = 'miter'
    
    # Arguments to xview/yview
    MOVETO: Literal['moveto'] = 'moveto'
    SCROLL: Literal['scroll'] = 'scroll'
    UNITS: Literal['units'] = 'units'
    PAGES: Literal['pages'] = 'pages'


ltk: Ltk = Ltk()


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
            theme_colors: dict[str, str] = {}  # type: ignore
        self.parent_root = parent_root
        self.window: tk.Toplevel = tk.Toplevel(self.parent_root)
        self.window.withdraw()
        self._ui_created: bool = False
        self.speed_label: tk.Label | None = None
        self.transfer_list: scrolledtext.ScrolledText | None = None
        
        # Speed calculation variables
        self.last_update_time: float = time.time()
        self.last_bytes_transferred: int = 0
        self.current_speed: float = 0.0
        
        # Theme colours (use provided theme or defaults)
        if theme_colors:
            self.BG_COLOR = theme_colors["BG_COLOR"]
            self.FG_COLOR = theme_colors["FG_COLOR"]
            self.ENTRY_BG_COLOR = theme_colors["ENTRY_BG_COLOR"]
            self.BUTTON_BG_COLOR = theme_colors["BUTTON_BG_COLOR"]
            self.TEXT_BG_COLOR = theme_colors["TEXT_BG_COLOR"]
            self.SPEED_LABEL_COLOR = theme_colors["SPEED_LABEL_COLOR"]
        else:
            # Default dark theme colours
            self.BG_COLOR = "#2b2b2b"
            self.FG_COLOR = "#d4d4d4"
            self.ENTRY_BG_COLOR = "#3c3c3c"
            self.BUTTON_BG_COLOR = "#555555"
            self.TEXT_BG_COLOR = "#1e1e1e"
            self.SPEED_LABEL_COLOR = "#4CAF50"
    
    def create_window(self):
        """Create the file transfer window if it doesn't exist."""
        if not self._ui_created:
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
                    font=("Consolas", 10, "bold"),
            )
            self.speed_label.pack(side=ltk.RIGHT)
            
            # Title label
            title_label = tk.Label(
                    top_frame,
                    text="File Transfers",
                    bg=self.BG_COLOR,
                    fg=self.FG_COLOR,
                    font=("Consolas", 12, "bold"),
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
                    relief=ltk.FLAT,
            )
            self.transfer_list.pack(fill=ltk.BOTH, expand=True)
            
            # Handle window closing
            self.window.protocol("WM_DELETE_WINDOW", self.hide_window)
            self._ui_created = True
    
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
                                 comp_text: str = "",
                                 ) -> None:
        """
        Update the progress of a file transfer.
        :param filename: The name of the file being transferred.
        :param current: The current progress in chunks.
        :param total: The total number of chunks.
        :param bytes_transferred: Total bytes transferred so far (for speed calculation).
        :param comp_text: Optional compression status text. (e.g. "compressed", "uncompressed")
        :returns: None
        """
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


class DeadDropWindow:
    """Dialog window for deaddrop upload, check, and download operations."""
    
    def __init__(self, parent_root: tk.Tk, client: ClientBase, theme_colors: dict):
        self.parent_root = parent_root
        self.client = client
        self.theme_colors = theme_colors
        
        self.BG_COLOR = theme_colors.get("BG_COLOR", "#2b2b2b")
        self.FG_COLOR = theme_colors.get("FG_COLOR", "#d4d4d4")
        self.ENTRY_BG_COLOR = theme_colors.get("ENTRY_BG_COLOR", "#3c3c3c")
        self.BUTTON_BG_COLOR = theme_colors.get("BUTTON_BG_COLOR", "#4b4b4b")
        self.TEXT_BG_COLOR = theme_colors.get("TEXT_BG_COLOR", "#1e1e1e")
        
        self.window = tk.Toplevel(parent_root)
        self.window.title("Dead Drop")
        self.window.geometry("480x420")
        self.window.configure(bg=self.BG_COLOR)
        self.window.resizable(False, False)
        self.window.transient(parent_root)
        
        self._build_ui()
    
    def _label(self, parent, text, **kw):
        return tk.Label(parent, text=text, bg=self.BG_COLOR, fg=self.FG_COLOR, **kw)
    
    def _entry(self, parent, show="", **kw):
        return tk.Entry(parent, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR,
                        insertbackground=self.FG_COLOR, relief=ltk.FLAT, show=show, **kw)
    
    def _button(self, parent, text, command, **kw):
        return tk.Button(parent, text=text, command=command,
                         bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT, **kw)
    
    def _build_ui(self):
        pad = {"padx": 10, "pady": 4}
        
        # --- Tab bar (Upload / Check / Download) ---
        tab_frame = tk.Frame(self.window, bg=self.BG_COLOR)
        tab_frame.pack(fill=ltk.X, padx=10, pady=(10, 0))
        
        self._tab_frames: dict[str, tk.Frame] = {}
        self._tab_buttons: dict[str, tk.Button] = {}
        
        for tab_name in ("Upload", "Check", "Download"):
            btn = self._button(tab_frame, tab_name, lambda n=tab_name: self._show_tab(n))
            btn.pack(side=ltk.LEFT, padx=(0, 4))
            self._tab_buttons[tab_name] = btn
        
        # --- Content area ---
        content = tk.Frame(self.window, bg=self.BG_COLOR)
        content.pack(fill=ltk.BOTH, expand=True, padx=10, pady=6)
        
        # Upload tab
        upload_frame = tk.Frame(content, bg=self.BG_COLOR)
        self._tab_frames["Upload"] = upload_frame
        
        self._label(upload_frame, "Name:").grid(row=0, column=0, sticky=ltk.W, **pad)
        self.upload_name = self._entry(upload_frame, width=30)
        self.upload_name.grid(row=0, column=1, sticky=ltk.W, **pad)
        
        self._label(upload_frame, "Password:").grid(row=1, column=0, sticky=ltk.W, **pad)
        self.upload_password = self._entry(upload_frame, show="*", width=30)
        self.upload_password.grid(row=1, column=1, sticky=ltk.W, **pad)
        
        self._label(upload_frame, "File:").grid(row=2, column=0, sticky=ltk.W, **pad)
        file_row = tk.Frame(upload_frame, bg=self.BG_COLOR)
        file_row.grid(row=2, column=1, sticky=ltk.W, **pad)
        self.upload_file_var = tk.StringVar()
        self._entry(upload_frame, width=22, textvariable=self.upload_file_var).grid(row=2, column=1, sticky=ltk.W, **pad)
        self._button(upload_frame, "Browse…", self._browse_upload_file).grid(row=2, column=2, **pad)
        
        self._button(upload_frame, "Upload", self._do_upload).grid(row=3, column=1, sticky=ltk.W, **pad)
        
        # Check tab
        check_frame = tk.Frame(content, bg=self.BG_COLOR)
        self._tab_frames["Check"] = check_frame
        
        self._label(check_frame, "Name:").grid(row=0, column=0, sticky=ltk.W, **pad)
        self.check_name = self._entry(check_frame, width=30)
        self.check_name.grid(row=0, column=1, sticky=ltk.W, **pad)
        
        self._button(check_frame, "Check", self._do_check).grid(row=1, column=1, sticky=ltk.W, **pad)
        
        # Download tab
        download_frame = tk.Frame(content, bg=self.BG_COLOR)
        self._tab_frames["Download"] = download_frame
        
        self._label(download_frame, "Name:").grid(row=0, column=0, sticky=ltk.W, **pad)
        self.download_name = self._entry(download_frame, width=30)
        self.download_name.grid(row=0, column=1, sticky=ltk.W, **pad)
        
        self._label(download_frame, "Password:").grid(row=1, column=0, sticky=ltk.W, **pad)
        self.download_password = self._entry(download_frame, show="*", width=30)
        self.download_password.grid(row=1, column=1, sticky=ltk.W, **pad)
        
        self._button(download_frame, "Download", self._do_download).grid(row=2, column=1, sticky=ltk.W, **pad)
        
        # --- Status / log area ---
        self._label(self.window, "Status:").pack(anchor=ltk.W, padx=10)
        self.status_text = scrolledtext.ScrolledText(
                self.window, height=6, state=ltk.DISABLED, wrap=ltk.WORD,
                font=("Consolas", 9), bg=self.TEXT_BG_COLOR, fg=self.FG_COLOR,
                relief=ltk.FLAT,
        )
        self.status_text.pack(fill=ltk.X, padx=10, pady=(0, 10))
        
        self._show_tab("Upload")
    
    def _show_tab(self, name: str):
        for tab_name, frame in self._tab_frames.items():
            frame.pack_forget()
        self._tab_frames[name].pack(fill=ltk.BOTH, expand=True)
        for tab_name, btn in self._tab_buttons.items():
            btn.config(relief=ltk.FLAT if tab_name != name else ltk.SUNKEN)
    
    def _browse_upload_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.upload_file_var.set(path)
    
    def log(self, message: str):
        self.status_text.config(state=ltk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=ltk.DISABLED)
    
    # --- Actions (run on background thread so UI stays responsive) ---
    
    def _do_upload(self):
        name = self.upload_name.get().strip()
        password = self.upload_password.get()
        file_path = self.upload_file_var.get().strip()
        if not name or not password or not file_path:
            messagebox.showerror("Dead Drop", "Please fill in all fields.", parent=self.window)
            return
        threading.Thread(target=self._upload_worker, args=(name, password, Path(file_path)), daemon=True).start()
    
    def _upload_worker(self, name: str, password: str, file_path: Path):
        self.parent_root.after(0, self.log, "Starting deaddrop handshake…")
        self.client.start_deaddrop()
        if not self.client.wait_for_deaddrop_handshake(5.0):
            self.parent_root.after(0, self.log, "Handshake failed.")
            return
        self.client.deaddrop_upload(name, password, file_path)
    
    def _do_check(self):
        name = self.check_name.get().strip()
        if not name:
            messagebox.showerror("Dead Drop", "Please enter a name.", parent=self.window)
            return
        threading.Thread(target=self._check_worker, args=(name,), daemon=True).start()
    
    def _check_worker(self, name: str):
        self.parent_root.after(0, self.log, f"Checking '{name}'…")
        if not self.client.deaddrop_session_active():
            self.client.start_deaddrop()
            if not self.client.wait_for_deaddrop_handshake(5.0):
                self.parent_root.after(0, self.log, "Handshake failed.")
                return
        self.client.deaddrop_check(name)
    
    def _do_download(self):
        name = self.download_name.get().strip()
        password = self.download_password.get()
        if not name or not password:
            messagebox.showerror("Dead Drop", "Please fill in all fields.", parent=self.window)
            return
        threading.Thread(target=self._download_worker, args=(name, password), daemon=True).start()
    
    def _download_worker(self, name: str, password: str):
        self.parent_root.after(0, self.log, "Starting deaddrop handshake…")
        self.client.start_deaddrop()
        if not self.client.wait_for_deaddrop_handshake(5.0):
            self.parent_root.after(0, self.log, "Handshake failed.")
            return
        self.client.deaddrop_download(name, password)


def is_image_file(file_path: str) -> bool:
    """Check if a file is an image based on its extension."""
    image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
    return os.path.splitext(file_path.lower())[1] in image_extensions


def get_image_from_clipboard() -> Image.Image | None:
    """Try to get an image from the system clipboard."""
    if not PIL_AVAILABLE:
        return None
    try:
        # noinspection PyUnresolvedReferences
        img = ImageGrab.grabclipboard()
        if isinstance(img, Image.Image):
            return img
        elif isinstance(img, list) and img and isinstance(img[0], str):
            # On some systems, grabclipboard() might return a list of file paths
            if is_image_file(img[0]):
                return Image.open(img[0])
    except Exception:
        pass
    return None


def display_image(image: Image.Image, root: tk.Tk) -> None:
    """Display an image in a new window."""
    if not PIL_AVAILABLE:
        return
    
    top = tk.Toplevel(root)
    top.title("Image Preview")
    
    # Scale image if too large
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    max_w, max_h = screen_width * 0.8, screen_height * 0.8
    
    w, h = image.size
    if w > max_w or h > max_h:
        ratio = min(max_w / w, max_h / h)
        image = image.resize((int(w * ratio), int(h * ratio)), Image.Resampling.LANCZOS)
    
    img_tk = ImageTk.PhotoImage(image)
    label = tk.Label(top, image=img_tk)
    label.image = img_tk  # type: ignore
    label.pack()


THEMES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "themes")
THEME_SELECTION_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "theme_selection.json")


def get_available_themes() -> list[str]:
    """Return a sorted list of theme names found in the themes directory."""
    if not os.path.isdir(THEMES_DIR):
        return []
    names = []
    for fname in os.listdir(THEMES_DIR):
        if fname.endswith(".json"):
            names.append(fname[:-5])
    return sorted(names)


def load_theme_colors(theme_name: str | None = None) -> dict[str, str]:
    """Load theme colors from the themes folder, falling back to defaults."""
    default_colors: dict[str, str] = {
        "BG_COLOR":                 "#2b2b2b",
        "FG_COLOR":                 "#d4d4d4",
        "ENTRY_BG_COLOR":           "#3c3c3c",
        "BUTTON_BG_COLOR":          "#4b4b4b",
        "BUTTON_ACTIVE_BG":         "#5b5b5b",
        "TEXT_BG_COLOR":            "#1e1e1e",
        "STATUS_CONNECTED":         "#4CAF50",
        "STATUS_NOT_CONNECTED":     "#ff6b6b",
        "STATUS_KEY_EXCHANGE":      "#FF9800",
        "STATUS_VERIFIED":          "#2196F3",
        "MESSAGE_TIME_COLOR":       "#888888",
        "MESSAGE_NICKNAME_COLOR":   "#569cd6",
        "SYSTEM_MESSAGE_COLOR":     "#ce9178",
        "ERROR_MESSAGE_COLOR":      "#f44747",
        "DELIVERY_PENDING_COLOR":   "#888888",
        "DELIVERY_CONFIRMED_COLOR": "#4CAF50",
        "SPELLCHECK_ERROR_COLOR":   "#f44747",
        "SPEED_LABEL_COLOR":        "#4CAF50",
    }

    # Determine which theme to load
    selected = theme_name
    if selected is None:
        try:
            with open(THEME_SELECTION_FILE, "r") as f:
                data = json.load(f)
                selected = data.get("theme")
        except (OSError, json.JSONDecodeError):
            selected = None

    if selected:
        theme_path = os.path.join(THEMES_DIR, f"{selected}.json")
        try:
            with open(theme_path, "r") as f:
                user_colors: dict[str, Any] = json.load(f)
                default_colors.update(user_colors)
                return default_colors
        except (OSError, PermissionError, json.JSONDecodeError):
            pass

    # Legacy fallback: theme.json in project root
    legacy_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "theme.json")
    if os.path.exists(legacy_path):
        try:
            with open(legacy_path, "r") as f:
                user_colors = json.load(f)
                default_colors.update(user_colors)
                return default_colors
        except (OSError, PermissionError, json.JSONDecodeError):
            pass

    return default_colors


def save_theme_selection(theme_name: str) -> None:
    """Persist the selected theme name to theme_selection.json."""
    try:
        with open(THEME_SELECTION_FILE, "w") as f:
            json.dump({"theme": theme_name}, f, indent=4)
    except (OSError, PermissionError):
        pass


class WordFrequency:
    def load_words(self, words: Iterable[str | bytes]) -> None:
        pass


class SpellCheckerWrap:
    def __init__(self):
        if SPELLCHECKER_AVAILABLE:
            self.sc = SpellChecker()
        else:
            self.sc = None
    
    def unknown(self, words: Iterable[str]) -> set[str]:
        if self.sc:
            return self.sc.unknown(words)
        return set()
    
    def candidates(self, word: str) -> set[str]:
        if self.sc:
            return self.sc.candidates(word) or set()
        return set()


# noinspection DuplicatedCode
class GUI(UIBase):
    def __init__(self, root: tk.Tk):
        self.root: tk.Tk = root
        self.root.title("Secure Chat Client")
        self.root.geometry("950x600")
        
        self.theme_colors = load_theme_colors()
        self.BG_COLOR = self.theme_colors["BG_COLOR"]
        self.FG_COLOR = self.theme_colors["FG_COLOR"]
        self.ENTRY_BG_COLOR = self.theme_colors["ENTRY_BG_COLOR"]
        self.BUTTON_BG_COLOR = self.theme_colors["BUTTON_BG_COLOR"]
        self.BUTTON_ACTIVE_BG = self.theme_colors["BUTTON_ACTIVE_BG"]
        self.TEXT_BG_COLOR = self.theme_colors["TEXT_BG_COLOR"]
        
        self.root.configure(bg=self.BG_COLOR)
        
        self.client: ClientBase | None = None
        self.peer_nickname: str = "Other user"
        self.config = ConfigHandler()
        
        self.ephemeral_mode: str = "OFF"
        self.ephemeral_global_owner_id: str | None = None
        self.local_client_id: str = str(uuid.uuid4())
        self.ephemeral_messages: dict[str, float] = {}
        self.message_counter: int = 0
        self.sent_messages: dict[int, str] = {}
        
        self.notification_enabled: bool = self.config["notification_sound"]
        self.window_focused: bool = True
        self.system_notifications_enabled: bool = self.config["system_notifications"] and PLYER_AVAILABLE
        self.allow_voice_calls: bool = self.config["allow_voice_calls"] and PYAUDIO_AVAILABLE
        self.auto_display_images: bool = self.config["auto_display_images"] and PIL_AVAILABLE
        
        self.file_transfer_window = FileTransferWindow(self.root, self.theme_colors)
        self._deaddrop_window: DeadDropWindow | None = None
        
        self.spell_checker = SpellCheckerWrap()
        self.spellcheck_timer: str = ""
        self.spellcheck_enabled: bool = SPELLCHECKER_AVAILABLE
        self.misspelled_tags: set[str] = set()
        
        if PYAUDIO_AVAILABLE:
            self.audio_interface = pyaudio.PyAudio()
            self.notification_stream = None
        else:
            self.audio_interface = None
            self.notification_stream = None
        
        self.current_theme_name: str = self._load_saved_theme_name()
        self.create_widgets()
        self.setup_focus_tracking()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    @staticmethod
    def _load_saved_theme_name() -> str:
        """Return the persisted theme name, or empty string if none saved."""
        try:
            with open(THEME_SELECTION_FILE, "r") as f:
                data = json.load(f)
                return data.get("theme", "")
        except (OSError, json.JSONDecodeError):
            return ""

    def apply_theme(self, theme_name: str) -> None:
        """Load and apply a theme by name, re-coloring all existing widgets."""
        self.theme_colors = load_theme_colors(theme_name)
        self.current_theme_name = theme_name
        self.BG_COLOR = self.theme_colors["BG_COLOR"]
        self.FG_COLOR = self.theme_colors["FG_COLOR"]
        self.ENTRY_BG_COLOR = self.theme_colors["ENTRY_BG_COLOR"]
        self.BUTTON_BG_COLOR = self.theme_colors["BUTTON_BG_COLOR"]
        self.BUTTON_ACTIVE_BG = self.theme_colors["BUTTON_ACTIVE_BG"]
        self.TEXT_BG_COLOR = self.theme_colors["TEXT_BG_COLOR"]

        save_theme_selection(theme_name)
        self._recolor_widgets()

    def _recolor_widgets(self) -> None:
        """Re-apply theme colors to all main widgets."""
        self.root.configure(bg=self.BG_COLOR)

        def recolor(widget: tk.Widget) -> None:
            cls = widget.winfo_class()
            try:
                if cls in ("Frame", "Toplevel"):
                    widget.configure(bg=self.BG_COLOR)  # type: ignore
                elif cls == "Label":
                    widget.configure(bg=self.BG_COLOR, fg=self.FG_COLOR)  # type: ignore
                elif cls == "Button":
                    widget.configure(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR,  # type: ignore
                                     activebackground=self.BUTTON_ACTIVE_BG)
                elif cls == "Entry":
                    widget.configure(bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)  # type: ignore
                elif cls in ("Text", "ScrolledText"):
                    widget.configure(bg=self.TEXT_BG_COLOR, fg=self.FG_COLOR)  # type: ignore
                elif cls == "Checkbutton":
                    widget.configure(bg=self.BG_COLOR, fg=self.FG_COLOR,  # type: ignore
                                     selectcolor=self.BUTTON_BG_COLOR,
                                     activebackground=self.BUTTON_ACTIVE_BG,
                                     activeforeground=self.FG_COLOR)
            except tk.TclError:
                pass
            for child in widget.winfo_children():
                recolor(child)

        recolor(self.root)

        # Update specific widgets that use named theme color keys
        try:
            self.status_label.configure(fg=self.theme_colors.get("STATUS_NOT_CONNECTED", "#ff6b6b"))
        except AttributeError:
            pass
        try:
            self.chat_display.configure(bg=self.TEXT_BG_COLOR, fg=self.FG_COLOR)
            self.chat_display.tag_configure("misspelled", underline=True,
                                            underlinefg=self.theme_colors.get("SPELLCHECK_ERROR_COLOR", "red"))
        except AttributeError:
            pass
        try:
            self.message_entry.configure(bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR)
            self.message_entry.tag_configure("misspelled", underline=True,
                                             underlinefg=self.theme_colors.get("SPELLCHECK_ERROR_COLOR", "red"))
        except AttributeError:
            pass

    def set_client(self, client: ClientBase) -> None:
        self.client = client
    
    @property
    def capabilities(self) -> UICapability:
        caps = UICapability.NONE
        caps |= UICapability.FILE_TRANSFER
        caps |= UICapability.EPHEMERAL_MODE
        caps |= UICapability.DELIVERY_STATUS
        caps |= UICapability.NICKNAMES
        if PYAUDIO_AVAILABLE:
            caps |= UICapability.VOICE_CALLS
        caps |= UICapability.DEADDROP
        return caps
    
    def on_tk_thread(self, func: Callable[P, Any], /, *args: P.args, **kwargs: P.kwargs) -> None:
        self.root.after(0, lambda: func(*args, **kwargs))  # type: ignore
    
    def no_types_tk_thread(self, func: Callable[[Any], Any], /, *args: Any, **kwargs: Any) -> None:
        self.root.after(0, lambda: func(*args, **kwargs))  # type: ignore
    
    def setup_focus_tracking(self) -> None:
        def on_focus_in(_) -> None: self.window_focused = True
        
        def on_focus_out(_) -> None: self.window_focused = False
        
        self.root.bind("<FocusIn>", on_focus_in)
        self.root.bind("<FocusOut>", on_focus_out)
        self.root.bind("<Control-q>", self.emergency_close)
    
    # noinspection PyAttributeOutsideInit
    def create_widgets(self) -> None:
        main_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        main_frame.pack(fill=ltk.BOTH, expand=True, padx=10, pady=10)
        
        conn_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        conn_frame.pack(fill=ltk.X, pady=(0, 10))
        
        tk.Label(conn_frame, text="Host:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=ltk.LEFT)
        self.host_entry = tk.Entry(conn_frame, width=15, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.host_entry.pack(side=ltk.LEFT, padx=(5, 10))
        self.host_entry.insert(0, "localhost")
        
        tk.Label(conn_frame, text="Port:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=ltk.LEFT)
        self.port_entry = tk.Entry(conn_frame, width=8, bg=self.ENTRY_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.port_entry.pack(side=ltk.LEFT, padx=(5, 10))
        self.port_entry.insert(0, "16384")
        
        self.connect_btn = tk.Button(conn_frame, text="Connect", command=self.toggle_connection,
                                     bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.connect_btn.pack(side=ltk.LEFT, padx=(10, 0))
        
        self.config_btn = tk.Button(conn_frame, text="Config", command=self.open_config_dialog,
                                    bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.config_btn.pack(side=ltk.LEFT, padx=(10, 0))
        
        if PYAUDIO_AVAILABLE:
            self.voice_call_btn = tk.Button(conn_frame, text="Voice Call", command=self.start_call,
                                            bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
            self.voice_call_btn.pack(side=ltk.LEFT, padx=(10, 0))
            self.mute_btn = tk.Button(conn_frame, text="Mute", command=self.toggle_mute,
                                      bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        
        self.status_label = tk.Label(conn_frame, text="Not Connected", bg=self.BG_COLOR,
                                     fg=self.theme_colors.get("STATUS_NOT_CONNECTED", "#ff6b6b"),
                                     font=("Consolas", 9, "bold"))
        self.status_label.pack(side=ltk.RIGHT, padx=(10, 0))
        
        self.chat_display = scrolledtext.ScrolledText(main_frame, state=ltk.DISABLED, wrap=ltk.WORD, height=20,
                                                      font=("Consolas", 10), bg=self.TEXT_BG_COLOR, fg=self.FG_COLOR,
                                                      relief=ltk.FLAT)
        self.chat_display.pack(fill=ltk.BOTH, expand=True, pady=(0, 10))
        if TKINTERDND2_AVAILABLE:
            # noinspection PyUnresolvedReferences
            self.chat_display.drop_target_register(DND_FILES)
            # noinspection PyUnresolvedReferences
            self.chat_display.dnd_bind('<<Drop>>', self.handle_drop)
        
        self.input_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        self.input_frame.pack(fill=ltk.X)
        
        self.message_entry = tk.Text(self.input_frame, height=1, font=("Consolas", 10), bg=self.ENTRY_BG_COLOR,
                                     fg=self.FG_COLOR, width=15, relief=ltk.FLAT, wrap=ltk.NONE)
        self.message_entry.pack(side=ltk.LEFT, fill=ltk.X, expand=True, padx=(0, 10))
        self.message_entry.tag_configure("misspelled", underline=True,
                                         underlinefg=self.theme_colors.get("SPELLCHECK_ERROR_COLOR", "red"))
        
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        self.message_entry.bind("<Control-v>", self.on_paste)
        self.message_entry.bind("<KeyRelease>", self.on_text_change)
        self.message_entry.bind("<Button-1>", self.on_text_change)
        self.message_entry.bind("<Button-3>", self.show_spellcheck_menu)
        
        self.send_btn = tk.Button(self.input_frame, text="Send", command=self.send_message,
                                  bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.send_btn.pack(side=ltk.LEFT)
        
        self.send_file_btn = tk.Button(self.input_frame, text="📁", command=self.on_send_file_click,
                                       bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.send_file_btn.pack(side=ltk.LEFT, padx=(5, 0))
        
        self.deaddrop_btn = tk.Button(self.input_frame, text="Dead Drop", command=self.open_deaddrop_window,
                                      bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        self.deaddrop_btn.pack(side=ltk.LEFT, padx=(5, 0))
    
    # --- UIBase implementations ---
    def display_regular_message(self, message: str, nickname: str | None = None) -> None:
        nick = nickname or self.peer_nickname
        self.on_tk_thread(self._append_to_chat, f"{nick}: {message}", is_message=True)
        if not self.window_focused:
            self.play_notification_sound()
            self.show_sys_notification(f"New message from {nick}")
    
    def display_error_message(self, message: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"ERROR: {message}")
        self.on_tk_thread(messagebox.showerror, "Error", message)
    
    def display_system_message(self, message: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: {message}")
    
    def display_raw_message(self, message: str) -> None:
        self.on_tk_thread(self._append_to_chat, message)
    
    def prompt_key_verification(self, fingerprint: str) -> bool:
        # This is called from the client thread.
        res = messagebox.askyesno("Verify Fingerprint",
                                  f"Do you verify that the following fingerprint matches the peer's?\n\n{fingerprint}")
        if res and self.client:
            self.client.confirm_key_verification(True)
        return res
    
    def prompt_file_transfer(self, filename: str, file_size: int, total_chunks: int,
                             compressed_file_size: int | None = None,
                             ) -> Path | bool | None:
        # This is called from the client thread.
        size_str = bytes_to_human_readable(file_size)
        msg = f"Incoming file: {filename}\nSize: {size_str}\nDo you want to accept it?"
        if messagebox.askyesno("File Transfer", msg):
            save_path = filedialog.asksaveasfilename(initialfile=filename)
            if save_path:
                return Path(save_path)
            else:
                return True  # Accept but use default (current dir)
        else:
            return False
    
    def prompt_rekey(self) -> bool | None:
        # This is called from the client thread.
        msg = "Peer requested a rekey. Do you want to proceed?\n\nYes: Proceed\nNo: Disconnect\nCancel: Reject rekey but stay connected"
        res = messagebox.askyesnocancel("Rekey Request", msg)
        if res is True:
            return True
        elif res is False:
            return False
        else:
            return None
    
    def on_connected(self) -> None:
        self.on_tk_thread(self._update_status, "Connected", self.theme_colors.get("STATUS_CONNECTED", "#4CAF50"))
        self.no_types_tk_thread(self.connect_btn.configure, text="Disconnect")
    
    def on_graceful_disconnect(self, reason: str) -> None:
        self.on_tk_thread(self._update_status, "Disconnected", self.theme_colors.get("STATUS_NOT_CONNECTED", "#ff6b6b"))
        self.no_types_tk_thread(self.connect_btn.configure, text="Connect")
        self.on_tk_thread(self._append_to_chat, f"Disconnected: {reason}")
    
    def on_unexpected_disconnect(self, reason: str) -> None:
        self.on_tk_thread(self._update_status, "Disconnected (Error)", self.theme_colors.get("STATUS_NOT_CONNECTED", "#ff6b6b"))
        self.no_types_tk_thread(self.connect_btn.configure, text="Connect")
        self.on_tk_thread(messagebox.showerror, "Disconnected", f"Unexpectedly disconnected: {reason}")
    
    # --- Event Handlers ---
    def on_key_exchange_started(self) -> None:
        self.on_tk_thread(self._update_status, "Key Exchange...", self.theme_colors.get("STATUS_KEY_EXCHANGE", "#FF9800"))
    
    def on_key_exchange_complete(self) -> None:
        self.on_tk_thread(self._update_status, "Encrypted", self.theme_colors.get("STATUS_CONNECTED", "#4CAF50"))
        if self.client and not self.client.peer_key_verified:
            self.on_tk_thread(self._append_to_chat, "Connection encrypted but peer not verified.")
    
    def on_rekey_complete(self) -> None:
        self.on_tk_thread(self._append_to_chat, "Rekey complete.")
    
    def on_auto_rekey(self) -> None:
        self.on_tk_thread(self._append_to_chat, "Auto rekey message threshold reached. Rekeying...")
    
    def on_nickname_change(self, new_nickname: str) -> None:
        old_nick = self.peer_nickname
        self.peer_nickname = new_nickname
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: {old_nick} changed their nickname to {new_nickname}")
    
    def on_delivery_confirmation(self, message_counter: int) -> None:
        self.on_tk_thread(self.update_message_delivery_status, message_counter)
    
    def on_ephemeral_mode_change(self, mode: str, owner_id: str | None) -> None:
        self.ephemeral_mode = mode
        self.ephemeral_global_owner_id = owner_id
        self.on_tk_thread(self.update_ephemeral_ui)
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Ephemeral mode changed to {mode}")
    
    def on_voice_call_init(self, init_msg: dict[str, Any]) -> None:
        threading.Thread(target=self.prompt_voice_call, args=(init_msg,), daemon=True).start()
    
    def on_voice_call_accept(self, message: dict[str, Any]) -> None:
        if PYAUDIO_AVAILABLE:
            self.no_types_tk_thread(self.voice_call_btn.configure, text="End Call")
    
    def on_voice_call_reject(self) -> None:
        self.on_tk_thread(self._append_to_chat, "SYSTEM: Voice call rejected by peer.")
    
    def on_voice_call_end(self) -> None:
        if PYAUDIO_AVAILABLE:
            self.no_types_tk_thread(self.voice_call_btn.configure, text="Voice Call")
    
    def file_download_progress(self, transfer_id: str, filename: str, received_chunks: int, total_chunks: int, bytes_transferred: int = -1) -> None:
        self.on_tk_thread(self.file_transfer_window.update_transfer_progress, filename, received_chunks, total_chunks, bytes_transferred, "Downloading")
    
    def file_upload_progress(self, transfer_id: str, filename: str, sent_chunks: int, total_chunks: int, bytes_transferred: int = -1) -> None:
        self.on_tk_thread(self.file_transfer_window.update_transfer_progress, filename, sent_chunks, total_chunks, bytes_transferred, "Uploading")
    
    def on_file_transfer_complete(self, transfer_id: str, output_path: str) -> None:
        self.on_tk_thread(self.file_transfer_window.add_transfer_message, f"File transfer complete: {output_path}")
        self.on_tk_thread(self._append_to_chat, f"File transfer complete: {output_path}")
    
    def _append_to_chat(self, text: str, is_message: bool = False, show_time: bool = True) -> None:
        self.chat_display.config(state=ltk.NORMAL)
        timestamp = time.strftime("[%H:%M:%S] ") if show_time else ""
        
        if is_message:
            msg_id = f"msg_{int(time.time() * 1000)}"
            self.chat_display.insert(ltk.END, timestamp, "time")
            self.chat_display.insert(ltk.END, f"{text}\n", msg_id)
            if self.ephemeral_mode != "OFF":
                # Handle ephemeral timing if needed
                pass
        else:
            self.chat_display.insert(ltk.END, f"{timestamp}{text}\n")
        
        self.chat_display.tag_configure("time", foreground=self.theme_colors.get("MESSAGE_TIME_COLOR", "#888888"))
        self.chat_display.see(ltk.END)
        self.chat_display.config(state=ltk.DISABLED)
    
    def _update_status(self, status_text: str, color: str = "") -> None:
        self.status_label.config(text=status_text)
        if color:
            self.status_label.config(fg=color)
    
    def toggle_connection(self) -> None:
        if not self.client:
            return
        if self.client.connected:
            self.client.disconnect()
        else:
            host = self.host_entry.get()
            try:
                port = int(self.port_entry.get())
                threading.Thread(target=self.client.connect, args=(host, port), daemon=True).start()
            except ValueError:
                messagebox.showerror("Error", "Invalid port number")
    
    def send_message(self, event: tk.Event | None = None) -> str:
        if event:
            # Shift+Enter for new line, Enter to send
            if event.state & 0x1:  # Shift pressed
                return ""
        
        text = self.message_entry.get("1.0", ltk.END).strip()
        if not text or not self.client:
            return "break"
        
        # Check for commands
        if text.startswith("/"):
            self.handle_command(text)
        else:
            counter = self.client.next_message_counter
            tag_id = f"sent_{counter}"
            
            self.chat_display.config(state=ltk.NORMAL)
            timestamp = time.strftime("[%H:%M:%S] ")
            self.chat_display.insert(ltk.END, timestamp, "time")
            nick = self.client.own_nickname
            self.chat_display.insert(ltk.END, f"{nick}: ", "own_nick")
            self.chat_display.insert(ltk.END, f"{text} ", tag_id)
            self.chat_display.insert(ltk.END, "○\n", f"status_{counter}")
            
            self.chat_display.tag_configure("own_nick", foreground=self.theme_colors.get("MESSAGE_NICKNAME_COLOR", "#569cd6"))
            self.chat_display.tag_configure(f"status_{counter}", foreground=self.theme_colors.get("DELIVERY_PENDING_COLOR", "#888888"))
            self.chat_display.see(ltk.END)
            self.chat_display.config(state=ltk.DISABLED)
            
            self.sent_messages[counter] = f"status_{counter}"
            
            threading.Thread(target=self.client.send_message, args=(text,), daemon=True).start()
        
        self.message_entry.delete("1.0", ltk.END)
        return "break"
    
    def handle_command(self, text: str) -> None:
        if not self.client:
            return
        cmd_parts = text.split()
        cmd = cmd_parts[0].lower()
        
        if cmd == "/nick" or cmd == "/nickname":
            if len(cmd_parts) > 1:
                self.client.own_nickname = cmd_parts[1]
                self._append_to_chat(f"Nickname changed to: {cmd_parts[1]}")
            else:
                self._append_to_chat("Usage: /nick <name>")
        elif cmd == "/rekey":
            self.client.initiate_rekey()
        elif cmd == "/emergency":
            self.client.emergency_close()
        elif cmd == "/deaddrop":
            self.open_deaddrop_window()
        elif cmd.startswith("/deaddrop"):
            sub = cmd_parts[1].lower() if len(cmd_parts) > 1 else ""
            if sub == "upload":
                self.open_deaddrop_window(tab="Upload")
            elif sub == "check":
                self.open_deaddrop_window(tab="Check")
            elif sub == "download":
                self.open_deaddrop_window(tab="Download")
            else:
                self._append_to_chat("Usage: /deaddrop [upload|check|download]")
        else:
            self._append_to_chat(f"Unknown command: {cmd}")
    
    def update_message_delivery_status(self, counter: int) -> None:
        tag = self.sent_messages.get(counter)
        if tag:
            self.chat_display.config(state=ltk.NORMAL)
            # Find the text of the tag
            ranges = self.chat_display.tag_ranges(tag)
            if ranges:
                self.chat_display.delete(ranges[0], ranges[1])
                self.chat_display.insert(ranges[0], "●", tag)
                self.chat_display.tag_configure(tag, foreground=self.theme_colors.get("DELIVERY_CONFIRMED_COLOR", "#4CAF50"))
            self.chat_display.config(state=ltk.DISABLED)
    
    def on_send_file_click(self, event=None) -> None:
        file_path = filedialog.askopenfilename()
        if file_path and self.client:
            threading.Thread(target=self.client.send_file, args=(Path(file_path),), daemon=True).start()
    
    def handle_drop(self, event) -> None:
        files = self.root.tk.splitlist(event.data)  # type: ignore
        for f in files:
            if os.path.isfile(f) and self.client:
                threading.Thread(target=self.client.send_file, args=(Path(f),), daemon=True).start()
    
    def on_key_press(self, event: tk.Event) -> None:
        # Ported from old_gui.py
        pass
    
    def on_paste(self, event: tk.Event) -> None:
        img = get_image_from_clipboard()
        if img and self.client:
            if messagebox.askyesno("Send Image", "Image found in clipboard. Do you want to send it?"):
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
                img.save(temp_file.name)
                temp_file.close()
                threading.Thread(target=self.client.send_file, args=(Path(temp_file.name),), daemon=True).start()
    
    def on_text_change(self, event: tk.Event | None = None) -> None:
        if self.spellcheck_enabled:
            # Cancel previous timer
            if self.spellcheck_timer:
                self.root.after_cancel(self.spellcheck_timer)
            self.spellcheck_timer = self.root.after(500, self.perform_spellcheck)  # type: ignore
    
    def perform_spellcheck(self) -> None:
        self.spellcheck_timer = ""
        # Get all text
        text = self.message_entry.get("1.0", "end-1c")
        # Split by non-word characters
        words = re.findall(r"\w+", text)
        
        # Remove old tags
        self.message_entry.tag_remove("misspelled", "1.0", ltk.END)
        self.misspelled_tags.clear()
        
        if not words:
            return
        
        misspelled = self.spell_checker.unknown(words)
        
        for word in misspelled:
            start_pos = "1.0"
            while True:
                # search for exact word
                start_pos = self.message_entry.search(rf"\y{re.escape(word)}\y", start_pos, stopindex=ltk.END, regexp=True)
                if not start_pos:
                    break
                
                # Verify it's a whole word
                end_pos = f"{start_pos} + {len(word)}c"
                
                # Add tag
                self.message_entry.tag_add("misspelled", start_pos, end_pos)
                
                start_pos = end_pos
    
    def show_spellcheck_menu(self, event: tk.Event) -> None:
        pass
    
    # noinspection PyAttributeOutsideInit
    def open_config_dialog(self) -> None:
        """Open a small configuration window with common settings."""
        if hasattr(self, "config_window") and self.config_window and self.config_window.winfo_exists():
            self.config_window.lift()
            self.config_window.focus_set()
            return
        
        self.config_window = tk.Toplevel(self.root)
        self.config_window.title("Configuration")
        self.config_window.configure(bg=self.BG_COLOR)
        self.config_window.resizable(False, False)
        
        container = tk.Frame(self.config_window, bg=self.BG_COLOR)
        container.pack(padx=10, pady=10, fill=ltk.BOTH, expand=True)
        
        # Tk variables reflecting current settings
        self.var_sound_notif = tk.BooleanVar(value=self.notification_enabled)
        self.var_system_notif = tk.BooleanVar(value=self.system_notifications_enabled)
        self.var_allow_calls = tk.BooleanVar(value=self.allow_voice_calls)
        self.var_allow_file_transfers = tk.BooleanVar(
                value=self.client.allow_file_transfers if self.client else True)
        self.var_send_delivery_receipts = tk.BooleanVar(
                value=self.client.send_delivery_receipts if self.client else True)
        
        # Checkbuttons
        cb1 = tk.Checkbutton(container, text="Notification sounds", variable=self.var_sound_notif,
                             command=lambda: setattr(self, 'notification_enabled', self.var_sound_notif.get()))
        cb2 = tk.Checkbutton(container, text="System notifications", variable=self.var_system_notif,
                             command=lambda: setattr(self, 'system_notifications_enabled', self.var_system_notif.get()))
        cb4 = tk.Checkbutton(container, text="Allow voice calls", variable=self.var_allow_calls,
                             command=lambda: setattr(self, 'allow_voice_calls', self.var_allow_calls.get()))
        cb5 = tk.Checkbutton(container, text="Allow file transfers", variable=self.var_allow_file_transfers,
                             command=lambda: (setattr(self.client, 'allow_file_transfers',
                                                      self.var_allow_file_transfers.get()) if self.client else None))
        cb6 = tk.Checkbutton(container, text="Send delivery receipts", variable=self.var_send_delivery_receipts,
                             command=lambda: (setattr(self.client, 'send_delivery_receipts',
                                                      self.var_send_delivery_receipts.get()) if self.client else None))
        
        for cb in (cb1, cb2, cb4, cb5, cb6):
            cb.configure(bg=self.BG_COLOR, fg=self.FG_COLOR, selectcolor=self.BUTTON_BG_COLOR,
                         activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR)
            cb.pack(anchor="w", pady=2)
        
        # Theme selector
        theme_frame = tk.Frame(container, bg=self.BG_COLOR)
        theme_frame.pack(fill=ltk.X, pady=(8, 2))
        tk.Label(theme_frame, text="Theme:", bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=ltk.LEFT)

        available_themes = get_available_themes()
        self.var_theme = tk.StringVar(value=self.current_theme_name if self.current_theme_name in available_themes else (available_themes[0] if available_themes else ""))

        if available_themes:
            theme_menu = tk.OptionMenu(theme_frame, self.var_theme, *available_themes,
                                       command=self._on_theme_selected)
            theme_menu.configure(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR,
                                 activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
                                 highlightthickness=0, relief=ltk.FLAT)
            theme_menu["menu"].configure(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR)
            theme_menu.pack(side=ltk.LEFT, padx=(5, 0))
        else:
            tk.Label(theme_frame, text="No themes found in /themes",
                     bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=ltk.LEFT, padx=(5, 0))

        # Close button
        btn_close = tk.Button(container, text="Close", command=self.config_window.destroy,
                              bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=ltk.FLAT)
        btn_close.pack(pady=(10, 0))
    
    def _on_theme_selected(self, theme_name: str) -> None:
        """Called when the user picks a theme from the dropdown."""
        self.apply_theme(theme_name)
        # Re-style the config window itself if it's open
        if hasattr(self, "config_window") and self.config_window and self.config_window.winfo_exists():
            self.config_window.configure(bg=self.BG_COLOR)
            for child in self.config_window.winfo_children():
                try:
                    child.configure(bg=self.BG_COLOR)  # type: ignore
                except tk.TclError:
                    pass

    def start_call(self) -> None:
        if self.client and self.allow_voice_calls:
            if self.client.voice_call_active:
                self.client.end_call()
                return
            rate = self.config["voice_rate"]
            chunk = self.config.voice_chunk
            fmt = self.config["voice_format"]
            threading.Thread(target=self.client.request_voice_call, args=(rate, chunk, fmt), daemon=True).start()
    
    def toggle_mute(self) -> None:
        if self.client:
            self.client.voice_muted = not self.client.voice_muted
    
    def prompt_voice_call(self, init_msg: dict[str, Any]) -> None:
        def play_ringtone(stop_event: threading.Event):
            if not PYAUDIO_AVAILABLE or not self.audio_interface:
                return
            try:
                with wave.open(self.config["ringtone_file"], 'rb') as wf:
                    stream = self.audio_interface.open(
                            format=self.audio_interface.get_format_from_width(wf.getsampwidth()),
                            channels=wf.getnchannels(),
                            rate=wf.getframerate(),
                            output=True,
                    )
                    data = wf.readframes(1024)
                    while data and not stop_event.is_set():
                        stream.write(data)
                        data = wf.readframes(1024)
                        if not data:
                            wf.rewind()
                            data = wf.readframes(1024)
                    stream.stop_stream()
                    stream.close()
            except Exception:
                pass
        
        stop_event = threading.Event()
        ringtone_thread = threading.Thread(target=play_ringtone, args=(stop_event,), daemon=True)
        ringtone_thread.start()
        
        msg = f"Incoming voice call from {self.peer_nickname}. Accept?"
        res = messagebox.askyesno("Voice Call", msg)
        stop_event.set()
        
        if res:
            rate = init_msg.get("rate", 44100)
            chunk = init_msg.get("chunk_size", 1024)
            fmt = init_msg.get("audio_format", 8)
            if self.client:
                self.client.on_user_response(True, rate, chunk, fmt)
        else:
            if self.client:
                self.client.on_user_response(False, 0, 0, 0)
    
    def open_deaddrop_window(self, tab: str = "Upload") -> None:
        if not self.client:
            messagebox.showerror("Dead Drop", "Not connected.")
            return
        if self._deaddrop_window is None or not self._deaddrop_window.window.winfo_exists():
            self._deaddrop_window = DeadDropWindow(self.root, self.client, self.theme_colors)
        self._deaddrop_window._show_tab(tab)
        self._deaddrop_window.window.lift()
        self._deaddrop_window.window.focus_set()
    
    # --- Deaddrop UIBase callbacks ---
    
    def on_deaddrop_handshake_started(self) -> None:
        self.on_tk_thread(self._append_to_chat, "SYSTEM: Deaddrop handshake started.")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, "Handshake started…")
    
    def on_deaddrop_handshake_complete(self) -> None:
        self.on_tk_thread(self._append_to_chat, "SYSTEM: Deaddrop handshake complete.")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, "Handshake complete.")
    
    def on_deaddrop_handshake_failed(self, reason: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Deaddrop handshake failed: {reason}")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, f"Handshake failed: {reason}")
    
    def on_deaddrop_upload_started(self, name: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Deaddrop upload started: {name}")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, f"Upload started: {name}")
    
    def on_deaddrop_upload_progress(self, name: str, bytes_uploaded: int, total_bytes: int) -> None:
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            pct = (bytes_uploaded / total_bytes * 100) if total_bytes > 0 else 0
            self.on_tk_thread(self._deaddrop_window.log,
                              f"Upload progress: {name} {pct:.1f}% ({bytes_to_human_readable(bytes_uploaded)} / {bytes_to_human_readable(total_bytes)})")
    
    def on_deaddrop_upload_complete(self, name: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Deaddrop upload complete: {name}")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, f"Upload complete: {name}")
    
    def on_deaddrop_download_started(self, name: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Deaddrop download started: {name}")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, f"Download started: {name}")
    
    def on_deaddrop_download_progress(self, name: str, bytes_downloaded: int, total_bytes: int) -> None:
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            pct = (bytes_downloaded / total_bytes * 100) if total_bytes > 0 else 0
            self.on_tk_thread(self._deaddrop_window.log,
                              f"Download progress: {name} {pct:.1f}% ({bytes_to_human_readable(bytes_downloaded)} / {bytes_to_human_readable(total_bytes)})")
    
    def on_deaddrop_download_complete(self, name: str, output_path: str) -> None:
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Deaddrop download complete: {output_path}")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, f"Download complete: {output_path}")
    
    def on_deaddrop_check_result(self, name: str, exists: bool) -> None:
        result = "exists" if exists else "does not exist"
        self.on_tk_thread(self._append_to_chat, f"SYSTEM: Deaddrop '{name}' {result}.")
        if self._deaddrop_window and self._deaddrop_window.window.winfo_exists():
            self.on_tk_thread(self._deaddrop_window.log, f"'{name}' {result}.")
    
    def update_ephemeral_ui(self) -> None:
        pass
    
    def play_notification_sound(self) -> None:
        if not self.notification_enabled or not PYAUDIO_AVAILABLE or not self.audio_interface:
            return
        
        def play_notif():
            try:
                with wave.open(self.config["message_notif_sound_file"], 'rb') as wf:
                    stream = self.audio_interface.open(
                            format=self.audio_interface.get_format_from_width(wf.getsampwidth()),
                            channels=wf.getnchannels(),
                            rate=wf.getframerate(),
                            output=True,
                    )
                    data = wf.readframes(1024)
                    while data:
                        stream.write(data)
                        data = wf.readframes(1024)
                    stream.stop_stream()
                    stream.close()
            except Exception:
                pass
        
        threading.Thread(target=play_notif, daemon=True).start()
    
    def show_sys_notification(self, message: str) -> None:
        if self.system_notifications_enabled and notification:
            notification.notify(title="Secure Chat", message=message)
    
    def emergency_close(self, *args) -> None:
        if self.client:
            self.client.emergency_close()
        self.root.destroy()
    
    def on_closing(self) -> None:
        if self.client:
            self.client.disconnect()
        self.root.destroy()


def run(client_class: type[ClientBase]) -> None:
    if TKINTERDND2_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    
    ui = GUI(root)
    client = client_class(ui)
    ui.set_client(client)
    
    root.mainloop()
