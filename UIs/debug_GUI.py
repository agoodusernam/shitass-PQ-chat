"""
Debug GUI — a tkinter UI implementation for development and testing.

Provides a standard chat interface on the left and a live debug panel on
the right that shows cryptographic state, connection info, and offers
debug actions.  Where possible the debug panel uses the public ClientBase
API; richer crypto details are read from client._protocol via hasattr
guards so the GUI degrades gracefully when internals change.
"""

from __future__ import annotations

import datetime
import os
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from typing import Any, Literal

from SecureChatABCs.client_base import ClientBase
from SecureChatABCs.ui_base import UIBase, UICapability
from debug_client import DebugClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Ltk:
    """
    Literal types for Tkinter constants because type checking YAY
    """
    END: Literal["end"] = "end"
    W: Literal["w"] = "w"
    X: Literal["x"] = "x"
    Y: Literal["y"] = "y"
    BOTH: Literal["both"] = "both"
    RIGHT: Literal["right"] = "right"
    LEFT: Literal["left"] = "left"
    DISABLED: Literal["disabled"] = "disabled"
    NORMAL: Literal["normal"] = "normal"
    ACTIVE: Literal["active"] = "active"
    FLAT: Literal["flat"] = "flat"
    HORIZONTAL: Literal["horizontal"] = "horizontal"
    VERTICAL: Literal["vertical"] = "vertical"
    WORD: Literal["word"] = "word"
    NONE: Literal["none"] = "none"


ltk: Ltk = Ltk()

# Dark theme colours
BG_COLOR = "#2b2b2b"
FG_COLOR = "#d4d4d4"
ENTRY_BG_COLOR = "#3c3c3c"
BUTTON_BG_COLOR = "#4b4b4b"
BUTTON_ACTIVE_BG = "#5b5b5b"
TEXT_BG_COLOR = "#1e1e1e"
DEBUG_BG_COLOR = "#1a1a2e"
DEBUG_FG_COLOR = "#a8d8a8"
STATUS_CONNECTED = "#4CAF50"
STATUS_NOT_CONNECTED = "#ff6b6b"
STATUS_KEY_EXCHANGE = "#FF9800"
SYSTEM_MSG_COLOR = "#ce9178"
ERROR_MSG_COLOR = "#f44747"
TIME_COLOR = "#888888"


def _hex_preview(data: bytes, n: int = 16) -> str:
    """Return first *n* bytes of *data* as a hex string with ellipsis."""
    if not data:
        return "<empty>"
    preview = data[:n].hex()
    return f"{preview}…" if len(data) > n else preview


# ---------------------------------------------------------------------------
# DebugGUI
# ---------------------------------------------------------------------------

class DebugGUI(UIBase):
    """Debug UI: chat panel on the left, live debug panel on the right."""
    
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Secure Chat — Debug GUI")
        self.root.geometry("1400x700")
        self.root.configure(bg=BG_COLOR)
        
        self.client: ClientBase | None = None
        self.peer_nickname: str = "Peer"
        self.message_counter: int = 0
        self.sent_messages: dict[int, str] = {}
        
        # Debug panel state
        self._debug_timer_id: str | None = None
        self._debug_update_interval_ms: int = 1000
        
        # Message log buffer: list of (timestamp, direction, kind, content)
        self._message_log: list[tuple[str, str, str, str]] = []
        # Raw bytes log: list of (timestamp, direction, context, hex_data, decrypted_text|None)
        self._raw_bytes_log: list[tuple[str, str, str, str, str | None]] = []
        
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        self._schedule_debug_update()
    
    # ------------------------------------------------------------------
    # Public wiring
    # ------------------------------------------------------------------
    
    def set_client(self, client: ClientBase) -> None:
        self.client = client
    
    # ------------------------------------------------------------------
    # UICapability
    # ------------------------------------------------------------------
    
    @property
    def capabilities(self) -> UICapability:
        return (
                UICapability.FILE_TRANSFER
                | UICapability.EPHEMERAL_MODE
                | UICapability.DELIVERY_STATUS
                | UICapability.NICKNAMES
        )
    
    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    
    def _build_ui(self) -> None:
        # Top bar: connection controls
        top_bar = tk.Frame(self.root, bg=BG_COLOR)
        top_bar.pack(fill=ltk.X, padx=10, pady=(8, 0))
        self._build_conn_bar(top_bar)
        
        # Body: chat (left) + debug (right)
        body = tk.Frame(self.root, bg=BG_COLOR)
        body.pack(fill=ltk.BOTH, expand=True, padx=10, pady=8)
        
        self._build_chat_panel(body)
        self._build_debug_panel(body)
    
    def _build_conn_bar(self, parent: tk.Frame) -> None:
        tk.Label(parent, text="Host:", bg=BG_COLOR, fg=FG_COLOR).pack(side=ltk.LEFT)
        self.host_entry = tk.Entry(parent, width=15, bg=ENTRY_BG_COLOR, fg=FG_COLOR,
                                   insertbackground=FG_COLOR, relief=ltk.FLAT)
        self.host_entry.insert(0, "localhost")
        self.host_entry.pack(side=ltk.LEFT, padx=(4, 10))
        
        tk.Label(parent, text="Port:", bg=BG_COLOR, fg=FG_COLOR).pack(side=ltk.LEFT)
        self.port_entry = tk.Entry(parent, width=7, bg=ENTRY_BG_COLOR, fg=FG_COLOR,
                                   insertbackground=FG_COLOR, relief=ltk.FLAT)
        self.port_entry.insert(0, "16384")
        self.port_entry.pack(side=ltk.LEFT, padx=(4, 10))
        
        self.connect_btn = tk.Button(parent, text="Connect", command=self._toggle_connection,
                                     bg=BUTTON_BG_COLOR, fg=FG_COLOR, relief=ltk.FLAT,
                                     activebackground=BUTTON_ACTIVE_BG, activeforeground=FG_COLOR)
        self.connect_btn.pack(side=ltk.LEFT, padx=(0, 6))
        
        self.status_label = tk.Label(parent, text="Not Connected", bg=BG_COLOR,
                                     fg=STATUS_NOT_CONNECTED, font=("Consolas", 9, "bold"))
        self.status_label.pack(side=ltk.RIGHT, padx=(10, 0))
    
    def _build_chat_panel(self, parent: tk.Frame) -> None:
        chat_frame = tk.Frame(parent, bg=BG_COLOR)
        chat_frame.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=True, padx=(0, 6))
        
        tk.Label(chat_frame, text="Chat", bg=BG_COLOR, fg=FG_COLOR,
                 font=("Consolas", 10, "bold")).pack(anchor=ltk.W)
        
        self.chat_display = scrolledtext.ScrolledText(
                chat_frame, state=ltk.DISABLED, wrap=ltk.WORD,
                font=("Consolas", 10), bg=TEXT_BG_COLOR, fg=FG_COLOR,
                relief=ltk.FLAT, height=28,
        )
        self.chat_display.pack(fill=ltk.BOTH, expand=True, pady=(4, 6))
        self.chat_display.tag_configure("time", foreground=TIME_COLOR)
        self.chat_display.tag_configure("system", foreground=SYSTEM_MSG_COLOR)
        self.chat_display.tag_configure("error", foreground=ERROR_MSG_COLOR)
        
        input_frame = tk.Frame(chat_frame, bg=BG_COLOR)
        input_frame.pack(fill=ltk.X)
        
        self.message_entry = tk.Entry(input_frame, bg=ENTRY_BG_COLOR, fg=FG_COLOR,
                                      insertbackground=FG_COLOR, relief=ltk.FLAT,
                                      font=("Consolas", 10))
        self.message_entry.pack(side=ltk.LEFT, fill=ltk.X, expand=True, padx=(0, 6))
        self.message_entry.bind("<Return>", self._send_message)
        
        tk.Button(input_frame, text="Send", command=self._send_message,
                  bg=BUTTON_BG_COLOR, fg=FG_COLOR, relief=ltk.FLAT,
                  activebackground=BUTTON_ACTIVE_BG, activeforeground=FG_COLOR,
                  ).pack(side=ltk.LEFT, padx=(0, 4))
        
        tk.Button(input_frame, text="📁", command=self._send_file,
                  bg=BUTTON_BG_COLOR, fg=FG_COLOR, relief=ltk.FLAT,
                  activebackground=BUTTON_ACTIVE_BG, activeforeground=FG_COLOR,
                  ).pack(side=ltk.LEFT)
    
    def _build_debug_panel(self, parent: tk.Frame) -> None:
        debug_outer = tk.Frame(parent, bg=BG_COLOR)
        debug_outer.pack(side=ltk.LEFT, fill=ltk.BOTH, expand=False)
        
        tk.Label(debug_outer, text="Debug Panel", bg=BG_COLOR, fg=FG_COLOR,
                 font=("Consolas", 10, "bold")).pack(anchor=ltk.W)
        
        # Live info display
        self.debug_display = scrolledtext.ScrolledText(
                debug_outer, state=ltk.DISABLED, wrap=ltk.WORD,
                font=("Consolas", 9), bg=DEBUG_BG_COLOR, fg=DEBUG_FG_COLOR,
                relief=ltk.FLAT, width=52, height=22,
        )
        self.debug_display.pack(fill=ltk.BOTH, expand=True, pady=(4, 6))
        
        # Action buttons
        btn_frame = tk.Frame(debug_outer, bg=BG_COLOR)
        btn_frame.pack(fill=ltk.X)
        
        actions = [
            ("Refresh Debug Info", self._update_debug_info),
            ("View Key Fingerprint", self._view_fingerprint),
            ("Initiate Rekey", self._initiate_rekey),
            ("Force Disconnect", self._force_disconnect),
            ("Emergency Close", self._emergency_close),
            ("Send Malformed Msg", self._send_malformed),
            ("View Raw Crypto", self._view_raw_crypto),
            ("Export Debug Log", self._export_debug_log),
        ]
        
        for label, cmd in actions:
            tk.Button(btn_frame, text=label, command=cmd,
                      bg=BUTTON_BG_COLOR, fg=FG_COLOR, relief=ltk.FLAT,
                      activebackground=BUTTON_ACTIVE_BG, activeforeground=FG_COLOR,
                      anchor=ltk.W, width=22,
                      ).pack(fill=ltk.X, pady=1)
    
    # ------------------------------------------------------------------
    # UIBase — required display methods
    # ------------------------------------------------------------------
    
    def display_regular_message(self, message: str, nickname: str | None = None) -> None:
        nick = nickname or self.peer_nickname
        self._log_message("RECV", "TEXT", f"{nick}: {message}")
        self._on_tk(self._append_chat, f"{nick}: {message}")
    
    def display_error_message(self, message: str) -> None:
        self._log_message("RECV", "ERROR", message)
        self._on_tk(self._append_chat, f"ERROR: {message}", tag="error")
    
    def display_system_message(self, message: str) -> None:
        self._log_message("SYS", "SYSTEM", message)
        self._on_tk(self._append_chat, f"SYSTEM: {message}", tag="system")
    
    def display_raw_message(self, message: str) -> None:
        self._log_message("RECV", "RAW", message)
        self._on_tk(self._append_chat, message)
    
    # ------------------------------------------------------------------
    # UIBase — required prompts
    # ------------------------------------------------------------------
    
    def prompt_key_verification(self, fingerprint: str) -> bool:
        return messagebox.askyesno(
                "Verify Fingerprint",
                f"Does this fingerprint match the peer's?\n\n{fingerprint}",
        )
    
    def prompt_file_transfer(
            self,
            filename: str,
            file_size: int,
            total_chunks: int,
            compressed_file_size: int | None = None,
    ) -> Path | bool | None:
        msg = f"Incoming file: {filename}\nSize: {file_size} bytes\nAccept?"
        if messagebox.askyesno("File Transfer", msg):
            save_path = filedialog.asksaveasfilename(initialfile=filename)
            return Path(save_path) if save_path else True
        return False
    
    def prompt_rekey(self) -> bool | None:
        msg = ("Peer requested a rekey.\n\n"
               "Yes → proceed\nNo → disconnect\nCancel → reject but stay connected")
        res = messagebox.askyesnocancel("Rekey Request", msg)
        if res is True:
            return True
        if res is False:
            return False
        return None
    
    # ------------------------------------------------------------------
    # UIBase — connection lifecycle
    # ------------------------------------------------------------------
    
    def on_connected(self) -> None:
        self._on_tk(self._set_status, "Connected", STATUS_CONNECTED)
        self._on_tk(self.connect_btn.config, text="Disconnect")
    
    def on_graceful_disconnect(self, reason: str) -> None:
        self._on_tk(self._set_status, "Disconnected", STATUS_NOT_CONNECTED)
        self._on_tk(self.connect_btn.config, text="Connect")
        self._on_tk(self._append_chat, f"Disconnected: {reason}", tag="system")
    
    def on_unexpected_disconnect(self, reason: str) -> None:
        self._on_tk(self._set_status, "Disconnected (Error)", STATUS_NOT_CONNECTED)
        self._on_tk(self.connect_btn.config, text="Connect")
        self._on_tk(messagebox.showerror, "Disconnected", f"Unexpected disconnect: {reason}")
    
    # ------------------------------------------------------------------
    # UIBase — optional event hooks
    # ------------------------------------------------------------------
    
    def on_key_exchange_started(self) -> None:
        self._on_tk(self._set_status, "Key Exchange…", STATUS_KEY_EXCHANGE)
    
    def on_key_exchange_complete(self) -> None:
        self._on_tk(self._set_status, "Encrypted", STATUS_CONNECTED)
        self._on_tk(self._append_chat, "Key exchange complete.", tag="system")
    
    def on_rekey_complete(self) -> None:
        self._on_tk(self._append_chat, "Rekey complete.", tag="system")
    
    def on_nickname_change(self, new_nickname: str) -> None:
        old = self.peer_nickname
        self.peer_nickname = new_nickname
        self._on_tk(self._append_chat, f"Peer renamed: {old} → {new_nickname}", tag="system")
    
    def on_delivery_confirmation(self, message_counter: int) -> None:
        self._on_tk(self._mark_delivered, message_counter)
    
    def on_ephemeral_mode_change(self, mode: str, owner_id: str | None) -> None:
        self._on_tk(self._append_chat, f"Ephemeral mode → {mode}", tag="system")
    
    def on_emergency_close(self) -> None:
        self._on_tk(self._append_chat, "EMERGENCY CLOSE received from peer.", tag="error")
    
    def file_download_progress(self, transfer_id: str, filename: str,
                               received_chunks: int, total_chunks: int,
                               bytes_transferred: int = -1,
                               ) -> None:
        pct = (received_chunks / total_chunks * 100) if total_chunks else 0
        self._on_tk(self._append_chat,
                    f"[DL] {filename}: {pct:.1f}% ({received_chunks}/{total_chunks})",
                    tag="system")
    
    def file_upload_progress(self, transfer_id: str, filename: str,
                             sent_chunks: int, total_chunks: int,
                             bytes_transferred: int = -1,
                             ) -> None:
        pct = (sent_chunks / total_chunks * 100) if total_chunks else 0
        self._on_tk(self._append_chat,
                    f"[UL] {filename}: {pct:.1f}% ({sent_chunks}/{total_chunks})",
                    tag="system")
    
    def on_file_transfer_complete(self, transfer_id: str, output_path: str) -> None:
        self._on_tk(self._append_chat, f"File transfer complete: {output_path}", tag="system")
    
    # ------------------------------------------------------------------
    # Internal helpers — chat
    # ------------------------------------------------------------------
    
    def _on_tk(self, func, /, *args: Any, **kwargs: Any) -> None:
        self.root.after(0, lambda: func(*args, **kwargs))  # type: ignore[arg-type]
    
    def _append_chat(self, text: str, tag: str = "") -> None:
        self.chat_display.config(state=ltk.NORMAL)
        ts = time.strftime("[%H:%M:%S] ")
        self.chat_display.insert(tk.END, ts, "time")
        self.chat_display.insert(tk.END, f"{text}\n", tag or "")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=ltk.DISABLED)
    
    def _set_status(self, text: str, color: str = FG_COLOR) -> None:
        self.status_label.config(text=text, fg=color)
    
    def _mark_delivered(self, counter: int) -> None:
        tag = self.sent_messages.get(counter)
        if not tag:
            return
        self.chat_display.config(state=ltk.NORMAL)
        ranges = self.chat_display.tag_ranges(tag)
        if ranges:
            self.chat_display.delete(ranges[0], ranges[1])
            self.chat_display.insert(ranges[0], "●", tag)
            self.chat_display.tag_configure(tag, foreground=STATUS_CONNECTED)
        self.chat_display.config(state=ltk.DISABLED)
    
    # ------------------------------------------------------------------
    # Internal helpers — connection / messaging
    # ------------------------------------------------------------------
    
    def _toggle_connection(self) -> None:
        if not self.client:
            return
        if self.client.connected:
            threading.Thread(target=self.client.disconnect, daemon=True).start()
        else:
            host = self.host_entry.get().strip()
            try:
                port = int(self.port_entry.get().strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid port number")
                return
            threading.Thread(target=self.client.connect, args=(host, port), daemon=True).start()
    
    def _send_message(self, event: tk.Event | None = None) -> str:
        text = self.message_entry.get().strip()
        if not text or not self.client:
            return "break"
        
        if text.startswith("/"):
            self._handle_command(text)
        else:
            counter = self.client.next_message_counter
            tag_id = f"sent_{counter}"
            
            self.chat_display.config(state=ltk.NORMAL)
            ts = time.strftime("[%H:%M:%S] ")
            nick = self.client.own_nickname if self.client else "Me"
            self.chat_display.insert(tk.END, ts, "time")
            self.chat_display.insert(tk.END, f"{nick}: {text} ", tag_id)
            self.chat_display.insert(tk.END, "○\n", f"status_{counter}")
            self.chat_display.tag_configure(f"status_{counter}", foreground=TIME_COLOR)
            self.chat_display.see(tk.END)
            self.chat_display.config(state=ltk.DISABLED)
            
            self.sent_messages[counter] = f"status_{counter}"
            self._log_message("SENT", "TEXT", f"{nick}: {text}")
            threading.Thread(target=self.client.send_message, args=(text,), daemon=True).start()
        
        self.message_entry.delete(0, tk.END)
        return "break"
    
    def _handle_command(self, text: str) -> None:
        if not self.client:
            return
        parts = text.split()
        cmd = parts[0].lower()
        if cmd in ("/nick", "/nickname") and len(parts) > 1:
            self.client.own_nickname = parts[1]
            self._append_chat(f"Nickname set to: {parts[1]}", tag="system")
        elif cmd == "/rekey":
            self.client.initiate_rekey()
        elif cmd == "/emergency":
            self.client.emergency_close()
        else:
            self._append_chat(f"Unknown command: {cmd}", tag="error")
    
    def _send_file(self) -> None:
        if not self.client:
            return
        path = filedialog.askopenfilename()
        if path:
            threading.Thread(target=self.client.send_file, args=(Path(path),), daemon=True).start()
    
    # ------------------------------------------------------------------
    # Debug panel — periodic update
    # ------------------------------------------------------------------
    
    def _schedule_debug_update(self) -> None:
        self._debug_timer_id = self.root.after(  # type: ignore[assignment]
                self._debug_update_interval_ms, self._periodic_debug_update,
        )
    
    def _periodic_debug_update(self) -> None:
        try:
            self._update_debug_info()
        except Exception:
            pass
        finally:
            self._schedule_debug_update()
    
    def _update_debug_info(self) -> None:
        lines: list[str] = []
        ts = time.strftime("%H:%M:%S")
        lines.append(f"=== DEBUG INFO  {ts} ===\n")
        
        c = self.client
        
        # -- Connection status --
        lines.append("CONNECTION:")
        if c is None:
            lines.append("  No client attached\n")
        else:
            lines.append(f"  Connected:          {'Yes' if c.connected else 'No'}")
            lines.append(f"  Key exchange done:  {'Yes' if c.key_exchange_complete else 'No'}")
            lines.append(f"  Verification done:  {'Yes' if c.verification_complete else 'No'}")
            lines.append(f"  Peer key verified:  {'Yes' if c.peer_key_verified else 'No'}")
            lines.append(f"  Voice call active:  {'Yes' if c.voice_call_active else 'No'}")
            lines.append(f"  File xfer active:   {'Yes' if c.file_transfer_active else 'No'}")
            lines.append("")
            
            # -- Server info (best-effort) --
            srv_ver = getattr(c, "server_protocol_version", None)
            srv_id = getattr(c, "server_identifier", None)
            if srv_ver or srv_id:
                lines.append("SERVER:")
                if srv_ver:
                    lines.append(f"  Protocol version:   {srv_ver}")
                if srv_id:
                    lines.append(f"  Identifier:         {srv_id}")
                lines.append("")
            
            # -- Nickname --
            lines.append("IDENTITY:")
            lines.append(f"  Own nickname:       {c.own_nickname}")
            lines.append(f"  Peer nickname:      {self.peer_nickname}")
            lines.append("")
            
            # -- Crypto (via _protocol if available) --
            proto = getattr(c, "_protocol", None)
            if proto is not None:
                lines.append("CRYPTO (internal):")
                send_ck = getattr(proto, "send_chain_key", b"")
                recv_ck = getattr(proto, "receive_chain_key", b"")
                msg_ctr = getattr(proto, "message_counter", "?")
                peer_ctr = getattr(proto, "peer_counter", "?")
                vk = getattr(proto, "verification_key", b"")
                own_pub = getattr(proto, "mlkem_public_key", b"")
                peer_pub = getattr(proto, "peer_mlkem_public_key", b"")
                dh_pub = getattr(proto, "dh_public_key_bytes", b"")
                peer_dh = getattr(proto, "peer_dh_public_key_bytes", b"")
                rekey_ip = getattr(proto, "rekey_in_progress", False)
                msgs_since = getattr(proto, "messages_since_last_rekey", "?")
                rekey_iv = getattr(proto, "rekey_interval", "?")
                
                lines.append(f"  Send chain key:     {_hex_preview(send_ck)}")
                lines.append(f"  Recv chain key:     {_hex_preview(recv_ck)}")
                lines.append(f"  Msg counter (out):  {msg_ctr}")
                lines.append(f"  Peer counter (in):  {peer_ctr}")
                lines.append(f"  Verification key:   {_hex_preview(vk)}")
                lines.append(f"  Own ML-KEM pub:     {_hex_preview(own_pub)}")
                lines.append(f"  Peer ML-KEM pub:    {_hex_preview(peer_pub)}")
                lines.append(f"  Own DH pub:         {_hex_preview(dh_pub)}")
                lines.append(f"  Peer DH pub:        {_hex_preview(peer_dh)}")
                lines.append(f"  Rekey in progress:  {'Yes' if rekey_ip else 'No'}")
                lines.append(f"  Msgs since rekey:   {msgs_since} / {rekey_iv}")
                lines.append("")
            
            # -- Deaddrop --
            dd_active = False
            try:
                dd_active = c.deaddrop_session_active()
            except Exception:
                pass
            lines.append("DEADDROP:")
            lines.append(f"  Session active:     {'Yes' if dd_active else 'No'}")
            dd_sup = getattr(c, "deaddrop_supported", None)
            if dd_sup is not None:
                lines.append(f"  Supported by srv:   {'Yes' if dd_sup else 'No'}")
            dd_max = getattr(c, "deaddrop_max_size", None)
            if dd_max:
                lines.append(f"  Max size:           {dd_max} bytes")
            lines.append("")
        
        self._write_debug(lines)
    
    def _write_debug(self, lines: list[str]) -> None:
        self.debug_display.config(state=ltk.NORMAL)
        self.debug_display.delete("1.0", tk.END)
        self.debug_display.insert(tk.END, "\n".join(lines))
        self.debug_display.config(state=ltk.DISABLED)
    
    # ------------------------------------------------------------------
    # Debug action buttons
    # ------------------------------------------------------------------
    
    def _view_fingerprint(self) -> None:
        if not self.client:
            messagebox.showinfo("Fingerprint", "No client connected.")
            return
        fp = self.client.own_key_fingerprint
        messagebox.showinfo("Own Key Fingerprint", fp)
    
    def _initiate_rekey(self) -> None:
        if not self.client:
            return
        try:
            self.client.initiate_rekey()
            self._append_chat("Rekey initiated.", tag="system")
        except Exception as exc:
            messagebox.showerror("Rekey Error", str(exc))
    
    def _force_disconnect(self) -> None:
        if not self.client:
            return
        threading.Thread(target=self.client.disconnect, daemon=True).start()
        self._append_chat("Force disconnect requested.", tag="system")
    
    def _emergency_close(self) -> None:
        if not self.client:
            return
        self.client.emergency_close()
        self._append_chat("Emergency close triggered.", tag="error")
    
    def _send_malformed(self) -> None:
        """Attempt to send a raw malformed/garbage message via the socket."""
        if not self.client:
            messagebox.showinfo("Malformed", "No client connected.")
            return
        sock = getattr(self.client, "socket", None)
        if sock is None:
            messagebox.showinfo("Malformed", "No socket available.")
            return
        try:
            garbage = os.urandom(64)
            sock.sendall(garbage)
            self._append_chat(f"Sent 64 bytes of garbage: {garbage[:16].hex()}…", tag="error")
        except Exception as exc:
            messagebox.showerror("Send Error", str(exc))
    
    def _view_raw_crypto(self) -> None:
        """Open a window showing full raw crypto state from _protocol."""
        if not self.client:
            messagebox.showinfo("Raw Crypto", "No client connected.")
            return
        proto = getattr(self.client, "_protocol", None)
        if proto is None:
            messagebox.showinfo("Raw Crypto", "Client has no _protocol attribute.")
            return
        
        win = tk.Toplevel(self.root)
        win.title("Raw Crypto State")
        win.configure(bg=BG_COLOR)
        win.geometry("700x500")
        
        txt = scrolledtext.ScrolledText(win, font=("Consolas", 9),
                                        bg=DEBUG_BG_COLOR, fg=DEBUG_FG_COLOR,
                                        relief=ltk.FLAT)
        txt.pack(fill=ltk.BOTH, expand=True, padx=8, pady=8)
        
        def _write_section(title: str, attrs: list[str], obj: object = proto) -> None:
            txt.insert(tk.END, f"\n{'─' * 50}\n{title}\n{'─' * 50}\n")
            for attr in attrs:
                val = getattr(obj, attr, "<not found>")
                if isinstance(val, bytes):
                    display = val.hex() if val else "<empty>"
                elif isinstance(val, bool):
                    display = str(val)
                else:
                    display = str(val)
                txt.insert(tk.END, f"  {attr:<35} {display}\n")

        _write_section("Chain Keys & Counters", [
            "send_chain_key", "receive_chain_key",
            "message_counter", "peer_counter",
        ])
        _write_section("Public Keys", [
            "mlkem_public_key", "peer_mlkem_public_key",
            "hqc_public_key", "peer_hqc_public_key",
            "dh_public_key_bytes", "peer_dh_public_key_bytes",
        ])
        _write_section("Session Keys", [
            "verification_key", "shared_key",
        ])
        _write_section("Rekey State", [
            "_rekey_in_progress",
            "messages_since_last_rekey", "rekey_interval",
            "pending_message_counter", "pending_peer_counter",
            "_rke_dh_pub_bytes",
        ], obj=proto._rekey)
        
        txt.config(state=ltk.DISABLED)
    
    # ------------------------------------------------------------------
    # Internal helpers — message log
    # ------------------------------------------------------------------
    
    def _log_message(self, direction: str, kind: str, content: str) -> None:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self._message_log.append((ts, direction, kind, content))
    
    def log_raw_bytes(self, direction: str, context: str, data: bytes, decrypted_text: str | None = None) -> None:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self._raw_bytes_log.append((ts, direction, context, data.hex(), decrypted_text))
    
    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    
    def _export_debug_log(self) -> None:
        """Export message log, debug summary, and full crypto state to a timestamped file."""
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"debug_export_{ts_file}.txt"
        path = Path(filename)
        
        lines: list[str] = []
        header_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{'=' * 70}")
        lines.append(f"SECURE CHAT DEBUG EXPORT")
        lines.append(f"Generated: {header_ts}")
        lines.append(f"{'=' * 70}")
        lines.append("")
        
        # ── Section 1: Message log ──────────────────────────────────────
        lines.append(f"{'─' * 70}")
        lines.append("SECTION 1: MESSAGE LOG")
        lines.append(f"{'─' * 70}")
        if self._message_log:
            for (entry_ts, direction, kind, content) in self._message_log:
                lines.append(f"[{entry_ts}] [{direction:<4}] [{kind:<6}] {content}")
        else:
            lines.append("  (no messages recorded)")
        lines.append("")
        
        # ── Section 1b: Raw bytes log ───────────────────────────────────
        lines.append(f"{'─' * 70}")
        lines.append("SECTION 1b: RAW BYTES LOG (dropped / failed messages)")
        lines.append(f"{'─' * 70}")
        if self._raw_bytes_log:
            for (entry_ts, direction, context, hex_data, decrypted_text) in self._raw_bytes_log:
                lines.append(f"[{entry_ts}] [{direction:<4}] [{context}]")
                lines.append(f"  hex: {hex_data}")
                if decrypted_text is not None:
                    lines.append(f"  decrypted: {decrypted_text}")
        else:
            lines.append("  (no raw bytes recorded)")
        lines.append("")
        
        # ── Section 2: Debug summary ────────────────────────────────────
        lines.append(f"{'─' * 70}")
        lines.append("SECTION 2: DEBUG SUMMARY (snapshot at export time)")
        lines.append(f"{'─' * 70}")
        summary_lines: list[str] = []
        ts_now = time.strftime("%H:%M:%S")
        summary_lines.append(f"=== DEBUG INFO  {ts_now} ===")
        c = self.client
        if c is None:
            summary_lines.append("  No client attached")
        else:
            summary_lines.append(f"  Connected:          {'Yes' if c.connected else 'No'}")
            summary_lines.append(f"  Key exchange done:  {'Yes' if c.key_exchange_complete else 'No'}")
            summary_lines.append(f"  Verification done:  {'Yes' if c.verification_complete else 'No'}")
            summary_lines.append(f"  Peer key verified:  {'Yes' if c.peer_key_verified else 'No'}")
            summary_lines.append(f"  Own nickname:       {c.own_nickname}")
            summary_lines.append(f"  Peer nickname:      {self.peer_nickname}")
            srv_ver = getattr(c, "server_protocol_version", None)
            srv_id = getattr(c, "server_identifier", None)
            if srv_ver:
                summary_lines.append(f"  Server version:     {srv_ver}")
            if srv_id:
                summary_lines.append(f"  Server identifier:  {srv_id}")
            proto = getattr(c, "_protocol", None)
            if proto is not None:
                summary_lines.append(f"  Send chain key:     {_hex_preview(getattr(proto, 'send_chain_key', b''))}")
                summary_lines.append(f"  Recv chain key:     {_hex_preview(getattr(proto, 'receive_chain_key', b''))}")
                summary_lines.append(f"  Msg counter (out):  {getattr(proto, 'message_counter', '?')}")
                summary_lines.append(f"  Peer counter (in):  {getattr(proto, 'peer_counter', '?')}")
                summary_lines.append(f"  Rekey in progress:  {'Yes' if getattr(proto, 'rekey_in_progress', False) else 'No'}")
                summary_lines.append(f"  Msgs since rekey:   {getattr(proto, 'messages_since_last_rekey', '?')} / {getattr(proto, 'rekey_interval', '?')}")
        lines.extend(summary_lines)
        lines.append("")
        
        # ── Section 3: Full raw crypto state ────────────────────────────
        lines.append(f"{'─' * 70}")
        lines.append("SECTION 3: FULL RAW CRYPTO STATE")
        lines.append(f"{'─' * 70}")
        if self.client is None:
            lines.append("  No client attached")
        else:
            proto = getattr(self.client, "_protocol", None)
            if proto is None:
                lines.append("  Client has no _protocol attribute")
            else:
                def _section(title: str, attrs: list[str], obj: object = proto) -> None:
                    lines.append(f"\n  [{title}]")
                    for attr in attrs:
                        val = getattr(obj, attr, "<not found>")
                        if isinstance(val, bytes):
                            display = val.hex() if val else "<empty>"
                        else:
                            display = str(val)
                        lines.append(f"    {attr:<35} {display}")

                _section("Chain Keys & Counters", [
                    "send_chain_key", "receive_chain_key",
                    "message_counter", "peer_counter",
                ])
                _section("Public Keys", [
                    "mlkem_public_key", "peer_mlkem_public_key",
                    "hqc_public_key", "peer_hqc_public_key",
                    "dh_public_key_bytes", "peer_dh_public_key_bytes",
                ])
                _section("Session Keys", [
                    "verification_key", "shared_key",
                ])
                _section("Rekey State", [
                    "_rekey_in_progress",
                    "messages_since_last_rekey", "rekey_interval",
                    "pending_message_counter", "pending_peer_counter",
                    "_rke_dh_pub_bytes",
                ], obj=proto._rekey)
        lines.append("")
        lines.append(f"{'=' * 70}")
        lines.append("END OF EXPORT")
        lines.append(f"{'=' * 70}")
        
        try:
            path.write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo("Export Successful", f"Debug log exported to:\n{path.resolve()}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))
    
    # ------------------------------------------------------------------
    # Window close
    # ------------------------------------------------------------------
    
    def _on_closing(self) -> None:
        if self.client:
            try:
                self.client.disconnect()
            except Exception:
                pass
        self.root.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(client_class: type[ClientBase]) -> None:
    root = tk.Tk()
    ui = DebugGUI(root)
    client = DebugClient(ui)
    ui.set_client(client)
    root.mainloop()
