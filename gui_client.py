import tkinter as tk # type: ignore
from tkinter import scrolledtext, messagebox, filedialog # type: ignore
import threading
import sys
import io
import os
from client import SecureChatClient

from shared import bytes_to_human_readable


class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")

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
            bg="#1e1e1e",
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
            input_frame, text="⏱️ Ephemeral", command=self.toggle_ephemeral_mode,
            bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, relief=tk.FLAT, # type: ignore
            activebackground=self.BUTTON_ACTIVE_BG, activeforeground=self.FG_COLOR,
            font=("Consolas", 9)
        )
        self.ephemeral_btn.pack(side=tk.RIGHT, padx=(0, 15)) # type: ignore

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
        
        # Start ephemeral message cleanup thread
        self.start_ephemeral_cleanup()

    def setup_output_redirection(self):
        """Setup output redirection to capture print statements."""
        self.output_buffer = io.StringIO()

    def append_to_chat(self, text, is_message=False):
        """Append text to the chat display."""
        self.chat_display.config(state=tk.NORMAL) # type: ignore
        
        # If ephemeral mode is enabled and this is a message, track it
        if self.ephemeral_mode and is_message:
            self.message_counter += 1
            message_id = f"msg_{self.message_counter}"
            import time
            self.ephemeral_messages[message_id] = time.time()
            # Add invisible marker for tracking
            self.chat_display.insert(tk.END, f"{text} <!-- {message_id} -->\n")
        else:
            self.chat_display.insert(tk.END, text + "\n")
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED) # type: ignore

    def update_status(self, status_text, color="#ff6b6b"):
        """Update the status indicator with new text and color."""
        self.status_label.config(text=status_text, fg=color) # type: ignore

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
                    self.root.after(0, lambda: self.append_to_chat(f"Connection error: {e}"))
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
        self.host_entry.config(state=tk.DISABLED) # type: ignore
        self.port_entry.config(state=tk.DISABLED) # type: ignore
        self.message_entry.config(state=tk.NORMAL) # type: ignore
        self.send_btn.config(state=tk.NORMAL) # type: ignore
        self.send_file_btn.config(state=tk.NORMAL) # type: ignore
        self.ephemeral_btn.config(state=tk.NORMAL) # type: ignore
        self.message_entry.focus()
        self.update_status("Connected, waiting for other client", "#ffff00")  # Yellow for waiting

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
        self.append_to_chat("Disconnected from server.")
        self.update_status("Not Connected", "#ff6b6b")
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

                    import time
                    time.sleep(0.1)

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
            import time
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
            self.ephemeral_btn.config(bg="#ff6b6b", fg="#ffffff", text="⏱️ Ephemeral ON") # type: ignore
            self.append_to_chat("🔥 Ephemeral mode enabled - messages will disappear after 30 seconds", is_message=True)
        else:
            # Disable ephemeral mode
            self.ephemeral_btn.config(bg=self.BUTTON_BG_COLOR, fg=self.FG_COLOR, text="⏱️ Ephemeral") # type: ignore
            # Clear all ephemeral messages
            self.ephemeral_messages.clear()

    def remove_ephemeral_messages(self, message_ids):
        """Remove ephemeral messages from the chat display."""
        try:
            # Get all chat content
            self.chat_display.config(state=tk.NORMAL) # type: ignore
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
            self.chat_display.config(state=tk.DISABLED) # type: ignore
            
            # Remove from tracking dict
            for message_id in message_ids:
                self.ephemeral_messages.pop(message_id, None)
                
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
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}", is_message=True))
            else:
                print(f"\nOther user: {decrypted_text}")

        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Failed to decrypt message: {e}"))
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
                
                self.protocol.process_key_exchange_response(message_data, self.private_key)
            else:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat("Received key exchange response but no private key found"))
                else:
                    print("Received key exchange response but no private key found")

        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Key exchange response error: {e}"))
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
            self.gui.root.after(0, lambda: self.gui.update_status("Processing key exchange", "#ffa500"))
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
            import json
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
                self.gui.root.after(0, lambda: self.gui.update_status("Key exchange reset - waiting for new client", "#ff6b6b"))
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
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error handling key exchange reset: {e}"))
            else:
                print(f"Error handling key exchange reset: {e}")
    
    def handle_file_metadata(self, message_data: bytes):
        """Handle incoming file metadata with GUI dialog."""
        try:
            metadata = self.protocol.process_file_metadata(message_data)
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
                        from shared import send_message
                        accept_msg = self.protocol.create_file_accept_message(transfer_id)
                        send_message(self.socket, accept_msg)
                        self.gui.append_to_chat(f"File transfer accepted: {metadata['filename']}")
                    else:
                        # Send rejection
                        from shared import send_message
                        reject_msg = self.protocol.create_file_reject_message(transfer_id)
                        send_message(self.socket, reject_msg)
                        self.gui.append_to_chat("File transfer rejected.")
                        del self.active_file_metadata[transfer_id]
                
                self.gui.root.after(0, show_file_dialog)
            else:
                # Fallback to console behavior
                super().handle_file_metadata(message_data)
                
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error handling file metadata: {e}"))
            else:
                print(f"Error handling file metadata: {e}")
    
    def handle_file_accept(self, message_data: bytes):
        """Handle file acceptance from peer with GUI updates."""
        try:
            import json
            message = json.loads(message_data.decode('utf-8'))
            transfer_id = message["transfer_id"]
            
            if transfer_id not in self.pending_file_transfers:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat("Received acceptance for unknown file transfer"))
                return
            
            transfer_info = self.pending_file_transfers[transfer_id]
            filename = transfer_info["metadata"]["filename"]
            
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"File transfer accepted. Sending {filename}..."))
            
            # Start sending file chunks
            self._send_file_chunks(transfer_id, transfer_info["file_path"])
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error handling file acceptance: {e}"))
            else:
                print(f"Error handling file acceptance: {e}")
    
    def handle_file_reject(self, message_data: bytes):
        """Handle file rejection from peer with GUI updates."""
        try:
            import json
            message = json.loads(message_data.decode('utf-8'))
            transfer_id = message["transfer_id"]
            reason = message.get("reason", "Unknown reason")
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(f"File transfer rejected: {filename} - {reason}"))
                del self.pending_file_transfers[transfer_id]
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error handling file rejection: {e}"))
            else:
                print(f"Error handling file rejection: {e}")
    
    def handle_file_chunk(self, message_data: bytes):
        """Handle incoming file chunk with GUI progress updates."""
        try:
            chunk_info = self.protocol.process_file_chunk(message_data)
            transfer_id = chunk_info["transfer_id"]
            
            if transfer_id not in self.active_file_metadata:
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat("Received chunk for unknown file transfer"))
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
                received_chunks = len(self.protocol.received_chunks.get(transfer_id, {}))
                if received_chunks % 10 == 0: # Update every 100 chunks
                    progress = (received_chunks / metadata["total_chunks"]) * 100
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(
                        f"Receiving {metadata['filename']}: {progress:.1f}% ({received_chunks}/{metadata['total_chunks']} chunks)"
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
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(f"File received successfully: {output_path}"))
                    
                    # Send completion message
                    from shared import send_message
                    complete_msg = self.protocol.create_file_complete_message(transfer_id)
                    send_message(self.socket, complete_msg)
                    
                except Exception as e:
                    if self.gui:
                        self.gui.root.after(0, lambda: self.gui.append_to_chat(f"File reassembly failed: {e}"))
                
                # Clean up
                del self.active_file_metadata[transfer_id]
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error handling file chunk: {e}"))
            else:
                print(f"Error handling file chunk: {e}")
    
    def handle_file_complete(self, message_data: bytes):
        """Handle file transfer completion notification with GUI updates."""
        try:
            import json
            message = json.loads(message_data.decode('utf-8'))
            transfer_id = message["transfer_id"]
            
            if transfer_id in self.pending_file_transfers:
                filename = self.pending_file_transfers[transfer_id]["metadata"]["filename"]
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat(f"File transfer completed: {filename}"))
                del self.pending_file_transfers[transfer_id]
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error handling file completion: {e}"))
            else:
                print(f"Error handling file completion: {e}")
    
    def _send_file_chunks(self, transfer_id: str, file_path: str):
        """Send file chunks to peer with GUI progress updates."""
        try:
            chunks = self.protocol.chunk_file(file_path)
            total_chunks = len(chunks)
            
            for i, chunk in enumerate(chunks):
                chunk_msg = self.protocol.create_file_chunk_message(transfer_id, i, chunk)
                from shared import send_message
                send_message(self.socket, chunk_msg)
                
                # Show progress in GUI every 10 chunks
                if self.gui:
                    progress = ((i + 1) / total_chunks) * 100
                    if (i + 1) % 10 == 0:  # Update every 10 chunks
                        self.gui.root.after(0, lambda p=progress, curr=i+1, total=total_chunks:
                            self.gui.append_to_chat(f"Sending: {p:.1f}% ({curr}/{total} chunks)")
                        )
            
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat("File chunks sent successfully."))
            
        except Exception as e:
            if self.gui:
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Error sending file chunks: {e}"))
            else:
                print(f"Error sending file chunks: {e}")


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
                    gui.root.after(0, lambda: gui.append_to_chat(f"Connection error: {e}"))

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