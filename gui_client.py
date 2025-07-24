#!/usr/bin/env python3
"""
Simple GUI wrapper for the SecureChatClient.
Provides a basic chat interface with text area and input box.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import threading
import sys
import io
from contextlib import redirect_stdout, redirect_stderr
from client import SecureChatClient


class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")
        
        # Chat client instance
        self.client = None
        self.connected = False
        
        # Create GUI elements
        self.create_widgets()
        
        # Redirect stdout to capture print statements
        self.setup_output_redirection()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        """Create the GUI widgets."""
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection frame
        conn_frame = tk.Frame(main_frame)
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Host and port inputs
        tk.Label(conn_frame, text="Host:").pack(side=tk.LEFT)
        self.host_entry = tk.Entry(conn_frame, width=15)
        self.host_entry.pack(side=tk.LEFT, padx=(5, 10))
        self.host_entry.insert(0, "localhost")
        
        tk.Label(conn_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(conn_frame, width=8)
        self.port_entry.pack(side=tk.LEFT, padx=(5, 10))
        self.port_entry.insert(0, "16384")
        
        # Connect/Disconnect button
        self.connect_btn = tk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(
            main_frame, 
            state=tk.DISABLED, 
            wrap=tk.WORD,
            height=20,
            font=("Consolas", 10)
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Input frame
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X)
        
        # Message input
        self.message_entry = tk.Entry(input_frame, font=("Consolas", 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        
        # Send button
        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)
        
        # Initially disable input until connected
        self.message_entry.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
    
    def setup_output_redirection(self):
        """Setup output redirection to capture print statements."""
        self.output_buffer = io.StringIO()
        
    def append_to_chat(self, text):
        """Append text to the chat display."""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
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
            
            self.append_to_chat(f"Connecting to {host}:{port}...")
            
            # Create client instance
            self.client = SecureChatClient(host, port)
            
            # Start connection in a separate thread
            def connect_thread():
                try:
                    if self.client.connect():
                        self.connected = True
                        self.root.after(0, self.on_connected)
                        self.start_chat_monitoring()
                    else:
                        self.root.after(0, lambda: self.append_to_chat("Failed to connect to server"))
                except Exception as e:
                    self.root.after(0, lambda: self.append_to_chat(f"Connection error: {e}"))
            
            threading.Thread(target=connect_thread, daemon=True).start()
            
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            self.append_to_chat(f"Connection error: {e}")
    
    def on_connected(self):
        """Called when successfully connected."""
        self.connected = True
        self.connect_btn.config(text="Disconnect")
        self.host_entry.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.DISABLED)
        self.message_entry.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL)
        self.message_entry.focus()
        self.append_to_chat("Connected! Performing key exchange...")
    
    def disconnect_from_server(self):
        """Disconnect from the server."""
        if self.client:
            self.client.disconnect()
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.append_to_chat("Disconnected from server.")
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
                        
                        # Show verification dialog
                        self.root.after(0, self.show_verification_dialog)
                    
                    import time
                    time.sleep(0.1)
                    
            except Exception as e:
                self.root.after(0, lambda: self.append_to_chat(f"Monitor error: {e}"))
        
        threading.Thread(target=monitor_thread, daemon=True).start()
    
    def show_verification_dialog(self):
        """Show the key verification dialog."""
        if not self.client or not hasattr(self.client, 'protocol'):
            return
            
        try:
            fingerprint = self.client.protocol.get_own_key_fingerprint()
            
            dialog_text = f"""Key Exchange Complete!

Session fingerprint:
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
                self.append_to_chat("✓ You verified the peer's key.")
            else:
                self.append_to_chat("✗ You did not verify the peer's key.")
                
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
                # Display the sent message
                if hasattr(self.client, 'protocol') and self.client.protocol.is_peer_key_verified():
                    self.append_to_chat(f"You: {message}")
                else:
                    self.append_to_chat(f"You (unverified): {message}")
            else:
                self.append_to_chat("Failed to send message")
                
        except Exception as e:
            self.append_to_chat(f"Send error: {e}")
            
        self.message_entry.delete(0, tk.END)
    
    def on_key_press(self, event):
        """Handle key press events in message entry."""
        # Allow normal typing when connected
        pass
    
    def on_closing(self):
        """Handle window closing."""
        if self.connected:
            self.disconnect_from_server()
        self.root.destroy()


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
                self.gui.root.after(0, lambda: self.gui.append_to_chat(f"Other user: {decrypted_text}"))
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
                shared_secret = self.protocol.process_key_exchange_response(message_data, self.private_key)
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.append_to_chat("Key exchange completed successfully."))
                else:
                    print("Key exchange completed successfully.")
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
        # The GUI monitoring thread will detect key_exchange_complete and show the dialog
    
    def start_key_verification(self):
        """Start the key verification process - override to prevent blocking."""
        # This method is overridden to prevent the base class from blocking
        # the receive thread with console input. The GUI handles verification
        # through the monitoring thread and verification dialog.
        pass


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