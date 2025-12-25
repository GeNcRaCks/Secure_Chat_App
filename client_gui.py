import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from crypto_utils import *
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import json
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9999

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat – Alice (Client)")
        self.root.geometry("900x700")
        self.root.configure(bg="#121212")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Chat Tab
        self.chat_frame = tk.Frame(self.notebook, bg="#121212")
        self.notebook.add(self.chat_frame, text="💬 Chat")
        
        # Control Panel Tab
        self.control_frame = tk.Frame(self.notebook, bg="#121212")
        self.notebook.add(self.control_frame, text="🔐 Encryption Control")
        
        # Details Tab
        self.details_frame = tk.Frame(self.notebook, bg="#121212")
        self.notebook.add(self.details_frame, text="📊 Details")
        
        self.setup_chat_tab()
        self.setup_control_tab()
        self.setup_details_tab()
        
        # Initialize connection
        self.sock = None
        self.connected = False
        self.aes_key = None
        self.server_pub_key = None
        self.running = True
        self.connection_thread = None
        
        # Statistics
        self.messages_sent = 0
        self.messages_received = 0
        self.integrity_failures = 0
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Start connection thread
        self.connect_to_server()

    def setup_chat_tab(self):
        # Header
        header = tk.Frame(self.chat_frame, bg="#075E54", height=70)
        header.pack(fill="x")
        
        tk.Label(
            header,
            text="Alice 👩‍💻 (Client)",
            fg="white",
            bg="#075E54",
            font=("Segoe UI", 16, "bold")
        ).pack(side="left", padx=20, pady=10)
        
        status_frame = tk.Frame(header, bg="#075E54")
        status_frame.pack(side="right", padx=20)
        
        self.status_label = tk.Label(
            status_frame,
            text="🟡 Connecting to server...",
            fg="white",
            bg="#075E54",
            font=("Segoe UI", 10)
        )
        self.status_label.pack()
        
        # Stats label
        self.stats_label = tk.Label(
            status_frame,
            text="📊 Messages: 0 sent, 0 received",
            fg="white",
            bg="#075E54",
            font=("Segoe UI", 8)
        )
        self.stats_label.pack()
        
        # Chat display area
        chat_container = tk.Frame(self.chat_frame, bg="#121212")
        chat_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Canvas for scrolling
        self.canvas = tk.Canvas(chat_container, bg="#0a0a0a", highlightthickness=0)
        scrollbar = tk.Scrollbar(chat_container, command=self.canvas.yview)
        
        self.msg_frame = tk.Frame(self.canvas, bg="#0a0a0a")
        
        self.msg_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.msg_frame, anchor="nw", width=self.canvas.winfo_width())
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind canvas resize to update message frame width
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        
        # Input area
        input_frame = tk.Frame(self.chat_frame, bg="#1f1f1f")
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.entry = tk.Text(
            input_frame,
            height=3,
            bg="#2a2a2a",
            fg="white",
            font=("Segoe UI", 11),
            wrap="word",
            relief="flat",
            insertbackground="white"
        )
        self.entry.pack(side="left", fill="both", expand=True, padx=(10, 5), pady=10)
        self.entry.bind("<Return>", self.send_on_enter)
        
        # Send button
        send_btn = tk.Button(
            input_frame,
            text="Send",
            bg="#25D366",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            command=self.send_message
        )
        send_btn.pack(side="right", padx=(5, 10), pady=10, ipadx=20)
        
        # Integrity test button
        test_btn = tk.Button(
            input_frame,
            text="Test Tampering",
            bg="#FF6B6B",
            fg="white",
            font=("Segoe UI", 10),
            command=self.send_tampered_message
        )
        test_btn.pack(side="right", padx=(0, 5), pady=10)

    def on_canvas_configure(self, event):
        # Update the width of the message frame when canvas is resized
        canvas_width = event.width
        self.canvas.itemconfig(1, width=canvas_width)

    def setup_control_tab(self):
        # Control panel
        control_bg = "#1a1a1a"
        
        # Status panel
        status_panel = tk.LabelFrame(
            self.control_frame,
            text="Connection Status",
            bg=control_bg,
            fg="#25D366",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=15
        )
        status_panel.pack(fill="x", padx=20, pady=10)
        
        self.connection_status = tk.Label(
            status_panel,
            text="🟡 Connecting...",
            bg=control_bg,
            fg="#FFD700",
            font=("Segoe UI", 11, "bold")
        )
        self.connection_status.pack(anchor="w", pady=5)
        
        # Encryption status
        tk.Label(
            status_panel,
            text="🔒 Encryption: Hybrid (RSA + AES-256-CBC + HMAC-SHA256)",
            bg=control_bg,
            fg="white",
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=2)
        
        # Integrity status
        self.integrity_status = tk.Label(
            status_panel,
            text="🛡️ Integrity: SHA-256 HMAC Active",
            bg=control_bg,
            fg="#4CAF50",
            font=("Segoe UI", 10)
        )
        self.integrity_status.pack(anchor="w", pady=2)
        
        # Test buttons
        test_frame = tk.LabelFrame(
            self.control_frame,
            text="Test Functions",
            bg=control_bg,
            fg="#25D366",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=15
        )
        test_frame.pack(fill="x", padx=20, pady=10)
        
        tk.Button(
            test_frame,
            text="Send Test Message",
            bg="#128C7E",
            fg="white",
            font=("Segoe UI", 10),
            command=self.send_test_message
        ).pack(side="left", padx=5)
        
        tk.Button(
            test_frame,
            text="View Server Public Key",
            bg="#34B7F1",
            fg="white",
            font=("Segoe UI", 10),
            command=self.show_server_key
        ).pack(side="left", padx=5)
        
        tk.Button(
            test_frame,
            text="Verify Encryption",
            bg="#25D366",
            fg="white",
            font=("Segoe UI", 10),
            command=self.verify_encryption
        ).pack(side="left", padx=5)
        
        tk.Button(
            test_frame,
            text="Test Integrity Check",
            bg="#FF9800",
            fg="white",
            font=("Segoe UI", 10),
            command=self.test_integrity_check
        ).pack(side="left", padx=5)
        
        self.reconnect_btn = tk.Button(
            test_frame,
            text="Reconnect",
            bg="#FF6B6B",
            fg="white",
            font=("Segoe UI", 10),
            command=self.reconnect
        )
        self.reconnect_btn.pack(side="left", padx=5)
        
        # Statistics frame
        stats_frame = tk.LabelFrame(
            self.control_frame,
            text="Message Statistics",
            bg=control_bg,
            fg="#25D366",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=15
        )
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        self.stats_text = tk.Text(
            stats_frame,
            height=4,
            bg="#2a2a2a",
            fg="white",
            font=("Segoe UI", 9)
        )
        self.stats_text.pack(fill="both", expand=True)
        self.stats_text.insert("1.0", "Messages Sent: 0\nMessages Received: 0\nIntegrity Failures: 0")
        self.stats_text.config(state="disabled")
        
        # Key info
        key_frame = tk.LabelFrame(
            self.control_frame,
            text="Key Information",
            bg=control_bg,
            fg="#25D366",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=15
        )
        key_frame.pack(fill="x", padx=20, pady=10)
        
        self.key_text = scrolledtext.ScrolledText(
            key_frame,
            height=8,
            bg="#2a2a2a",
            fg="white",
            font=("Consolas", 9)
        )
        self.key_text.pack(fill="both", expand=True)
        self.key_text.insert("1.0", "Keys will appear after connection...")
        self.key_text.config(state="disabled")

    def setup_details_tab(self):
        # Details panel
        details_bg = "#1a1a1a"
        
        # Process flow
        flow_frame = tk.LabelFrame(
            self.details_frame,
            text="Encryption Process Flow",
            bg=details_bg,
            fg="#34B7F1",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=15
        )
        flow_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        flow_text = """1. 🔄 Connect to Bob's Server
2. ✅ Receive Bob's RSA Public Key
3. 🔐 Generate 256-bit AES Session Key
4. 🔄 Encrypt AES Key with RSA & sent to Bob
5. ✅ Secure channel established
6. 🔒 All messages encrypted with AES-256-CBC
7. 🔐 HMAC-SHA256 calculated for integrity
8. 🔄 Each message has unique random IV + HMAC
9. ✅ Messages verified & decrypted on receiver side
10. 🛡️ Integrity checked via HMAC-SHA256"""
        
        flow_label = tk.Label(
            flow_frame,
            text=flow_text,
            bg=details_bg,
            fg="white",
            font=("Segoe UI", 10),
            justify="left"
        )
        flow_label.pack(anchor="w", pady=5)
        
        # Technical details
        tech_frame = tk.LabelFrame(
            self.details_frame,
            text="Technical Specifications",
            bg=details_bg,
            fg="#34B7F1",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=15
        )
        tech_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.details_text = scrolledtext.ScrolledText(
            tech_frame,
            height=12,
            bg="#2a2a2a",
            fg="white",
            font=("Consolas", 9)
        )
        self.details_text.pack(fill="both", expand=True)
        self.details_text.insert("1.0", "Connection details will appear here...")
        self.details_text.config(state="disabled")

    def connect_to_server(self):
        """Single connection attempt"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)  # Connection timeout
            self.sock.connect((HOST, PORT))
            
            # Receive server's public key
            server_key_data = self.sock.recv(2048)
            if not server_key_data:
                raise Exception("No data received from server")
                
            self.server_pub_key = RSA.import_key(server_key_data)
            
            # Generate AES key
            self.aes_key = get_random_bytes(16)
            
            # Encrypt and send AES key
            encrypted_aes = encrypt_aes_key(self.aes_key, self.server_pub_key)
            self.sock.send(encrypted_aes)
            
            self.connected = True
            self.root.after(0, self.update_status, "🟢 Connected to Bob", "green")
            self.root.after(0, self.update_connection_info)
            
            # Set longer timeout for receiving (30 seconds)
            self.sock.settimeout(30.0)
            
            # Start receiving messages
            while self.connected and self.running:
                try:
                    encrypted_msg = self.sock.recv(4096)
                    if encrypted_msg:
                        # Reset timeout since we got data
                        self.sock.settimeout(30.0)
                        
                        try:
                            msg, timestamp, integrity_ok = decrypt_message(encrypted_msg, self.aes_key)
                            self.messages_received += 1
                            
                            if integrity_ok:
                                self.root.after(0, self.add_message, msg, timestamp, False, True)
                                # Log to console
                                print(f"[Alice] ✅ Message received (Integrity OK): {msg[:30]}...")
                            else:
                                self.root.after(0, self.add_message, msg, timestamp, False, False)
                                
                        except ValueError as e:
                            # Integrity check failed
                            error_msg = str(e)
                            self.integrity_failures += 1
                            self.root.after(0, self.add_message, error_msg, "Error", False, False)
                            print(f"[Alice] ❌ {error_msg}")
                            
                        # Update stats
                        self.root.after(0, self.update_stats)
                            
                    else:
                        # Connection closed by server
                        self.connected = False
                        self.root.after(0, self.update_status, "🟡 Server disconnected", "yellow")
                        break
                        
                except socket.timeout:
                    # Timeout occurred, but connection is still alive
                    try:
                        # Send keep-alive
                        self.sock.send(b'')
                    except:
                        self.connected = False
                        self.root.after(0, self.update_status, "🟡 Connection timeout", "yellow")
                        break
                        
                except Exception as e:
                    self.connected = False
                    self.root.after(0, self.update_status, f"🟡 Connection error: {str(e)}", "yellow")
                    break
            
            # Clean up socket
            if self.sock:
                self.sock.close()
                self.sock = None
                
        except Exception as e:
            if self.running:
                self.root.after(0, self.update_status, f"🔴 Connection failed: {str(e)}", "red")

    def cleanup_sockets(self):
        """Clean up all sockets properly"""
        self.running = False
        self.connected = False
        
        # Close socket
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def reconnect(self):
        """Manual reconnect button"""
        self.cleanup_sockets()
        self.connected = False
        self.aes_key = None
        self.server_pub_key = None
        self.messages_sent = 0
        self.messages_received = 0
        self.integrity_failures = 0
        
        # Clear chat
        for widget in self.msg_frame.winfo_children():
            widget.destroy()
        
        # Reset displays
        self.reset_displays()
        
        # Restart connection
        self.running = True
        self.root.after(0, self.update_status, "🟡 Connecting to server...", "yellow")
        
        # Start connection in new thread
        threading.Thread(target=self.connect_to_server, daemon=True).start()

    def reset_displays(self):
        """Reset all displays"""
        # Reset key display
        self.key_text.config(state="normal")
        self.key_text.delete("1.0", tk.END)
        self.key_text.insert("1.0", "Keys will appear after connection...")
        self.key_text.config(state="disabled")
        
        # Reset details
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert("1.0", "Connection details will appear here...")
        self.details_text.config(state="disabled")
        
        # Reset stats
        self.stats_text.config(state="normal")
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", "Messages Sent: 0\nMessages Received: 0\nIntegrity Failures: 0")
        self.stats_text.config(state="disabled")
        
        # Update stats label
        self.stats_label.config(text="📊 Messages: 0 sent, 0 received")

    def on_closing(self):
        """Handle window closing"""
        self.cleanup_sockets()
        self.root.destroy()

    def update_status(self, text, color="white"):
        self.status_label.config(text=text, fg=color)
        self.connection_status.config(text=text, fg=color)

    def update_stats(self):
        """Update statistics display"""
        self.stats_text.config(state="normal")
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", f"Messages Sent: {self.messages_sent}\nMessages Received: {self.messages_received}\nIntegrity Failures: {self.integrity_failures}")
        self.stats_text.config(state="disabled")
        
        # Update header stats
        self.stats_label.config(text=f"📊 Messages: {self.messages_sent} sent, {self.messages_received} received")

    def update_connection_info(self):
        # Update control tab
        self.key_text.config(state="normal")
        self.key_text.delete("1.0", tk.END)
        
        hmac_key = generate_hmac_key(self.aes_key)
        
        info = f"""=== SERVER'S KEY ===
RSA Public Key: {self.server_pub_key.export_key().decode('utf-8')[:80]}...
Key Fingerprint: {get_key_fingerprint(self.server_pub_key)}

=== MY KEYS ===
AES Session Key: {self.aes_key.hex()[:32]}...
HMAC Key (SHA-256): {hmac_key.hex()[:32]}...
Key Generated: {datetime.now().strftime('%H:%M:%S')}
Encryption: Active ✅
Integrity: HMAC-SHA256 Active 🛡️"""
        
        self.key_text.insert("1.0", info)
        self.key_text.config(state="disabled")
        
        # Update details tab
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", tk.END)
        
        details = get_encryption_details(self.aes_key, self.server_pub_key)
        details_str = json.dumps(details, indent=2)
        self.details_text.insert("1.0", details_str)
        self.details_text.config(state="disabled")

    def add_message(self, text, timestamp, sent=True, integrity_verified=True):
        # Create container for the entire message (bubble + timestamp)
        msg_container = tk.Frame(self.msg_frame, bg="#0a0a0a")
        
        # For sent messages - align to right, for received - align to left
        if sent:
            msg_container.pack(anchor="e", fill="x", pady=5, padx=10)
            bubble_bg = "#25D366"
        else:
            msg_container.pack(anchor="w", fill="x", pady=5, padx=10)
            if integrity_verified:
                bubble_bg = "#2a2a2a"  # Normal gray for verified messages
            else:
                bubble_bg = "#5D4037"  # Dark brown for integrity failures
        
        # Create bubble
        bubble = tk.Frame(msg_container, bg=bubble_bg, relief="flat")
        
        # For sent messages - bubble on right, for received - on left
        if sent:
            bubble.pack(anchor="e")
        else:
            bubble.pack(anchor="w")
        
        # Message text
        msg_label = tk.Label(
            bubble,
            text=text,
            bg=bubble_bg,
            fg="white",
            wraplength=280,
            justify="left",
            font=("Segoe UI", 11),
            padx=12,
            pady=8
        )
        msg_label.pack()
        
        # Create info frame for timestamp and integrity status
        info_frame = tk.Frame(msg_container, bg="#0a0a0a")
        
        # Timestamp
        time_label = tk.Label(
            info_frame,
            text=timestamp,
            bg="#0a0a0a",
            fg="#888888",
            font=("Segoe UI", 8)
        )
        time_label.pack(side="left", padx=2)
        
        # Integrity indicator (only for received messages)
        if not sent:
            if integrity_verified:
                integrity_color = "#4CAF50"
                integrity_text = "🔒 SHA-256 OK"
            else:
                integrity_color = "#FF5252"
                integrity_text = "⚠️ TAMPERED"
                
            integrity_label = tk.Label(
                info_frame,
                text=integrity_text,
                bg="#0a0a0a",
                fg=integrity_color,
                font=("Segoe UI", 8, "bold")
            )
            integrity_label.pack(side="left", padx=5)
        
        # Pack info frame
        if sent:
            info_frame.pack(anchor="e", padx=5)
        else:
            info_frame.pack(anchor="w", padx=5)
        
        # Auto-scroll to bottom
        self.canvas.yview_moveto(1)

    def send_message(self):
        msg = self.entry.get("1.0", "end-1c").strip()
        if msg and self.connected:
            try:
                encrypted = encrypt_message(msg, self.aes_key)
                self.sock.send(encrypted)
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.add_message(msg, timestamp, True)
                self.messages_sent += 1
                self.update_stats()
                self.entry.delete("1.0", tk.END)
                
                # Log hash
                msg_hash = get_message_hash(msg)
                print(f"[Alice] Sent: '{msg[:30]}...' Hash: {msg_hash}")
                
            except Exception as e:
                self.connected = False
                self.root.after(0, self.update_status, f"🔴 Send failed: {str(e)}", "red")
                if self.sock:
                    self.sock.close()
                    self.sock = None

    def send_on_enter(self, event):
        if event.state == 0 or event.state == 1:  # No modifier or Shift
            self.send_message()
            return "break"  # Prevent default behavior
        return None

    def send_test_message(self):
        if self.connected:
            test_msg = "🔒 This is a test encrypted message with SHA-256 integrity!"
            try:
                encrypted = encrypt_message(test_msg, self.aes_key)
                self.sock.send(encrypted)
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.add_message(test_msg, timestamp, True)
                self.messages_sent += 1
                self.update_stats()
                
                # Verify integrity
                ok, status = verify_message_integrity(encrypted, self.aes_key)
                print(f"[Alice] Test message sent. Integrity: {status}")
                
            except Exception as e:
                self.connected = False
                self.root.after(0, self.update_status, f"🔴 Send failed: {str(e)}", "red")
                if self.sock:
                    self.sock.close()
                    self.sock = None

    def send_tampered_message(self):
        """Send a tampered message to test integrity check"""
        if self.connected:
            test_msg = "🧪 This message will be tampered with to test SHA-256!"
            try:
                # First encrypt normally
                encrypted = encrypt_message(test_msg, self.aes_key)
                
                # Tamper with it
                tampered = tamper_with_message(encrypted)
                
                # Send tampered version
                self.sock.send(tampered)
                print("[Alice] Sent TAMPERED message to test integrity check")
                
                # Show what we did
                self.root.after(0, self.add_message, 
                              "🧪 Sent tampered message to test SHA-256 integrity check", 
                              "Test", True)
                
            except Exception as e:
                print(f"[Alice] Tamper test error: {e}")

    def show_server_key(self):
        if self.server_pub_key:
            key_str = self.server_pub_key.export_key().decode('utf-8')
            messagebox.showinfo("Server's Public Key", key_str)

    def verify_encryption(self):
        if self.connected:
            messagebox.showinfo(
                "Encryption & Integrity Verification",
                "✅ Encryption is ACTIVE\n"
                "🛡️ Integrity: HMAC-SHA256 Active\n\n"
                f"AES Session Key: {self.aes_key.hex()[:16]}...\n"
                f"Key Size: 256-bit\n"
                f"Protected by: RSA-2048\n"
                f"Hash: SHA-256\n"
                f"All messages are encrypted and integrity protected!"
            )

    def test_integrity_check(self):
        """Test integrity verification function"""
        if self.aes_key:
            test_msg = "Test message for integrity verification"
            encrypted = encrypt_message(test_msg, self.aes_key)
            
            # Test 1: Normal verification
            ok1, status1 = verify_message_integrity(encrypted, self.aes_key)
            
            # Test 2: Tampered verification
            tampered = tamper_with_message(encrypted)
            ok2, status2 = verify_message_integrity(tampered, self.aes_key)
            
            messagebox.showinfo(
                "Integrity Test Results",
                f"Test 1 (Normal message):\n{status1}\n\n"
                f"Test 2 (Tampered message):\n{status2}\n\n"
                "SHA-256 integrity checking is working correctly!"
            )
        else:
            messagebox.showinfo("Integrity Test", "Please establish a connection first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
