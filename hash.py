import bcrypt
import json
import os
import secrets
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import qrcode
from io import BytesIO
from PIL import Image, ImageTk
from cryptography.hazmat.primitives import hashes


# JSON file for storing encrypted passwords
DB_FILE = "password_manager.json"

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Manager")
        self.root.geometry("500x550")
        
        # Colors
        bg_color = "#222831"
        fg_color = "#eeeeee"
        btn_color = "#76ABAE"

        self.root.configure(bg=bg_color)

        # UI Elements
        self.label = tk.Label(root, text="Advanced Password Manager", font=("Arial", 14, "bold"), bg=bg_color, fg=fg_color)
        self.label.pack(pady=10)

        self.username_label = tk.Label(root, text="Username:", bg=bg_color, fg=fg_color)
        self.username_label.pack()
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack()

        self.password_label = tk.Label(root, text="Password:", bg=bg_color, fg=fg_color)
        self.password_label.pack()
        self.password_entry = tk.Entry(root, width=30, show="*")
        self.password_entry.pack()

        self.store_button = tk.Button(root, text="Store Password", bg=btn_color, command=self.store_password)
        self.store_button.pack(pady=5)

        self.verify_button = tk.Button(root, text="Verify Password", bg=btn_color, command=self.verify_password)
        self.verify_button.pack(pady=5)

        self.generate_button = tk.Button(root, text="Generate Strong Password", bg=btn_color, command=self.generate_password)
        self.generate_button.pack(pady=5)

        self.setup_2fa_button = tk.Button(root, text="Setup 2FA", bg=btn_color, command=self.setup_2fa)
        self.setup_2fa_button.pack(pady=5)

        self.export_button = tk.Button(root, text="Export Backup", bg=btn_color, command=self.export_backup)
        self.export_button.pack(pady=5)

        self.import_button = tk.Button(root, text="Import Backup", bg=btn_color, command=self.import_backup)
        self.import_button.pack(pady=5)

        self.check_strength_button = tk.Button(root, text="Check Password Strength", bg=btn_color, command=self.check_password_strength)
        self.check_strength_button.pack(pady=5)

        self.load_data()

    def generate_key(self, master_password: str) -> bytes:
        """Generate encryption key from master password"""
        salt = b'static_salt'  # Ideally, use a unique salt per user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def encrypt_data(self, data: str, key: bytes) -> str:
        """Encrypt data using Fernet"""
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt data using Fernet"""
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()

    def load_data(self):
        """Load stored passwords from JSON"""
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "r") as file:
                self.passwords = json.load(file)
        else:
            self.passwords = {}

    def save_data(self):
        """Save passwords to JSON"""
        with open(DB_FILE, "w") as file:
            json.dump(self.passwords, file, indent=4)

    def store_password(self):
        """Store password securely"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and Password cannot be empty!")
            return

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.passwords[username] = hashed_password
        self.save_data()
        messagebox.showinfo("Success", "Password stored securely!")

    def verify_password(self):
        """Verify password"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username not in self.passwords:
            messagebox.showerror("Error", "Username not found!")
            return

        stored_hash = self.passwords[username].encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            messagebox.showinfo("Success", "Password is correct!")
        else:
            messagebox.showerror("Error", "Incorrect password!")

    def generate_password(self):
        """Generate a strong password"""
        length = 16
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
        password = "".join(secrets.choice(chars) for _ in range(length))
        
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()

        messagebox.showinfo("Generated Password", f"Your new password is copied to clipboard!")

    def check_password_strength(self):
        """Check password strength"""
        password = self.password_entry.get()
        if len(password) < 8:
            strength = "Weak"
        elif any(char.isdigit() for char in password) and any(char.isupper() for char in password):
            strength = "Medium"
        elif any(char in "!@#$%^&*" for char in password):
            strength = "Strong"
        else:
            strength = "Weak"
        
        messagebox.showinfo("Password Strength", f"Strength: {strength}")

    def setup_2fa(self):
        """Setup 2FA for the user"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Enter a username first!")
            return

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name="AdvancedPasswordManager")

        # Generate QR Code
        qr = qrcode.make(uri)
        qr_img = ImageTk.PhotoImage(qr)

        # Show QR Code in a new window
        qr_window = tk.Toplevel(self.root)
        qr_window.title("Scan QR Code for 2FA")
        qr_label = tk.Label(qr_window, image=qr_img)
        qr_label.pack()
        qr_window.mainloop()

        messagebox.showinfo("2FA Setup", f"Secret: {secret}\nScan the QR Code with your authenticator app.")

    def export_backup(self):
        """Export encrypted backup"""
        master_password = simpledialog.askstring("Backup", "Enter master password:", show="*")
        if not master_password:
            return

        key = self.generate_key(master_password)
        data = json.dumps(self.passwords)
        encrypted = self.encrypt_data(data, key)

        with open("backup.enc", "w") as f:
            f.write(encrypted)

        messagebox.showinfo("Success", "Backup exported successfully!")

    def import_backup(self):
        """Import encrypted backup"""
        master_password = simpledialog.askstring("Backup", "Enter master password:", show="*")
        if not master_password:
            return

        key = self.generate_key(master_password)
        try:
            with open("backup.enc", "r") as f:
                encrypted = f.read()
            data = self.decrypt_data(encrypted, key)
            self.passwords = json.loads(data)
            self.save_data()
            messagebox.showinfo("Success", "Backup imported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import backup: {e}")

# Run the Tkinter app
root = tk.Tk()
app = PasswordManagerApp(root)
root.mainloop()