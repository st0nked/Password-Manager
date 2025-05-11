import tkinter as tk
from tkinter import ttk
import os
import json
import hashlib
import random
import string
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD_FILE = "password.db"
DATA_FILE = "data.json"
SALT_FILE = "salt.bin"

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("800x600")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")

        self.current_frame = None
        self.master_password = None
        self.cipher_suite = None

        self.setup_top_messages()
        
        self.entries = []

        if not os.path.exists(PASSWORD_FILE):
            self.show_setup_screen()
        else:
            self.show_login_screen()

    def setup_top_messages(self):
        common_style = {
            "font": ("Roboto", 14),
            "anchor": "center",
            "width": 800,
            "bg": "#1e1e1e"
        }

        # Success login message
        self.top_success_label = tk.Label(self, text="Successfully logged in!", fg="green", **common_style)
        self.top_success_label.place(x=0, y=-50)

        # Success setup message
        self.top_success_setup_label = tk.Label(self, text="Successfully set Password!", fg="green", **common_style)
        self.top_success_setup_label.place(x=0, y=-50)

        # Error message
        self.top_error_label = tk.Label(self, text="Incorrect password!", fg="red", **common_style)
        self.top_error_label.place(x=0, y=-50)

        # Copy message
        self.top_copy_label = tk.Label(self, text="Copied to clipboard!", fg="green", **common_style)
        self.top_copy_label.place(x=0, y=-50)

    def hide_all_messages(self):
        for label in [self.top_success_label, self.top_success_setup_label, self.top_error_label, self.top_copy_label]:
            label.place_forget()

    def show_setup_screen(self):
        self.clear_current_frame()

        frame = tk.Frame(self, bg="#2d2d2d", bd=2, relief="groove")
        frame.pack(padx=150, pady=200, fill="both", expand=True)
        self.current_frame = frame

        tk.Label(frame, text="Set Password", font=("Roboto", 30), bg="#2d2d2d", fg="#ffffff").pack(pady=15)
        self.setup_password = tk.Entry(frame, show='*', width=30, font=("Roboto", 14))
        self.setup_password.pack(pady=10)
        tk.Button(frame, text="Set Password", font=("Roboto", 14),bg="#3c3c3c", fg="#ffffff", command=self.save_master_password).pack(pady=5)
        tk.Label(frame, text="© 2025 | By Constantin", font=("Roboto", 10), bg="#2d2d2d", fg="#ffffff").pack(
            side="bottom", anchor="se", padx=10, pady=0
        )

    def save_master_password(self):
        password = self.setup_password.get()
        if not password:
            return

        # Generate a random salt
        salt = os.urandom(16)
        
        # Save the salt to a file
        with open(SALT_FILE, 'wb') as salt_file:
            salt_file.write(salt)
            
        # Hash the password with the salt
        hashed = hashlib.sha256(password.encode() + salt).hexdigest()
        
        # Save the hashed password
        with open(PASSWORD_FILE, 'w') as file:
            file.write(hashed)

        # Store the master password for encryption
        self.master_password = password
        
        # Initialize the encryption key
        self.initialize_cipher_suite(password, salt)

        self.show_message(self.top_success_setup_label)
        self.after(1500, self.cleanup_and_show_main_menu)

    def initialize_cipher_suite(self, password, salt=None):
        """Initialize the encryption cipher suite using the master password"""
        if not salt:
            # Read the salt from file
            try:
                with open(SALT_FILE, 'rb') as salt_file:
                    salt = salt_file.read()
            except FileNotFoundError:
                # This should not happen in normal operation
                salt = os.urandom(16)
                with open(SALT_FILE, 'wb') as salt_file:
                    salt_file.write(salt)
        
        # Create an encryption key from the password and salt using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Create the cipher suite
        self.cipher_suite = Fernet(key)

    def show_login_screen(self):
        self.clear_current_frame()

        frame = tk.Frame(self, bg="#2d2d2d", bd=2, relief="groove")
        frame.pack(padx=150, pady=200, fill="both", expand=True)
        self.current_frame = frame

        tk.Label(frame, text="Enter Master Password", font=("Roboto", 30), bg="#2d2d2d", fg="#ffffff").pack(pady=15)
        self.login_password = tk.Entry(frame, show='*', width=30, font=("Roboto", 14))
        self.login_password.pack(pady=10)
        self.login_password.focus_set()
        tk.Button(frame, text="Login", font=("Roboto", 14), command=self.verify_master_password, bg="#3c3c3c", fg="#ffffff").pack(pady=5)
        tk.Label(frame, text="© 2025 | By Constantin", font=("Roboto", 10), bg="#2d2d2d", fg="#ffffff").pack(
            side="bottom", anchor="se", padx=10, pady=0
        )

    def verify_master_password(self):
        entered = self.login_password.get()
        try:
            with open(PASSWORD_FILE, 'r') as pf:
                stored_hash = pf.read().strip()
            
            with open(SALT_FILE, 'rb') as salt_file:
                salt = salt_file.read()
                
        except FileNotFoundError:
            self.show_message(self.top_error_label)
            return

        if hashlib.sha256(entered.encode() + salt).hexdigest() == stored_hash:
            self.master_password = entered
            self.initialize_cipher_suite(entered, salt)
            self.show_message(self.top_success_label)
            self.after(1000, self.cleanup_and_show_main_menu)
            
        else:
            self.login_password.delete(0, tk.END)
            self.show_message(self.top_error_label)

    def clear_current_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None

    def cleanup_and_show_main_menu(self):
        self.clear_current_frame()
        self.load_data()
        self.show_main_menu()

    def show_main_menu(self):
        main_frame = tk.Frame(self, bg="#2d2d2d")
        main_frame.pack(fill="both", expand=True)
        self.current_frame = main_frame

        # Sidebar
        sidebar = tk.Frame(main_frame, width=200, bg="#2d2d2d", relief="sunken", bd=1)
        sidebar.pack(side="left", fill="y")

        tk.Label(sidebar, text="Menu", font=("Roboto", 20), bg="#2d2d2d", fg="#ffffff").pack(pady=10)
        tk.Button(sidebar, text="Add Entry", command=self.show_add_entry, width=15, bg="#3c3c3c", fg="#ffffff", ).pack(padx=10,pady=10)
        tk.Button(sidebar, text="Edit", command=self.enable_edit_mode, width=15, bg="#3c3c3c", fg="#ffffff", ).pack(padx= 10,pady=10)
        tk.Button(sidebar, text="Password Generator", command=self.show_password_generator, width=15, bg="#3c3c3c", fg="#ffffff", ).pack(padx=10,pady=10)

        # Content area
        content = tk.Frame(main_frame, bg="#2e2e2e")
        content.pack(side="right", fill="both", expand=True)

        tk.Label(content, text="Saved Entries", font=("Roboto", 24), bg="#2e2e2e", fg="#ffffff").pack(pady=10)

        canvas = tk.Canvas(content, bg="#2e2e2e")
        scrollbar = ttk.Scrollbar(content, orient="vertical", command=canvas.yview)
        self.entries_list = tk.Frame(canvas, bg="#2e2e2e")

        self.entries_list.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.entries_list, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.refresh_entries_list()

    def show_message(self, label):
        """Show a message by sliding it down from the top."""
        self.hide_all_messages()
        label.place(x=0, y=-50, width=self.winfo_width())
        self.animate_slide_down(label)

    def animate_slide_down(self, label, step=2, delay=10):
        current_y = label.winfo_y()
        if current_y < 10:  
            label.place(y=current_y + step)
            self.after(delay, lambda: self.animate_slide_down(label, step, delay))
        else:
            self.after(1500, lambda: self.animate_slide_up(label))

    def animate_slide_up(self, label, step=2, delay=10):
        current_y = label.winfo_y()
        if current_y > -50: 
            label.place(y=current_y - step)
            self.after(delay, lambda: self.animate_slide_up(label, step, delay))
        else:
            label.place_forget()

    def show_add_entry(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add new Entry")
        dialog.geometry("400x300")
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e1e")
        
        tk.Label(dialog, text="URL", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady=5)
        url_entry = tk.Entry(dialog, width=150)
        url_entry.pack(pady=5, padx=50)
        url_entry.focus_set()
        
        tk.Label(dialog, text="Username", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady=5)
        username_entry = tk.Entry(dialog, width=150)
        username_entry.pack(pady=5, padx=50)
        
        tk.Label(dialog, text="Password", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady=5)
        password_entry = tk.Entry(dialog, width=150)
        password_entry.pack(pady=5, padx=50)
        
        button_frame = tk.Frame(dialog, bg="#1e1e1e")
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, width=10, text="Save", command=lambda: save_entry(), fg="white", bg="#2e2e2e").pack(side="left", padx=5)
        tk.Button(button_frame, width=15, text="Generate Password", command=lambda: self.generate_password_for_entry(password_entry), fg="white", bg="#2e2e2e").pack(side="left", padx=5)
        
        def save_entry():
            url = url_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if url and password:
                self.entries.append({
                    "url": url,
                    "username": username,
                    "password": password
                })
                self.save_entries()
                self.refresh_entries_list()
                dialog.destroy()

    def generate_password_for_entry(self, entry_widget):
        """Generate a password and insert it into the given entry widget"""
        password = self.generate_secure_password(length=16, include_uppercase=True, 
                                                 include_digits=True, include_special=True)
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, password)

    def show_password_generator(self):
        """Open the password generator dialog"""
        dialog = tk.Toplevel(self)
        dialog.title("Password Generator")
        dialog.geometry("450x350")
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e1e")
        
        # Password length slider
        tk.Label(dialog, text="Password Length:", font=("Roboto", 14), bg="#1e1e1e", fg="white").pack(pady=(20, 5))
        length_frame = tk.Frame(dialog, bg="#1e1e1e")
        length_frame.pack(fill="x", padx=20)
        
        length_var = tk.IntVar(value=16)
        length_slider = tk.Scale(length_frame, from_=8, to=32, orient="horizontal", 
                                variable=length_var, bg="#2e2e2e", fg="white", 
                                highlightthickness=0, sliderrelief="flat")
        length_slider.pack(side="left", fill="x", expand=True)
        
        length_display = tk.Label(length_frame, textvariable=length_var, width=3, 
                                bg="#2e2e2e", fg="white", font=("Roboto", 12))
        length_display.pack(side="right", padx=10)
        
        # Character options
        options_frame = tk.Frame(dialog, bg="#1e1e1e", padx=20, pady=10)
        options_frame.pack(fill="x")
        
        uppercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(options_frame, text="Include Uppercase Letters", variable=uppercase_var, 
                     bg="#1e1e1e", fg="white", selectcolor="#2e2e2e", 
                     activebackground="#1e1e1e", activeforeground="white").pack(anchor="w", pady=5)
        
        tk.Checkbutton(options_frame, text="Include Numbers", variable=digits_var, 
                     bg="#1e1e1e", fg="white", selectcolor="#2e2e2e", 
                     activebackground="#1e1e1e", activeforeground="white").pack(anchor="w", pady=5)
        
        tk.Checkbutton(options_frame, text="Include Special Characters", variable=special_var, 
                     bg="#1e1e1e", fg="white", selectcolor="#2e2e2e", 
                     activebackground="#1e1e1e", activeforeground="white").pack(anchor="w", pady=5)
        
        # Generated password
        tk.Label(dialog, text="Generated Password:", font=("Roboto", 14), bg="#1e1e1e", fg="white").pack(pady=(15, 5))
        
        password_var = tk.StringVar()
        password_entry = tk.Entry(dialog, textvariable=password_var, font=("Roboto", 14), 
                                width=30, justify="center", bg="#2e2e2e", fg="white")
        password_entry.pack(pady=5)
        
        button_frame = tk.Frame(dialog, bg="#1e1e1e")
        button_frame.pack(pady=20)
        
        def generate_and_display():
            password = self.generate_secure_password(
                length=length_var.get(),
                include_uppercase=uppercase_var.get(),
                include_digits=digits_var.get(),
                include_special=special_var.get()
            )
            password_var.set(password)
        
        def copy_to_clipboard():
            password = password_var.get()
            if password:
                self.clipboard_clear()
                self.clipboard_append(password)
                self.update()
                self.show_message(self.top_copy_label)
        
        tk.Button(button_frame, text="Generate", command=generate_and_display, 
                width=12, bg="#3c3c3c", fg="white").pack(side="left", padx=5)
        
        tk.Button(button_frame, text="Copy", command=copy_to_clipboard, 
                width=12, bg="#3c3c3c", fg="white").pack(side="left", padx=5)
        
        # Generate initial password
        generate_and_display()

    def generate_secure_password(self, length=16, include_uppercase=True, include_digits=True, include_special=True):
        """Generate a secure random password with the specified characteristics"""
        # Define character sets
        lowercase_chars = string.ascii_lowercase
        uppercase_chars = string.ascii_uppercase if include_uppercase else ""
        digit_chars = string.digits if include_digits else ""
        special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/" if include_special else ""
        
        # Combine all allowed character sets
        all_chars = lowercase_chars + uppercase_chars + digit_chars + special_chars
        
        if not all_chars:
            return ""  # No character set selected
        
        # Ensure at least one character from each selected set
        password_chars = []
        
        # Always include at least one lowercase
        password_chars.append(secrets.choice(lowercase_chars))
        
        # Add one character from each selected set
        if include_uppercase:
            password_chars.append(secrets.choice(uppercase_chars))
        
        if include_digits:
            password_chars.append(secrets.choice(digit_chars))
        
        if include_special:
            password_chars.append(secrets.choice(special_chars))
        
        # Fill the rest with random characters from all allowed sets
        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))
        
        # Shuffle the characters to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        # Convert list to string
        return ''.join(password_chars)

    def enable_edit_mode(self):
        pass  
    
    def refresh_entries_list(self):
        for widget in self.entries_list.winfo_children():
            widget.destroy()

        for i, entry in enumerate(self.entries):
            frame = tk.Frame(self.entries_list, bg="#2e2e2e")
            frame.pack(pady=5, fill="x")

            url_label = tk.Label(frame, text=entry["url"], width=25, bg="#2e2e2e", fg="white", anchor="w")
            url_label.pack(side="left", padx=5)
            
            username = entry.get("username", "")
            username_label = tk.Label(frame, text=username, width=25, bg="#2e2e2e", fg="white", anchor="w")
            username_label.pack(side="left", padx=5)

            pass_label = tk.Label(frame, text="••••••••••", width=25, bg="#2e2e2e", fg="white")
            pass_label.pack(side="left", padx=5)
            
            view_button = tk.Button(frame, text="👁️", bg="#3c3c3c", fg="white", 
                                    command=lambda idx=i: self.toggle_password_visibility(idx))
            view_button.pack(side="left", padx=5)

            pass_label.bind("<Button-1>", lambda e, p=entry["password"]: self.copy_to_clipboard(p))
            url_label.bind("<Control-Button-1>", lambda e, u=entry["url"]: self.open_url(u))
    
    def toggle_password_visibility(self, index):
        """Toggle between showing and hiding the password at the given index"""
        if index < 0 or index >= len(self.entries):
            return
            
        # Get the container frame (which is the parent of all widgets in the row)
        container = self.entries_list.winfo_children()[index]
        
        # The password label is the third child of the container
        password_label = container.winfo_children()[2]
        
        # Check current text to determine if we're showing or hiding
        if password_label["text"] == "••••••••••":
            password_label["text"] = self.entries[index]["password"]
        else:
            password_label["text"] = "••••••••••"
    
    def encrypt_data(self, data):
        """Encrypt data using the cipher suite"""
        if not self.cipher_suite:
            return None
            
        # Convert data to JSON string
        json_data = json.dumps(data)
        
        # Encrypt the JSON string
        encrypted_data = self.cipher_suite.encrypt(json_data.encode('utf-8'))
        
        return encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using the cipher suite"""
        if not self.cipher_suite or not encrypted_data:
            return []
            
        try:
            # Decrypt the data
            decrypted_json = self.cipher_suite.decrypt(encrypted_data)
            
            # Parse the JSON data
            data = json.loads(decrypted_json.decode('utf-8'))
            
            return data
        except Exception as e:
            print(f"Error decrypting data: {e}")
            return []
        
    def save_entries(self):
        """Save entries in encrypted format"""
        if not self.cipher_suite:
            print("Cipher suite not initialized, cannot save entries")
            return False
            
        encrypted_data = self.encrypt_data(self.entries)
        
        try:
            with open(DATA_FILE, "wb") as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            print(f"Error saving entries: {e}")
            return False
            
    def copy_to_clipboard(self, p):
        self.clipboard_clear()
        self.clipboard_append(p)
        self.update()
        self.show_message(self.top_copy_label)

    def open_url(self, u):
        import webbrowser
        webbrowser.open(url=u)
        
    def load_data(self):
        """Load encrypted data from file"""
        try:
            with open(DATA_FILE, 'rb') as file:
                encrypted_data = file.read()
                self.entries = self.decrypt_data(encrypted_data)
        except FileNotFoundError:
            self.entries = []
        except Exception as e:
            print(f"Error loading data: {e}")
            self.entries = []

app = PasswordManager()
app.mainloop()
