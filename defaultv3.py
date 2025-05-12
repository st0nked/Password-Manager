import tkinter as tk
from tkinter import ttk
import os
import json
import hashlib
import string
import secrets
PASSWORD_FILE = "password.db"
DATA_FILE = "data.json"


class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("800x600")
        self.resizable(False, False)
        self.configure(bg="#1e1e1e")

        self.current_frame = None

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

    def hide_all_messages(self):
        for label in [self.top_success_label, self.top_success_setup_label, self.top_error_label]:
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

        hashed = hashlib.sha256(password.encode()).hexdigest()
        with open(PASSWORD_FILE, 'w') as file:
            file.write(hashed)

        self.show_message(self.top_success_setup_label)

        self.after(1500, self.cleanup_and_show_main_menu)

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
        except FileNotFoundError:
            self.show_message(self.top_error_label)
            return

        if hashlib.sha256(entered.encode()).hexdigest() == stored_hash:
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
        tk.Button(sidebar, text="Password Generator", command=self.show_password_gen, width=15, bg="#3c3c3c", fg="#ffffff", ).pack(padx= 10,pady=10)

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

    def show_password_gen(self):
        dialog = tk.Toplevel(self)
        dialog.title("Generate Password")
        dialog.geometry("400x350")
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e1e")
        
        
        tk.Label(dialog, text="Password Length", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady=5)
        length_frame = tk.Frame(dialog, bg="#1e1e1e")
        length_frame.pack(fill="x" ,padx=20)
        
        length_var = tk.IntVar(value=12)
        length_scale = tk.Scale(length_frame, from_=8, to=28, orient="horizontal", variable=length_var, bg="#1e1e1e", fg="white", highlightthickness=0, sliderrelief="flat")
        length_scale.pack(fill="x", padx=10, pady=5)
        
        options_frame = tk.Frame(dialog, bg="#1e1e1e", padx=20 ,pady=10)  
        options_frame.pack(fill="x")
        
        Uppercase_var = tk.BooleanVar(value=True)
        Numbers_var = tk.BooleanVar(value=True)
        Special_var = tk.BooleanVar(value=True)       
        
        tk.Checkbutton(options_frame, text="Include Uppercase", variable=Uppercase_var, bg="#1e1e1e", fg="white", activebackground="#1e1e1e", activeforeground="white", selectcolor="#2e2e2e").pack(anchor="w")
        tk.Checkbutton(options_frame, text="Include Numbers", variable=Numbers_var, bg="#1e1e1e", fg="white", activebackground="#1e1e1e", activeforeground="white", selectcolor="#2e2e2e").pack(anchor="w")
        tk.Checkbutton(options_frame, text="Include Special Characters", variable=Special_var, bg="#1e1e1e", fg="white" , activebackground="#1e1e1e", activeforeground="white", selectcolor="#2e2e2e").pack(anchor="w")
        
        
        password_var = tk.StringVar()
        tk.Label(dialog, text="Generated Password", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady=5)
        generated_password = tk.Entry(dialog, textvariable=password_var, width=30, font=("Roboto", 14), bg="#2e2e2e", fg="white", justify="center")
        generated_password.pack(pady=0)
        
        def generate_and_display():
            password = self.generate_password(
                length=length_var.get(),
                include_uppercase=Uppercase_var.get(),
                include_digits=Numbers_var.get(),
                include_special=Special_var.get()
            )
            password_var.set(password)
            
        def copy_password_to_clipboard():
            self.clipboard_clear()
            self.clipboard_append(password_var.get())
            self.update()
        
        tk.Button(dialog, width=25, text="Generate", fg="white", bg="#2e2e2e", command=generate_and_display).pack(pady=20)
        tk.Button(dialog, width=25, text="Copy to Clipboard", fg="white", bg="#2e2e2e", command=copy_password_to_clipboard).pack(pady=5)
        
        
    def generate_password(self, length=12, include_uppercase=True, include_digits=True, include_special=True):
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase if include_uppercase else ""
        digits = string.digits if include_digits else ""
        special = string.punctuation if include_special else ""
        all_characters = lowercase + uppercase + digits + special
        
        if not all_characters:
            return ""
        
        password_chars = []
        
        password_chars.append(secrets.choice(lowercase))
        
        if include_uppercase:
            password_chars.append(secrets.choice(uppercase))
        if include_digits:
            password_chars.append(secrets.choice(digits))
        if include_special:
            password_chars.append(secrets.choice(special))
            
        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            password_chars += [secrets.choice(all_characters) for _ in range(remaining_length)]
            
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)
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
        dialog.geometry("400x250")
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e1e")
        
        tk.Label(dialog, text="URL", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady=5)
        url_entry = tk.Entry(dialog, width=150)
        url_entry.pack(pady=5, padx=50)
        url_entry.focus_set()
        
        tk.Label(dialog, text="Password", font=("Roboto", 14), fg="white", bg="#1e1e1e").pack(pady = 5)
        password_entry = tk.Entry(dialog, width=150)
        password_entry.pack(pady=15, padx=50)
        
        def save_entry():
            url = url_entry.get()
            password = password_entry.get()
            if url and password:
                self.entries.append({"url": url, "password": password})
                self.save_entries()
                self.refresh_entries_list()
                dialog.destroy()
        
        tk.Button(dialog, width=10, text="Save", command=save_entry, fg="white", bg="#2e2e2e").pack(pady=10)
    def refresh_entries_list(self):
        for widget in self.entries_list.winfo_children():
            widget.destroy()

        for entry in self.entries:
            frame = tk.Frame(self.entries_list)
            frame.pack(pady=5, fill="x")

            url_label = tk.Label(frame, text=entry["url"], width=25, bg="#2e2e2e", fg="white", anchor="w")
            url_label.pack(side="left", padx=0)

            pass_label = tk.Label(frame, text="••••••••••", width=25, bg="#2e2e2e", fg="white")
            pass_label.pack(side="left", padx=0)

            pass_label.bind("<Button-1>", lambda e, p=entry["password"]: self.copy_to_clipboard(p))
            url_label.bind("<Control-Button-1>", lambda e, u=entry["url"]: self.open_url(u))
            
    def save_entries(self):
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, indent=4)
            
    def copy_to_clipboard(self, p):
        self.clipboard_clear()
        self.clipboard_append(p)
        self.update()

    def open_url(self, u):
        import webbrowser
        webbrowser.open(url=u)
        
    def load_data(self):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as file:
                self.entries = json.load(file)
        except(FileNotFoundError, json.JSONDecodeError):
            self.entries = []

app = PasswordManager()
app.mainloop()
