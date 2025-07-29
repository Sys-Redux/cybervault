import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# Get user's home directory for storing vault files
HOME_DIR = Path.home()
VAULT_FILE = HOME_DIR / "vault.json"
MASTER_HASH_FILE = HOME_DIR / "master.hash"

# --- Cyberpunk Colors ---
CYBER_BG = "#181825"
CYBER_PANEL = "#232136"
CYBER_NEON = "#00ffe7"
CYBER_MAGENTA = "#ff00c8"
CYBER_GREEN = "#00ff85"
CYBER_TEXT = "#e0e0e0"
CYBER_TITLE = "#00ffe7"
CYBER_BTN = "#232136"
CYBER_BTN_FG = "#00ffe7"
CYBER_BTN_ACTIVE = "#ff00c8"
CYBER_LIST_SEL = "#00ffe7"
CYBER_LIST_SEL_FG = "#181825"
MONO_FONT = ("Consolas", 12)
TITLE_FONT = ("Consolas", 18, "bold")
LABEL_FONT = ("Consolas", 12, "bold")

HASH_ITERATIONS = 200_000
HASH_SALT_SIZE = 16

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    return {"salt": base64.b64encode(os.urandom(16)).decode(), "notes": {}}

def save_vault(data):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f)

def get_fernet(password: str, data):
    salt = base64.b64decode(data["salt"])
    key = derive_key(password, salt)
    return Fernet(key)

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(HASH_SALT_SIZE)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, HASH_ITERATIONS)
    return salt + pwd_hash  # store salt+hash

def verify_password(password, stored):
    salt = stored[:HASH_SALT_SIZE]
    stored_hash = stored[HASH_SALT_SIZE:]
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, HASH_ITERATIONS)
    return pwd_hash == stored_hash

class VaultGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Notes Vault")
        self.root.geometry("800x600")
        self.root.configure(bg=CYBER_BG)
        self.style = ttk.Style()
        self.apply_cyberpunk_style()
        
        self.vault_data = None
        self.fernet = None
        self.current_note = None
        
        self.setup_ui()
        self.show_login()
    
    def apply_cyberpunk_style(self):
        self.style.theme_use('clam')
        self.style.configure("TFrame", background=CYBER_BG)
        self.style.configure("TLabel", background=CYBER_BG, foreground=CYBER_TEXT, font=LABEL_FONT)
        self.style.configure("Title.TLabel", background=CYBER_BG, foreground=CYBER_TITLE, font=TITLE_FONT)
        self.style.configure("TButton", background=CYBER_BTN, foreground=CYBER_BTN_FG, font=LABEL_FONT, borderwidth=2)
        self.style.map("TButton",
            background=[('active', CYBER_BTN_ACTIVE), ('!active', CYBER_BTN)],
            foreground=[('active', CYBER_TEXT), ('!active', CYBER_BTN_FG)])
        self.style.configure("CyberListbox.TFrame", background=CYBER_PANEL)
        self.style.configure("CyberListbox.TLabel", background=CYBER_PANEL, foreground=CYBER_NEON, font=LABEL_FONT)
        self.style.configure("TEntry", fieldbackground=CYBER_PANEL, foreground=CYBER_NEON, background=CYBER_BG)
        self.style.configure("TScrollbar", background=CYBER_NEON)

    def setup_ui(self):
        # Cyberpunk Title Bar
        self.title_bar = ttk.Label(self.root, text="CYBERVAULT", style="Title.TLabel", anchor="center")
        self.title_bar.pack(fill=tk.X, pady=(0, 8))
        # Login frame
        self.login_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        ttk.Label(self.login_frame, text="Enter Master Password", style="Title.TLabel").pack(pady=10)
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=30, font=MONO_FONT)
        self.password_entry.pack(pady=10)
        ttk.Button(self.login_frame, text="Unlock Vault", command=self.unlock_vault, style="TButton").pack(pady=10)
        # Main vault frame
        self.vault_frame = ttk.Frame(self.root, padding="10", style="TFrame")
        # Top controls
        top_frame = ttk.Frame(self.vault_frame, style="TFrame")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(top_frame, text="Add Note", command=self.add_note, style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(top_frame, text="Delete Note", command=self.delete_note, style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(top_frame, text="Save Note", command=self.save_note, style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        # Main content area
        content_frame = ttk.Frame(self.vault_frame, style="TFrame")
        content_frame.pack(fill=tk.BOTH, expand=True)
        # Left panel - note list
        left_frame = ttk.Frame(content_frame, style="CyberListbox.TFrame")
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        ttk.Label(left_frame, text="Notes:", style="CyberListbox.TLabel").pack(anchor=tk.W)
        # Note listbox with scrollbar
        list_frame = ttk.Frame(left_frame, style="CyberListbox.TFrame")
        list_frame.pack(fill=tk.BOTH, expand=True)
        self.note_listbox = tk.Listbox(list_frame, width=30, bg=CYBER_PANEL, fg=CYBER_NEON, selectbackground=CYBER_LIST_SEL, selectforeground=CYBER_LIST_SEL_FG, font=MONO_FONT, highlightthickness=2, highlightbackground=CYBER_NEON, relief=tk.FLAT, borderwidth=0)
        self.note_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.note_listbox.bind('<<ListboxSelect>>', self.on_note_select)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.note_listbox.yview, style="TScrollbar")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.note_listbox.config(yscrollcommand=scrollbar.set)
        # Right panel - note content
        right_frame = ttk.Frame(content_frame, style="TFrame")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        ttk.Label(right_frame, text="Note Content:", style="CyberListbox.TLabel").pack(anchor=tk.W)
        # Note content text area with scrollbar
        text_frame = ttk.Frame(right_frame, style="TFrame")
        text_frame.pack(fill=tk.BOTH, expand=True)
        self.note_text = tk.Text(text_frame, wrap=tk.WORD, undo=True, bg=CYBER_BG, fg=CYBER_MAGENTA, insertbackground=CYBER_NEON, font=MONO_FONT, relief=tk.FLAT, borderwidth=2, highlightthickness=2, highlightbackground=CYBER_NEON)
        self.note_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.note_text.yview, style="TScrollbar")
        text_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.note_text.config(yscrollcommand=text_scrollbar.set)
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.vault_frame, textvariable=self.status_var, relief=tk.SUNKEN, background=CYBER_PANEL, foreground=CYBER_NEON, font=MONO_FONT)
        status_bar.pack(fill=tk.X, pady=(10, 0))
    
    def show_login(self):
        self.vault_frame.pack_forget()
        self.login_frame.pack(expand=True)
        self.password_entry.focus()
        self.password_entry.bind('<Return>', lambda e: self.unlock_vault())
        # If no master hash, prompt to set password
        if not os.path.exists(MASTER_HASH_FILE):
            self.set_master_password()

    def set_master_password(self):
        while True:
            pwd1 = simpledialog.askstring("Set Master Password", "Enter a new master password:", show='*')
            if not pwd1:
                messagebox.showerror("Error", "Password cannot be empty.")
                continue
            pwd2 = simpledialog.askstring("Set Master Password", "Confirm master password:", show='*')
            if pwd1 != pwd2:
                messagebox.showerror("Error", "Passwords do not match.")
                continue
            # Save hash
            hashed = hash_password(pwd1)
            with open(MASTER_HASH_FILE, 'wb') as f:
                f.write(hashed)
            messagebox.showinfo("Success", "Master password set. Please log in.")
            break

    def unlock_vault(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        # Check password hash
        if not os.path.exists(MASTER_HASH_FILE):
            messagebox.showerror("Error", "No master password set. Please restart the app.")
            return
        with open(MASTER_HASH_FILE, 'rb') as f:
            stored = f.read()
        if not verify_password(password, stored):
            messagebox.showerror("Error", "Incorrect master password.")
            return
        try:
            self.vault_data = load_vault()
            self.fernet = get_fernet(password, self.vault_data)
            self.login_frame.pack_forget()
            self.vault_frame.pack(fill=tk.BOTH, expand=True)
            self.refresh_note_list()
            self.status_var.set("Vault unlocked successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock vault: {str(e)}")
    
    def refresh_note_list(self):
        self.note_listbox.delete(0, tk.END)
        for title in self.vault_data["notes"].keys():
            self.note_listbox.insert(tk.END, title)
    
    def on_note_select(self, event):
        selection = self.note_listbox.curselection()
        if selection:
            title = self.note_listbox.get(selection[0])
            self.load_note(title)
    
    def load_note(self, title):
        try:
            encrypted_content = self.vault_data["notes"][title]
            decrypted_content = self.fernet.decrypt(encrypted_content.encode()).decode()
            self.note_text.delete(1.0, tk.END)
            self.note_text.insert(1.0, decrypted_content)
            self.current_note = title
            self.status_var.set(f"Loaded note: {title}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load note: {str(e)}")
    
    def add_note(self):
        title = simpledialog.askstring("Add Note", "Enter note title:")
        if title:
            if title in self.vault_data["notes"]:
                messagebox.showerror("Error", "A note with this title already exists")
                return
            encrypted = self.fernet.encrypt("".encode()).decode()
            self.vault_data["notes"][title] = encrypted
            save_vault(self.vault_data)
            self.refresh_note_list()
            # Select the new note
            for i in range(self.note_listbox.size()):
                if self.note_listbox.get(i) == title:
                    self.note_listbox.selection_clear(0, tk.END)
                    self.note_listbox.selection_set(i)
                    self.note_listbox.see(i)
                    self.load_note(title)
                    break
            self.status_var.set(f"Added new note: {title}")
    
    def save_note(self):
        if not self.current_note:
            messagebox.showwarning("Warning", "No note selected")
            return
        
        content = self.note_text.get(1.0, tk.END).strip()
        encrypted_content = self.fernet.encrypt(content.encode()).decode()
        self.vault_data["notes"][self.current_note] = encrypted_content
        save_vault(self.vault_data)
        self.status_var.set(f"Saved note: {self.current_note}")
    
    def delete_note(self):
        if not self.current_note:
            messagebox.showwarning("Warning", "No note selected")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{self.current_note}'?"):
            del self.vault_data["notes"][self.current_note]
            save_vault(self.vault_data)
            self.refresh_note_list()
            self.note_text.delete(1.0, tk.END)
            self.current_note = None
            self.status_var.set("Note deleted")

def main():
    root = tk.Tk()
    app = VaultGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 