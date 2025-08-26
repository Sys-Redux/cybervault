import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import json
import base64
import hashlib
from cryptography.fernet import InvalidToken
from pathlib import Path
from .vault import CyberVault, VAULT_DIR

# Get user's home directory for storing vault files
HOME_DIR = Path.home()
# VAULT_FILE is deprecated, VAULT_DIR is imported from .vault
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

# Removed derive_key, load_vault, save_vault, get_fernet
# This functionality is now in the CyberVault class

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
        self.root.title("CyberVault")
        self.root.geometry("800x600")
        self.root.configure(bg=CYBER_BG)
        self.style = ttk.Style()
        self.apply_cyberpunk_style()

        self.master_password = None
        self.active_vault = None # This will be a CyberVault instance
        self.current_note_title = None

        self.setup_ui()
        self.show_login()

    def apply_cyberpunk_style(self):
        self.style.theme_use('clam')
        # ... (style configuration remains the same)
        self.style.configure("TFrame", background=CYBER_BG)
        self.style.configure("TLabel", background=CYBER_BG, foreground=CYBER_TEXT, font=LABEL_FONT)
        self.style.configure("Title.TLabel", background=CYBER_BG, foreground=CYBER_TITLE, font=TITLE_FONT)
        self.style.configure("TButton", background=CYBER_BTN, foreground=CYBER_BTN_FG, font=LABEL_FONT, borderwidth=2)
        self.style.map("TButton",
            background=[('active', CYBER_BTN_ACTIVE), ('!active', CYBER_BTN)],
            foreground=[('active', CYBER_TEXT), ('!active', CYBER_BTN_FG)])
        self.style.configure("CyberListbox.TFrame", background=CYBER_PANEL)
        self.style.configure("CyberListbox.TLabel", background=CYBER_PANEL, foreground=CYBER_NEON, font=LABEL_FONT)
        self.style.configure("TEntry", fieldbackground=CYBER_PANEL, foreground=CYBER_NEON, background=CYBER_BG, insertbackground=CYBER_NEON)
        self.style.configure("TScrollbar", background=CYBER_NEON)


    def setup_ui(self):
        # --- Universal Title Bar ---
        self.title_bar = ttk.Label(self.root, text="CYBERVAULT", style="Title.TLabel", anchor="center")
        self.title_bar.pack(fill=tk.X, pady=(0, 8))

        # --- Login Frame ---
        self.login_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        ttk.Label(self.login_frame, text="Enter Master Password", style="Title.TLabel").pack(pady=10)
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=30, font=MONO_FONT)
        self.password_entry.pack(pady=10)
        ttk.Button(self.login_frame, text="Unlock", command=self.unlock_vault, style="TButton").pack(pady=10)

        # --- Vault Selection Frame ---
        self.vault_selection_frame = ttk.Frame(self.root, padding="20", style="TFrame")
        ttk.Label(self.vault_selection_frame, text="Select a Vault", style="Title.TLabel").pack(pady=10)

        vault_list_frame = ttk.Frame(self.vault_selection_frame, style="CyberListbox.TFrame")
        vault_list_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.vault_listbox = tk.Listbox(vault_list_frame, bg=CYBER_PANEL, fg=CYBER_NEON, selectbackground=CYBER_LIST_SEL, selectforeground=CYBER_LIST_SEL_FG, font=MONO_FONT, highlightthickness=0, relief=tk.FLAT)
        self.vault_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        vault_buttons_frame = ttk.Frame(self.vault_selection_frame, style="TFrame")
        vault_buttons_frame.pack(pady=10)
        ttk.Button(vault_buttons_frame, text="Open Vault", command=self.open_selected_vault, style="TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(vault_buttons_frame, text="Create New Vault", command=self.create_new_vault, style="TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(vault_buttons_frame, text="Delete Vault", command=self.delete_selected_vault, style="TButton").pack(side=tk.LEFT, padx=5)

        # --- Note Frame (previously vault_frame) ---
        self.note_frame = ttk.Frame(self.root, padding="10", style="TFrame")
        top_frame = ttk.Frame(self.note_frame, style="TFrame")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(top_frame, text="Save Note", command=self.save_note, style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(top_frame, text="Add Note", command=self.add_note, style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(top_frame, text="Delete Note", command=self.delete_note, style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(top_frame, text="< Back to Vaults", command=self.logout, style="TButton").pack(side=tk.RIGHT, padx=(5, 0))

        content_frame = ttk.Frame(self.note_frame, style="TFrame")
        content_frame.pack(fill=tk.BOTH, expand=True)
        # Note List (Left)
        left_frame = ttk.Frame(content_frame, style="CyberListbox.TFrame")
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        self.note_list_title = ttk.Label(left_frame, text="Notes in ...", style="CyberListbox.TLabel")
        self.note_list_title.pack(anchor=tk.W)
        self.note_listbox = tk.Listbox(left_frame, width=30, bg=CYBER_PANEL, fg=CYBER_NEON, selectbackground=CYBER_LIST_SEL, selectforeground=CYBER_LIST_SEL_FG, font=MONO_FONT, highlightthickness=0, relief=tk.FLAT)
        self.note_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.note_listbox.bind('<<ListboxSelect>>', self.on_note_select)
        # Note Content (Right)
        right_frame = ttk.Frame(content_frame, style="TFrame")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        ttk.Label(right_frame, text="Note Content:", style="CyberListbox.TLabel").pack(anchor=tk.W)
        self.note_text = tk.Text(right_frame, wrap=tk.WORD, undo=True, bg=CYBER_BG, fg=CYBER_MAGENTA, insertbackground=CYBER_NEON, font=MONO_FONT, relief=tk.FLAT, borderwidth=2, highlightthickness=2, highlightbackground=CYBER_NEON)
        self.note_text.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.note_frame, textvariable=self.status_var, relief=tk.SUNKEN, background=CYBER_PANEL, foreground=CYBER_NEON, font=MONO_FONT)
        status_bar.pack(fill=tk.X, pady=(10, 0), side=tk.BOTTOM)

    def show_login(self):
        self.note_frame.pack_forget()
        self.vault_selection_frame.pack_forget()
        self.login_frame.pack(expand=True)
        self.password_entry.focus()
        self.password_entry.bind('<Return>', lambda e: self.unlock_vault())
        if not os.path.exists(MASTER_HASH_FILE):
            self.set_master_password()

    def set_master_password(self):
        # ... (this method remains the same)
        while True:
            pwd1 = simpledialog.askstring("Set Master Password", "Enter a new master password:", show='*')
            if not pwd1:
                messagebox.showerror("Error", "Password cannot be empty.")
                continue
            pwd2 = simpledialog.askstring("Set Master Password", "Confirm master password:", show='*')
            if pwd1 != pwd2:
                messagebox.showerror("Error", "Passwords do not match.")
                continue
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
        if not os.path.exists(MASTER_HASH_FILE):
            messagebox.showerror("Error", "No master password set. Please restart.")
            return
        with open(MASTER_HASH_FILE, 'rb') as f:
            stored = f.read()
        if not verify_password(password, stored):
            messagebox.showerror("Error", "Incorrect master password.")
            return

        self.master_password = password
        self.password_entry.delete(0, tk.END)
        self.show_vault_selection()

    def show_vault_selection(self):
        self.login_frame.pack_forget()
        self.note_frame.pack_forget()
        self.vault_selection_frame.pack(fill=tk.BOTH, expand=True)
        self.refresh_vault_list()

    def refresh_vault_list(self):
        self.vault_listbox.delete(0, tk.END)
        for vault_name in CyberVault.list_vaults():
            self.vault_listbox.insert(tk.END, vault_name)

    def open_selected_vault(self):
        selection = self.vault_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a vault to open.")
            return
        vault_name = self.vault_listbox.get(selection[0])

        vault_password = simpledialog.askstring(f"Password for {vault_name}", f"Enter password for '{vault_name}':", show='*')
        if not vault_password:
            return

        try:
            self.active_vault = CyberVault(vault_name, vault_password)
            self.show_note_editor()
        except (InvalidToken, ValueError):
            messagebox.showerror("Error", "Invalid password for this vault.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open vault: {e}")

    def create_new_vault(self):
        vault_name = simpledialog.askstring("Create New Vault", "Enter a name for the new vault:")
        if not vault_name: return
        if vault_name in CyberVault.list_vaults():
            messagebox.showerror("Error", f"Vault '{vault_name}' already exists.")
            return

        password = simpledialog.askstring("Create New Vault", f"Enter a password for '{vault_name}':", show='*')
        if not password: return
        password_confirm = simpledialog.askstring("Create New Vault", "Confirm password:", show='*')
        if password != password_confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        try:
            CyberVault.create_vault(vault_name, password)
            messagebox.showinfo("Success", f"Vault '{vault_name}' created.")
            self.refresh_vault_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {e}")

    def delete_selected_vault(self):
        selection = self.vault_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a vault to delete.")
            return
        vault_name = self.vault_listbox.get(selection[0])

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to permanently delete the vault '{vault_name}'?"):
            try:
                CyberVault.delete_vault(vault_name)
                messagebox.showinfo("Success", f"Vault '{vault_name}' deleted.")
                self.refresh_vault_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete vault: {e}")

    def show_note_editor(self):
        self.vault_selection_frame.pack_forget()
        self.note_frame.pack(fill=tk.BOTH, expand=True)
        self.note_list_title.config(text=f"Notes in {self.active_vault.vault_name}")
        self.refresh_note_list()
        self.note_text.delete(1.0, tk.END)
        self.current_note_title = None
        self.status_var.set(f"Opened vault: {self.active_vault.vault_name}")

    def logout(self):
        self.active_vault = None
        self.current_note_title = None
        self.show_vault_selection()

    def refresh_note_list(self):
        self.note_listbox.delete(0, tk.END)
        if self.active_vault:
            for title in self.active_vault.list_notes():
                self.note_listbox.insert(tk.END, title)

    def on_note_select(self, event):
        selection = self.note_listbox.curselection()
        if selection:
            title = self.note_listbox.get(selection[0])
            self.load_note(title)

    def load_note(self, title):
        try:
            content = self.active_vault.get_note(title)
            self.note_text.delete(1.0, tk.END)
            self.note_text.insert(1.0, content)
            self.current_note_title = title
            self.status_var.set(f"Loaded note: {title}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load note: {e}")

    def add_note(self):
        if not self.active_vault: return
        title = simpledialog.askstring("Add Note", "Enter note title:")
        if title:
            if title in self.active_vault.list_notes():
                messagebox.showerror("Error", "A note with this title already exists.")
                return
            self.active_vault.add_note(title, "") # Add empty note
            self.refresh_note_list()
            # Auto-select the new note
            for i in range(self.note_listbox.size()):
                if self.note_listbox.get(i) == title:
                    self.note_listbox.selection_clear(0, tk.END)
                    self.note_listbox.selection_set(i)
                    self.load_note(title)
                    break
            self.status_var.set(f"Added new note: {title}")

    def save_note(self):
        if not self.active_vault or not self.current_note_title:
            messagebox.showwarning("Warning", "No note selected to save.")
            return
        
        content = self.note_text.get(1.0, tk.END).strip()
        try:
            self.active_vault.add_note(self.current_note_title, content)
            self.status_var.set(f"Saved note: {self.current_note_title}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save note: {e}")

    def delete_note(self):
        if not self.active_vault or not self.current_note_title:
            messagebox.showwarning("Warning", "No note selected to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete note '{self.current_note_title}'?"):
            try:
                self.active_vault.delete_note(self.current_note_title)
                self.refresh_note_list()
                self.note_text.delete(1.0, tk.END)
                self.current_note_title = None
                self.status_var.set("Note deleted.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete note: {e}")

def main():
    root = tk.Tk()
    app = VaultGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 