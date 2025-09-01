import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
import argparse
from pathlib import Path
import shutil

# --- Constants ---
HOME_DIR = Path.home()
VAULT_DIR = HOME_DIR / ".cybervault"
MASTER_HASH_FILE = HOME_DIR / "master.hash" # Used by GUI, but good to have here

# Ensure the vault directory exists
os.makedirs(VAULT_DIR, exist_ok=True)

class CyberVault:
    def __init__(self, vault_name, password=None):
        self.vault_name = vault_name
        self.vault_path = VAULT_DIR / f"{vault_name}.json"
        self.password = password
        self.data = self._load_vault()
        self.fernet = self._get_fernet() if password else None
        self._is_unlocked = password is not None

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _load_vault(self):
        if not self.vault_path.exists():
            raise FileNotFoundError(f"Vault '{self.vault_name}' not found.")
        with open(self.vault_path, "r") as f:
            return json.load(f)

    def _save_vault(self):
        with open(self.vault_path, "w") as f:
            json.dump(self.data, f, indent=4)

    def _get_fernet(self):
        salt = base64.b64decode(self.data["salt"])
        key = self._derive_key(self.password, salt)
        return Fernet(key)

    def unlock(self, password):
        """Unlock the vault with a password."""
        try:
            self.password = password
            self.fernet = self._get_fernet()
            # Test the password by trying to decrypt one note (if any exist)
            if self.data["notes"]:
                first_note_title = list(self.data["notes"].keys())[0]
                encrypted_text = self.data["notes"][first_note_title]
                self.fernet.decrypt(encrypted_text.encode()).decode()
            self._is_unlocked = True
            return True
        except (InvalidToken, Exception):
            self.password = None
            self.fernet = None
            self._is_unlocked = False
            return False

    def is_unlocked(self):
        """Check if the vault is currently unlocked."""
        return self._is_unlocked

    def lock(self):
        """Lock the vault by clearing the password and fernet instance."""
        self.password = None
        self.fernet = None
        self._is_unlocked = False

    def add_note(self, title, text):
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked to add notes.")
        encrypted_text = self.fernet.encrypt(text.encode()).decode()
        self.data["notes"][title] = encrypted_text
        self._save_vault()

    def get_note(self, title):
        """Get decrypted note content. Returns None if note doesn't exist."""
        if title not in self.data["notes"]:
            return None
        if not self._is_unlocked:
            raise ValueError("Vault must be unlocked to decrypt notes.")
        try:
            encrypted_text = self.data["notes"][title]
            return self.fernet.decrypt(encrypted_text.encode()).decode()
        except InvalidToken:
            raise ValueError("Invalid password or corrupted data.")

    def get_encrypted_note(self, title):
        """Get encrypted note content without decrypting."""
        if title not in self.data["notes"]:
            return None
        return self.data["notes"][title]

    def delete_note(self, title):
        if title in self.data["notes"]:
            del self.data["notes"][title]
            self._save_vault()
            return True
        return False

    def list_notes(self):
        return list(self.data["notes"].keys())

    @staticmethod
    def list_vaults():
        return [f.stem for f in VAULT_DIR.glob("*.json")]

    @staticmethod
    def create_vault(vault_name, password):
        vault_path = VAULT_DIR / f"{vault_name}.json"
        if vault_path.exists():
            raise FileExistsError(f"Vault '{vault_name}' already exists.")

        salt = os.urandom(16)
        # We need to derive a key to check if the password is good, but also to show it works
        key = CyberVault._derive_key(password, salt)
        fernet = Fernet(key)

        # Create initial vault structure
        initial_data = {
            "salt": base64.b64encode(salt).decode(),
            "notes": {
                "welcome_note": fernet.encrypt(b"Your new vault is ready!").decode()
            }
        }
        with open(vault_path, "w") as f:
            json.dump(initial_data, f, indent=4)

    @staticmethod
    def delete_vault(vault_name):
        vault_path = VAULT_DIR / f"{vault_name}.json"
        if not vault_path.exists():
            raise FileNotFoundError(f"Vault '{vault_name}' not found.")
        os.remove(vault_path)

def main():
    parser = argparse.ArgumentParser(description="CyberVault - Encrypted Notes Vault")

    # Subparsers for different actions
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Note-level commands
    parser_add = subparsers.add_parser("add", help="Add a new note to a vault")
    parser_add.add_argument("--vault", required=True, help="Name of the vault")
    parser_add.add_argument("--title", required=True, help="Title of the note")
    parser_add.add_argument("--text", required=True, help="Text of the note")

    parser_get = subparsers.add_parser("get", help="Get a note from a vault")
    parser_get.add_argument("--vault", required=True, help="Name of the vault")
    parser_get.add_argument("--title", required=True, help="Title of the note")

    parser_delete = subparsers.add_parser("delete", help="Delete a note from a vault")
    parser_delete.add_argument("--vault", required=True, help="Name of the vault")
    parser_delete.add_argument("--title", required=True, help="Title of the note")

    parser_list = subparsers.add_parser("list", help="List all notes in a vault")
    parser_list.add_argument("--vault", required=True, help="Name of the vault")

    # Vault-level commands
    subparsers.add_parser("list-vaults", help="List all available vaults")

    parser_create_vault = subparsers.add_parser("create-vault", help="Create a new vault")
    parser_create_vault.add_argument("vault_name", help="Name for the new vault")

    parser_delete_vault = subparsers.add_parser("delete-vault", help="Delete a vault")
    parser_delete_vault.add_argument("vault_name", help="Name of the vault to delete")

    args = parser.parse_args()

    try:
        if args.action == "list-vaults":
            vaults = CyberVault.list_vaults()
            if not vaults:
                print("No vaults found. Create one with 'create-vault'.")
            else:
                print("Available Vaults:")
                for v in vaults:
                    print(f" - {v}")

        elif args.action == "create-vault":
            password = getpass.getpass("Enter a password for the new vault: ")
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print("Passwords do not match.")
                return
            CyberVault.create_vault(args.vault_name, password)
            print(f"Vault '{args.vault_name}' created successfully.")

        elif args.action == "delete-vault":
            if input(f"Are you sure you want to delete vault '{args.vault_name}'? This is irreversible. (y/n): ").lower() == 'y':
                CyberVault.delete_vault(args.vault_name)
                print(f"Vault '{args.vault_name}' deleted.")
            else:
                print("Deletion cancelled.")

        else: # Note-level commands that require a password
            password = getpass.getpass(f"Enter password for vault '{args.vault}': ")
            vault = CyberVault(args.vault, password)

            if args.action == "add":
                vault.add_note(args.title, args.text)
                print(f"Note '{args.title}' added to vault '{args.vault}'.")

            elif args.action == "get":
                note = vault.get_note(args.title)
                if note is None:
                    print("Note not found.")
                else:
                    print(f"--- {args.title} ---")
                    print(note)

            elif args.action == "delete":
                if vault.delete_note(args.title):
                    print(f"Note '{args.title}' deleted from vault '{args.vault}'.")
                else:
                    print("Note not found.")

            elif args.action == "list":
                notes = vault.list_notes()
                print(f"Notes in vault '{args.vault}':")
                for title in notes:
                    print(f" - {title}")

    except (FileNotFoundError, FileExistsError, ValueError) as e:
        print(f"Error: {e}")
    except InvalidToken:
        print("Error: Invalid password or corrupted vault data.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main() 