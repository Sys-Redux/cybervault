import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import argparse
from pathlib import Path

# Get user's home directory for storing vault files
HOME_DIR = Path.home()
VAULT_FILE = HOME_DIR / "vault.json"

# Key derivation
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

def main():
    parser = argparse.ArgumentParser(description="Encrypted Notes Vault")
    parser.add_argument("action", choices=["add", "get", "delete", "list"])
    parser.add_argument("--title", help="Title of the note")
    parser.add_argument("--text", help="Text of the note (for add)")
    args = parser.parse_args()

    data = load_vault()
    master_pwd = getpass.getpass("Enter master password: ")
    fernet = get_fernet(master_pwd, data)

    if args.action == "add":
        if not args.title or not args.text:
            print("Both --title and --text are required for 'add'")
            return
        encrypted = fernet.encrypt(args.text.encode()).decode()
        data["notes"][args.title] = encrypted
        save_vault(data)
        print(f"Note '{args.title}' added.")
    elif args.action == "get":
        if not args.title or args.title not in data["notes"]:
            print("Note not found.")
            return
        decrypted = fernet.decrypt(data["notes"][args.title].encode()).decode()
        print(f"{args.title}: {decrypted}")
    elif args.action == "delete":
        if not args.title or args.title not in data["notes"]:
            print("Note not found.")
            return
        del data["notes"][args.title]
        save_vault(data)
        print(f"Note '{args.title}' deleted.")
    elif args.action == "list":
        print("Stored Notes:")
        for k in data["notes"].keys():
            print(f" - {k}")

if __name__ == "__main__":
    main() 