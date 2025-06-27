# main.py
import os
import json
import hashlib
import base64
import argparse
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from app.crypto_utils import encrypt_file, decrypt_file
from app.metadata_utils import export_metadata, load_metadata, save_metadata

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QLabel, QMessageBox, QInputDialog, QTextEdit, QListWidget,
    QHBoxLayout, QCheckBox
)
from PyQt5.QtCore import Qt

META_FILE = "metadata.json"
STORAGE_DIR = "encrypted_files"
LOG_FILE = "secure_vault.log"

os.makedirs(STORAGE_DIR, exist_ok=True)

def log(message):
    with open(LOG_FILE, 'a') as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] {message}\n")
    print(message)

# Derive Fernet key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def main():
    parser = argparse.ArgumentParser(description="Secure File Storage with AES-256")
    subparsers = parser.add_subparsers(dest="command")

    enc_parser = subparsers.add_parser("encrypt")
    enc_parser.add_argument("file", nargs='+', help="File(s) to encrypt")
    enc_parser.add_argument("--password", required=True, help="Encryption password")
    enc_parser.add_argument("--force", action="store_true", help="Allow overwriting if file already exists")

    dec_parser = subparsers.add_parser("decrypt")
    dec_parser.add_argument("file", nargs='+', help="Encrypted .enc file(s) to decrypt")
    dec_parser.add_argument("--password", required=True, help="Decryption password")
    dec_parser.add_argument("--force", action="store_true", help="Allow overwriting if file already exists")
    dec_parser.add_argument("--output-dir", help="Output directory for decrypted files")

    args = parser.parse_args()

    if args.command == "encrypt":
        for f in args.file:
            try:
                enc_name = encrypt_file(f, args.password, force=args.force)
                log(f"✔ Encrypted: {f} → {enc_name}")
            except Exception as e:
                log(f"❌ Failed to encrypt {f}: {str(e)}")

    elif args.command == "decrypt":
        for f in args.file:
            try:
                dec_name = decrypt_file(f, args.password, force=args.force, output_dir=args.output_dir)
                log(f"✔ Decrypted: {f} → {dec_name}")
            except Exception as e:
                log(f"❌ Failed to decrypt {f}: {str(e)}")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
