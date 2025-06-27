import os
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from app.metadata_utils import load_metadata, save_metadata


STORAGE_DIR = "encrypted_files" 
os.makedirs(STORAGE_DIR, exist_ok=True)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filepath, password, force=False):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    hash_digest = hashlib.sha256(data).hexdigest()
    timestamp = datetime.now().isoformat()

    filename = os.path.basename(filepath)
    obfuscated_name = hashlib.sha256((filename + timestamp).encode()).hexdigest()
    encrypted_filename = f"{obfuscated_name}.enc"
    encrypted_path = os.path.join(STORAGE_DIR, encrypted_filename)

    if os.path.exists(encrypted_path) and not force:
        raise FileExistsError(f"{encrypted_filename} already exists. Use --force to overwrite.")

    with open(encrypted_path, 'wb') as f:
        f.write(salt + encrypted_data)

    metadata = load_metadata()
    metadata[encrypted_filename] = {
        "original_name": filename,
        "timestamp": timestamp,
        "sha256": hash_digest
    }
    save_metadata(metadata)

    return encrypted_filename

def decrypt_file(encrypted_filepath, password, force=False, output_dir=None):
    if not os.path.exists(encrypted_filepath):
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_filepath}")

    encrypted_filename = os.path.basename(encrypted_filepath)
    with open(encrypted_filepath, 'rb') as f:
        content = f.read()

    salt, encrypted_data = content[:16], content[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)

    decrypted_data = fernet.decrypt(encrypted_data)

    metadata = load_metadata()
    if encrypted_filename not in metadata:
        raise ValueError("No metadata found for this file.")

    expected_hash = metadata[encrypted_filename]["sha256"]
    actual_hash = hashlib.sha256(decrypted_data).hexdigest()
    if expected_hash != actual_hash:
        raise ValueError("Hash mismatch! File may have been tampered with.")

    original_name = metadata[encrypted_filename]['original_name']
    output_name = f"decrypted_{original_name}"
    output_path = os.path.join(output_dir or ".", output_name)

    if os.path.exists(output_path) and not force:
        raise FileExistsError(f"{output_name} already exists. Use --force to overwrite.")

    with open(output_path, 'wb') as f:
        f.write(decrypted_data)

    return output_path


