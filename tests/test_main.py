# tests/test_main.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
import shutil
import json
from main import encrypt_file, decrypt_file, load_metadata, derive_key
import csv
from utils.export_metadata import export_metadata_to_csv

TEST_DIR = "test_files"
ENCRYPTED_DIR = "encrypted_files"
META_FILE = "metadata.json"

class TestSecureFileStorage(unittest.TestCase):
    def setUp(self):
        os.makedirs(TEST_DIR, exist_ok=True)
        os.makedirs(ENCRYPTED_DIR, exist_ok=True)
        self.test_file = os.path.join(TEST_DIR, "sample.txt")
        self.password = "strongpassword"
        with open(self.test_file, "w") as f:
            f.write("This is a test file.")

    def tearDown(self):
        shutil.rmtree(TEST_DIR)
        shutil.rmtree(ENCRYPTED_DIR)
        if os.path.exists(META_FILE):
            os.remove(META_FILE)
        for f in os.listdir():
            if f.startswith("decrypted_"):
                os.remove(f)

    def test_encryption_and_metadata(self):
        encrypt_file(self.test_file, self.password)
        metadata = load_metadata()
        self.assertTrue(len(metadata) > 0)
        encrypted_name = next(iter(metadata))
        self.assertTrue(os.path.exists(os.path.join(ENCRYPTED_DIR, encrypted_name)))
        self.assertIn("sha256", metadata[encrypted_name])

    def test_decryption_success(self):
        encrypt_file(self.test_file, self.password)
        metadata = load_metadata()
        encrypted_name = next(iter(metadata))
        decrypt_file(encrypted_name, self.password)
        original_name = metadata[encrypted_name]["original_name"]
        self.assertTrue(os.path.exists(f"decrypted_{original_name}"))

    def test_decryption_with_wrong_password(self):
        encrypt_file(self.test_file, self.password)
        metadata = load_metadata()
        encrypted_name = next(iter(metadata))
        decrypt_file(encrypted_name, "wrongpassword")
        original_name = metadata[encrypted_name]["original_name"]
        self.assertFalse(os.path.exists(f"decrypted_{original_name}"))

    def test_key_derivation_consistency(self):
        salt = os.urandom(16)
        key1 = derive_key(self.password, salt)
        key2 = derive_key(self.password, salt)
        self.assertEqual(key1, key2)

    def test_file_tampering_detection(self):
        encrypt_file(self.test_file, self.password)
        metadata = load_metadata()
        encrypted_name = next(iter(metadata))
        enc_path = os.path.join(ENCRYPTED_DIR, encrypted_name)

        # Tamper with encrypted file
        with open(enc_path, 'rb+') as f:
            content = bytearray(f.read())
            content[10] = (content[10] + 1) % 256  # Modify a byte
            f.seek(0)
            f.write(content)

        # Attempt decryption
        decrypt_file(encrypted_name, self.password)
        original_name = metadata[encrypted_name]["original_name"]
        self.assertFalse(os.path.exists(f"decrypted_{original_name}"))

    def test_export_metadata_to_csv(self):
        encrypt_file(self.test_file, self.password)
        export_metadata_to_csv('metadata.json', 'metadata.csv')

        self.assertTrue(os.path.exists("metadata.csv"))

        with open("metadata.csv", newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)

        self.assertGreater(len(rows), 0)
        self.assertIn("encrypted_name", rows[0])
        self.assertIn("original_name", rows[0])
        self.assertIn("timestamp", rows[0])
        self.assertIn("sha256", rows[0])
        
if __name__ == '__main__':
    unittest.main()
