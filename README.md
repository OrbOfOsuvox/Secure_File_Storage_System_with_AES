# 🔐 Secure File Storage System with AES-256 Encryption

A robust Python application to encrypt and decrypt files locally using AES-256 encryption. It offers both a Command-Line Interface (CLI) and a user-friendly PyQt5-based GUI. Supports metadata logging, tamper detection, bulk file handling, and secure logging.

---

## 📌 Features

- 🔒 AES-256 (Fernet-based) encryption & decryption
- 🧾 Metadata logging (file name, timestamp, SHA-256 hash)
- 🛡️ File integrity verification (tampering detection)
- 📦 CLI & GUI (PyQt5) support
- 📂 Bulk file encryption & decryption
- 🧠 Filename obfuscation with UUID + SHA256
- 📋 Export metadata and decrypted file paths to CSV
- 📊 Drag & drop GUI with progress bar
- 🚫 Overwrite prevention with `--force` option
- 🪵 Secure logging to `secure_vault.log`

---

## 🛠 Tools & Libraries

- Python 3.11+
- PyQt5 (GUI)
- cryptography (AES-256 encryption)
- hashlib, base64
- argparse (CLI)
- JSON & CSV (metadata handling)
- FPDF (PDF report generation)

---

## 🗂️ Project Structure

# 🔐 Secure File Storage System with AES-256 Encryption

A robust Python application to encrypt and decrypt files locally using AES-256 encryption. It offers both a Command-Line Interface (CLI) and a user-friendly PyQt5-based GUI. Supports metadata logging, tamper detection, bulk file handling, and secure logging.

---

## 📌 Features

- 🔒 AES-256 (Fernet-based) encryption & decryption
- 🧾 Metadata logging (file name, timestamp, SHA-256 hash)
- 🛡️ File integrity verification (tampering detection)
- 📦 CLI & GUI (PyQt5) support
- 📂 Bulk file encryption & decryption
- 🧠 Filename obfuscation with UUID + SHA256
- 📋 Export metadata and decrypted file paths to CSV
- 📊 Drag & drop GUI with progress bar
- 🚫 Overwrite prevention with `--force` option
- 🪵 Secure logging to `secure_vault.log`

---

## 🛠 Tools & Libraries

- Python 3.11+
- PyQt5 (GUI)
- cryptography (AES-256 encryption)
- hashlib, base64
- argparse (CLI)
- JSON & CSV (metadata handling)
- FPDF (PDF report generation)

---

## 🗂️ Project Structure

```bash
Secure_File_Storage_System_with_AES/
├── main.py # CLI logic
├── gui_launcher.py # PyQt5 GUI entry point
├── app/
│ ├── crypto_utils.py # Encryption/Decryption logic
│ ├── metadata_utils.py # Metadata handling
│ └── gui.py # PyQt5 GUI logic
├── tests/
│ └── test_main.py # Pytest unit tests
├── metadata.json # Stored metadata (auto-generated)
├── secure_vault.log # Log file (auto-generated)
```

---

## 🚀 Getting Started

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Run GUI

```bash
python gui_launcher.py
```

### 3. Run CLI
### Encrypt a file:

```bash
python main.py encrypt sample.txt --password yourpassword
```

### Decrypt a file:

```bash
python main.py decrypt encrypted_files/abc123.enc --password yourpassword
```

### Optional Flags:

--force: Overwrite output files if they exist

--output-dir path/to/folder: Set output folder for decrypted files

### ✅ Run Tests

```bash
pytest tests/test_main.py
```

## 📤 Export Features
- Export metadata to CSV via GUI
- Log all encryption/decryption attempts in secure_vault.log
- Export decrypted file paths

## 🔐 Security Notes
- Uses PBKDF2 with SHA-256 for secure key derivation
- Salt is randomly generated for every encryption
- Obfuscated filenames via SHA-256 + timestamp
- File integrity is verified using SHA-256 hash

## 📦 Build Executable (Optional)
### Use PyInstaller to package:

```bash
pyinstaller main.py --name SecureFileVault --onefile
```

## 📃 License
MIT License – Use freely with credit.
