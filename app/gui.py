from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QLabel, QMessageBox, QInputDialog, QTextEdit,
    QProgressBar, QCheckBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
import os
import mimetypes
import csv
from app.crypto_utils import encrypt_file, decrypt_file
from app.metadata_utils import export_metadata, load_metadata

class SecureFileVaultApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Vault")
        self.setGeometry(100, 100, 600, 500)
        self.setAcceptDrops(True)

        self.layout = QVBoxLayout()

        self.status_label = QLabel("Select an action:")
        self.layout.addWidget(self.status_label)

        self.preview_label = QLabel()
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.preview_label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.layout.addWidget(self.log_area)

        self.progress_bar = QProgressBar()
        self.layout.addWidget(self.progress_bar)

        self.overwrite_checkbox = QCheckBox("Allow overwrite")
        self.layout.addWidget(self.overwrite_checkbox)

        self.btn_encrypt = QPushButton("Encrypt Files")
        self.btn_encrypt.clicked.connect(self.encrypt_files)
        self.layout.addWidget(self.btn_encrypt)

        self.btn_decrypt = QPushButton("Decrypt File(s)")
        self.btn_decrypt.clicked.connect(self.decrypt_file)
        self.layout.addWidget(self.btn_decrypt)

        self.btn_export = QPushButton("Export Metadata to CSV")
        self.btn_export.clicked.connect(self.export_metadata)
        self.layout.addWidget(self.btn_export)

        self.setLayout(self.layout)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        if files:
            password, ok = QInputDialog.getText(self, "Password", "Enter encryption password:")
            confirm, ok2 = QInputDialog.getText(self, "Confirm Password", "Re-enter password:")
            if not ok or not ok2 or password != confirm:
                QMessageBox.critical(self, "Error", "Passwords do not match.")
                return
            self.encrypt_files_from_list(files, password)

    def encrypt_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Encrypt")
        if not files:
            return
        password, ok = QInputDialog.getText(self, "Password", "Enter encryption password:")
        confirm, ok2 = QInputDialog.getText(self, "Confirm Password", "Re-enter password:")
        if not ok or not ok2 or password != confirm:
            QMessageBox.critical(self, "Error", "Passwords do not match.")
            return
        self.encrypt_files_from_list(files, password)

    def encrypt_files_from_list(self, files, password):
        self.progress_bar.setMaximum(len(files))
        self.progress_bar.setValue(0)
        for idx, file in enumerate(files):
            try:
                enc_name = encrypt_file(file, password, force=self.overwrite_checkbox.isChecked())
                size_kb = round(os.path.getsize(file) / 1024, 2)
                self.log_area.append(f"✔ Encrypted: {file} ({size_kb} KB) → {enc_name}")
                self.show_preview(file)
            except Exception as e:
                self.log_area.append(f"❌ Failed: {file} ({str(e)})")
            self.progress_bar.setValue(idx + 1)

    def decrypt_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Encrypted Files")
        if not files:
            return

        password, ok = QInputDialog.getText(self, "Password", "Enter decryption password:")
        if not ok or not password:
            return

        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not output_dir:
            return

        self.progress_bar.setMaximum(len(files))
        self.progress_bar.setValue(0)
        decrypted_paths = []

        for idx, file in enumerate(files):
            try:
                dec_name = decrypt_file(file, password, force=self.overwrite_checkbox.isChecked(), output_dir=output_dir)
                full_dec_path = os.path.join(output_dir, dec_name)
                decrypted_paths.append(full_dec_path)
                size_kb = round(os.path.getsize(file) / 1024, 2)
                self.log_area.append(f"✔ Decrypted: {file} ({size_kb} KB) → {dec_name}")
                self.show_preview(full_dec_path)
            except Exception as e:
                self.log_area.append(f"❌ Failed: {file} ({str(e)})")
            self.progress_bar.setValue(idx + 1)

        export_csv, _ = QFileDialog.getSaveFileName(self, "Export Decrypted File Paths", "decrypted_files.csv", "CSV Files (*.csv)")
        if export_csv:
            try:
                with open(export_csv, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Decrypted File Paths"])
                    for path in decrypted_paths:
                        writer.writerow([path])
                QMessageBox.information(self, "Success", "Decrypted paths exported.")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))

    def show_preview(self, filepath):
        mime, _ = mimetypes.guess_type(filepath)
        if mime and mime.startswith("image"):
            pixmap = QPixmap(filepath)
            if not pixmap.isNull():
                self.preview_label.setPixmap(pixmap.scaled(100, 100, Qt.KeepAspectRatio))
        else:
            self.preview_label.clear()

    def export_metadata(self):
        try:
            metadata = load_metadata()
            output_path, _ = QFileDialog.getSaveFileName(self, "Save Metadata CSV", "metadata.csv", "CSV Files (*.csv)")
            if output_path:
                try:
                    export_metadata(metadata, output_path)
                    QMessageBox.information(self, "Success", "Metadata exported successfully.")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export metadata: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export metadata: {str(e)}")
