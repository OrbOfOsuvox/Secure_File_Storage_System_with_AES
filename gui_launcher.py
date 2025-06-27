# gui_launcher.py
from PyQt5.QtWidgets import QApplication
from app.gui import SecureFileVaultApp
import sys

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureFileVaultApp()
    window.show()
    sys.exit(app.exec_())
