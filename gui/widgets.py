import os
from PyQt5.QtWidgets import (QDialog, QFormLayout, QLabel, QLineEdit,
                             QPushButton, QInputDialog, QMessageBox,
                             QTreeWidget, QTreeWidgetItem, QVBoxLayout, QHBoxLayout,
                             QFileDialog)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from pathlib import Path
from datetime import datetime
import platform # To detect OS for drive listing (needed if browsing outside CWD)

# Import security_manager from shared module, as it's a global dependency for security operations
from shared.security_manager import SecurityManager
from shared.config import CONFIG_DIR # Assuming CONFIG_DIR is needed for SecurityManager init

# Initialize security_manager, as it's a critical dependency for SecuritySettingsDialog
security_manager = SecurityManager(CONFIG_DIR)


class FileBrowser(QTreeWidget):
    """
    A custom QTreeWidget for displaying files and folders with size and modification date.
    It provides methods to format file sizes and timestamps.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Name", "Size", "Modified"])
        self.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.setColumnWidth(0, 300)  # Name column
        self.setColumnWidth(1, 100)  # Size column
        self.setColumnWidth(2, 150)  # Modified column
        
    def format_size(self, size):
        """Format file size in human readable format (KB, MB, GB, etc.)"""
        if size is None:
            return ""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
        
    def format_date(self, timestamp):
        """Format timestamp to a human-readable date and time string"""
        if timestamp is None:
            return ""
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


class SecuritySettingsDialog(QDialog):
    """
    A dialog for viewing security settings and changing the security code.
    It interacts directly with the global security_manager instance.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Security Settings")
        self.setFixedSize(400, 200) # Fixed size for simplicity
        
        layout = QFormLayout()

        self.hash_label = QLabel("Stored Hash (Base64):")
        self.hash_value = QLineEdit()
        self.hash_value.setReadOnly(True)
        self.hash_value.setPlaceholderText("Not set or unavailable")
        layout.addRow(self.hash_label, self.hash_value)

        # Get and display the current hash
        stored_hash = security_manager.get_stored_hash_b64()
        if stored_hash:
            self.hash_value.setText(stored_hash)
        
        self.change_password_button = QPushButton("Change Security Code")
        self.change_password_button.clicked.connect(self._change_password_dialog)
        layout.addRow(self.change_password_button)

        self.setLayout(layout)

    def _change_password_dialog(self):
        """Handles the 'Change Security Code' process, prompting for old and new codes."""
        if not security_manager.is_initialized():
            QMessageBox.warning(self, "Security", "Security is not initialized. Please restart to set it up.")
            return

        old_password, ok = QInputDialog.getText(self, "Change Security Code",
                                                 "Enter your OLD security code:",
                                                 QLineEdit.Password)
        if not ok or not old_password:
            return

        # Verify old password
        if not security_manager.load_security(old_password): # Temporarily load to verify
            QMessageBox.warning(self, "Incorrect Old Code", "The old security code you entered is incorrect.")
            return

        # Prompt for new password
        while True:
            new_password, ok_new = QInputDialog.getText(self, "Change Security Code",
                                                        "Enter your NEW security code:",
                                                        QLineEdit.Password)
            if not ok_new or not new_password:
                QMessageBox.warning(self, "Invalid New Code", "New security code cannot be empty.")
                return

            confirm_password, ok_confirm = QInputDialog.getText(self, "Change Security Code",
                                                                "Confirm your NEW security code:",
                                                                QLineEdit.Password)
            if not ok_confirm or new_password != confirm_password:
                QMessageBox.warning(self, "Mismatch", "New security codes do not match.")
                continue
            break

        if security_manager.change_password(old_password, new_password):
            QMessageBox.information(self, "Success", "Security code changed successfully!")
            # Update displayed hash after successful change
            self.hash_value.setText(security_manager.get_stored_hash_b64())
        else:
            QMessageBox.critical(self, "Error", "Failed to change security code. Please check logs.")


class UploadDialog(QDialog):
    """
    A dialog for selecting the destination path for file/folder uploads.
    Now allows arbitrary absolute paths.
    """
    def __init__(self, parent=None, is_folder=False):
        super().__init__(parent)
        self.setWindowTitle("Upload to Peer")
        self.is_folder = is_folder # Not directly used in this dialog's logic, but passed for context
        
        layout = QVBoxLayout()
        
        # Destination path input
        path_layout = QHBoxLayout()
        self.path_label = QLabel("Destination Path:")
        self.path_edit = QLineEdit()
        # Default to a sensible starting point (e.g., user's home or current CWD)
        self.path_edit.setText(str(Path.home().resolve()))  
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_destination)
        
        path_layout.addWidget(self.path_label)
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.browse_button)
        
        # Buttons (Upload/Cancel)
        button_layout = QHBoxLayout()
        self.upload_button = QPushButton("Upload")
        self.upload_button.clicked.connect(self.accept) # Accept the dialog
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject) # Reject the dialog
        
        button_layout.addWidget(self.upload_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(path_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def browse_destination(self):
        """Opens a file dialog to select a destination directory."""
        path = QFileDialog.getExistingDirectory(
            self, "Select Destination Directory", self.path_edit.text()
        )
        if path:
            self.path_edit.setText(path)
    
    def get_destination_path(self):
        """Returns the selected destination path from the QLineEdit."""
        return self.path_edit.text()
