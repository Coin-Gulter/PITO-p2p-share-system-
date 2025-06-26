import time
import os
import sys
import requests
import threading
import json
from pathlib import Path
from datetime import datetime
import platform # To detect OS for drive listing
import base64
import urllib.parse

from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel,
                             QPushButton, QListWidget, QListWidgetItem, QFileDialog,
                             QHBoxLayout, QMessageBox, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QCheckBox, QProgressBar, QLineEdit, QToolBar,
                             QDialog, QProgressDialog, QFormLayout, QInputDialog)
from PyQt5.QtCore import QTimer, Qt, QSize, pyqtSignal, QThread, QProcess, QObject, QEvent
from PyQt5.QtGui import QIcon, QFont

# Import separated GUI components
from gui.widgets import FileBrowser, SecuritySettingsDialog, UploadDialog
from gui.workers import UploadWorker, DownloadProcess, TokenFetcher # ProgressFileReader is utility for workers removed from here

# Import shared backend components
from shared.discovery import PeerDiscovery
from shared.config import settings, CONFIG_DIR
from shared.security_manager import SecurityManager
from shared.logging_config import setup_logger

# Set up logger for this module
logger = setup_logger(__name__)

# Global Security Manager instance (from main.py, assuming it's passed or set up)
# security_manager = SecurityManager(CONFIG_DIR) # Re-initialize or ensure it's a global singleton in main.py


class MainWindow(QWidget):
    """
    The main application window for the P2PShare system.
    Manages peer discovery, file browsing, and file transfer operations.
    Now allows browsing of the entire filesystem for authorized peers.
    """
    def __init__(self, security_manager: SecurityManager):
        super().__init__()
        logger.info("Initializing main window (MainWindow.__init__ start)")
        try:
            self.setWindowTitle(settings.device_id)
            self.setGeometry(100, 100, 1200, 800)

            # Initialize core components
            self.discovery = PeerDiscovery(port=settings.http_port, device_id=settings.device_id)

            # security manager
            self.security_manager = security_manager
            
            # State management for peers and operations
            self.peer_tokens = {} # Stores tokens for peers: {ip:port_str: token}
            self.last_peer_check = {} # Stores last check time for peers: {ip:port_str: datetime_obj}
            self.peer_check_timeout = 60 # Seconds to consider token valid before re-fetching
            self.offline_peers = set() # Stores peer_text of offline peers
            self.last_peer_update = datetime.now() # Last time peer list was updated from discovery
            self.peer_update_interval = 5 # Seconds between peer list updates from discovery
            
            self._operation_lock = threading.RLock() # Reentrant Lock for multi-threaded state access
            self.current_download = None # Reference to active DownloadProcess
            self.current_worker = None # Reference to active UploadWorker
            self.current_progress = None # Reference to active QProgressDialog
            self.is_operation_cancelled = False # Flag for user-initiated cancellation
            self.active_token_fetchers = {} # Tracks active TokenFetcher threads to prevent duplicates
            
            # Peer connection health tracking
            self.peer_connection_attempts = {} # {peer_text: count}
            self.peer_last_success = {} # {peer_text: datetime}
            self.peer_retry_delay = 30 # Seconds to wait before retrying failed peer token fetch
            self.max_connection_attempts = 5 # Maximum number of immediate token fetch attempts
            
            # Setup timers
            self.peer_health_check_timer = QTimer(self)
            self.peer_health_check_timer.timeout.connect(self._check_peer_health)
            logger.info("MainWindow: Peer health check timer created (will start deferred).")

            self._ui_update_timer = QTimer(self)
            self._ui_update_timer.timeout.connect(self._process_ui_updates)
            self._ui_update_timer.start(250) # Update UI at 4 FPS for responsiveness
            logger.info("MainWindow: _ui_update_timer started.")
            
            self._cleanup_timer = QTimer(self)
            self._cleanup_timer.setSingleShot(True) # Runs once
            # self._cleanup_timer.timeout.connect(self._delayed_cleanup)
            logger.info("MainWindow: _cleanup_timer created.")

            self._cleanup_in_progress = False # Reset flag
            
            self.timer = QTimer(self) # Timer for updating the peer list from discovery
            self.timer.timeout.connect(self.update_peer_list)
            logger.info("MainWindow: Peer list update timer created (will start deferred).")
            
            # Initial UI setup
            logger.info("MainWindow: Calling _init_ui()...")
            self._init_ui()
            logger.info("MainWindow: _init_ui() completed.")
            
            # Start discovery thread
            self._discovery_running = True # Flag to control discovery thread's loop
            self.discovery_thread = threading.Thread(target=self._run_discovery, daemon=True)
            self.discovery_thread.start()
            logger.info("Started peer discovery thread.")

            # Initial state for file browser - now starts at system root '/'
            self.current_peer = None
            self.current_path = "~" # Start at system root or drive list
            self.path_history = []

            # Defer initial tasks to ensure main window is fully initialized and shown
            QTimer.singleShot(100, self._start_initial_tasks)
            
            logger.info("Initializing main window (MainWindow.__init__ end)")
        except Exception as e:
            logger.critical(f"Error during MainWindow initialization: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "Initialization Error", f"An error occurred during window setup: {str(e)}")
            raise # Re-raise to propagate to main()

    def _start_initial_tasks(self):
        """Method to start tasks that rely on full MainWindow initialization and showing."""
        logger.info("MainWindow: Starting deferred initial tasks...")
        self.update_peer_list() # Perform initial peer list update
        logger.info("MainWindow: Initial update_peer_list() completed.")
        self.timer.start(self.peer_update_interval * 1000) # Start periodic peer list updates
        logger.info("MainWindow: Periodic peer list update timer started.")
        self.peer_health_check_timer.start(10000) # Start periodic health checks (every 10 seconds)
        logger.info("MainWindow: Periodic peer health check timer started.")

    def _run_discovery(self):
        """
        Runs the PeerDiscovery service in a separate thread.
        This method blocks until unregister is called on the discovery instance.
        """
        try:
            logger.info("Discovery thread: Starting discovery.run()...")
            self.discovery.run()
            logger.info("Discovery thread: discovery.run() exited.")
        except Exception as e:
            logger.error(f"Discovery thread error: {str(e)}", exc_info=True)
            if self._discovery_running: # Only show message if still expected to be running
                QTimer.singleShot(0, lambda: QMessageBox.warning(
                    self, "Discovery Error",
                    "Peer discovery service encountered an error. Some features may be limited."
                ))
        finally:
            logger.info("Discovery thread exiting.")
            self._discovery_running = False # Ensure flag is set to False upon exit

    def _init_ui(self):
        """Initializes the user interface elements and their layout."""
        logger.info("MainWindow._init_ui() start.")
        try:
            # Main layout setup
            self.layout = QVBoxLayout(self)
            self.layout.setSpacing(10)
            self.layout.setContentsMargins(10, 10, 10, 10)
            
            # Splitter for left (peers) and right (files) panels
            self.splitter = QSplitter(Qt.Horizontal)
            
            # Left Panel: Peer List
            self.peers_panel = QWidget()
            self.peers_layout = QVBoxLayout(self.peers_panel)
            self.peers_layout.setSpacing(5)
            
            self.peer_status = QLabel("No peers discovered")
            self.peer_status.setStyleSheet("color: gray; font-weight: bold;")
            self.peers_layout.addWidget(self.peer_status)
            
            self.peers_list = QListWidget()
            self.peers_list.setStyleSheet("""
                QListWidget {
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    padding: 2px;
                    background-color: #f9f9f9;
                }
                QListWidget::item {
                    padding: 4px;
                    border-bottom: 1px solid #eee; /* Subtle separator */
                }
                QListWidget::item:selected {
                    background-color: #e0e0e0; /* Light gray selection */
                    color: black;
                }
            """)
            self.peers_list.itemClicked.connect(self.on_peer_selected)
            self.peers_layout.addWidget(self.peers_list)

            self.refresh_button = QPushButton("Refresh Peer List")
            self.refresh_button.setStyleSheet("""
                QPushButton {
                    padding: 6px 12px;
                    background-color: #f0f0f0;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                }
                QPushButton:pressed {
                    background-color: #d0d0d0;
                }
            """)
            self.refresh_button.clicked.connect(self.update_peer_list)
            self.peers_layout.addWidget(self.refresh_button)

            self.security_settings_button = QPushButton("Security Settings")
            self.security_settings_button.setStyleSheet("""
                QPushButton {
                    padding: 6px 12px;
                    background-color: #e6e6e6;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #d6d6d6;
                }
                QPushButton:pressed {
                    background-color: #c6c6c6;
                }
            """)
            self.security_settings_button.clicked.connect(self._show_security_settings_dialog)
            self.peers_layout.addWidget(self.security_settings_button)

            self.splitter.addWidget(self.peers_panel)
            
            # Right Panel: File Browser
            self.files_panel = QWidget()
            self.files_layout = QVBoxLayout(self.files_panel)
            self.files_layout.setSpacing(10)
            
            # Navigation bar for file browser
            self.nav_layout = QHBoxLayout()
            self.back_button = QPushButton("← Back")
            self.back_button.setStyleSheet("""
                QPushButton {
                    padding: 5px 10px;
                    background-color: #f0f0f0;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }
                QPushButton:hover { background-color: #e0e0e0; }
                QPushButton:pressed { background-color: #d0d0d0; }
            """)
            self.back_button.clicked.connect(self.navigate_back)
            
            self.path_edit = QLineEdit()
            self.path_edit.setPlaceholderText("Enter path or browse...")
            self.path_edit.setStyleSheet("""
                QLineEdit {
                    padding: 5px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }
            """)
            self.path_edit.returnPressed.connect(self.navigate_to_path)
            
            self.refresh_files_button = QPushButton("Refresh")
            self.refresh_files_button.setStyleSheet("""
                QPushButton {
                    padding: 5px 10px;
                    background-color: #f0f0f0;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }
                QPushButton:hover { background-color: #e0e0e0; }
                QPushButton:pressed { background-color: #d0d0d0; }
            """)
            self.refresh_files_button.clicked.connect(self.refresh_current_directory)
            
            self.nav_layout.addWidget(self.back_button)
            self.nav_layout.addWidget(self.path_edit, 1) # Give path edit more space
            self.nav_layout.addWidget(self.refresh_files_button)
            self.files_layout.addLayout(self.nav_layout)
            
            # File browser tree
            self.files_tree = FileBrowser()
            self.files_tree.setStyleSheet("""
                QTreeWidget {
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    background-color: #f9f9f9;
                }
                QTreeWidget::item {
                    padding: 4px;
                }
                QTreeWidget::item:selected {
                    background-color: #e0e0e0;
                    color: black;
                }
            """)
            self.files_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
            self.files_layout.addWidget(self.files_tree)
            
            # File operation buttons (Download/Upload)
            self.files_buttons = QHBoxLayout()
            self.download_button = QPushButton("Download Selected")
            self.upload_button = QPushButton("Upload File/Folder") # Consolidated button
            
            for button in [self.download_button, self.upload_button]:
                button.setStyleSheet("""
                    QPushButton {
                        padding: 8px 15px;
                        background-color: #4CAF50; /* Green */
                        color: white;
                        border: none;
                        border-radius: 4px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #45a049;
                    }
                    QPushButton:pressed {
                        background-color: #3e8e41;
                    }
                    QPushButton:disabled {
                        background-color: #cccccc;
                        color: #666666;
                    }
                """)
            
            self.download_button.clicked.connect(self.download_selected_files)
            self.upload_button.clicked.connect(self.upload_file_to_peer)

            self.files_buttons.addWidget(self.download_button)
            self.files_buttons.addWidget(self.upload_button)
            self.files_layout.addLayout(self.files_buttons)
            
            # Progress bar for transfers
            self.progress_bar = QProgressBar()
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    text-align: center;
                    height: 25px; /* Slightly taller */
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #4CAF50;
                    border-radius: 3px;
                }
            """)
            self.progress_bar.setVisible(False) # Hidden by default
            self.files_layout.addWidget(self.progress_bar)
            
            self.splitter.addWidget(self.peers_panel)
            self.splitter.addWidget(self.files_panel)
            self.splitter.setSizes([250, 950]) # Initial panel sizes
            self.layout.addWidget(self.splitter)
            
            self.setLayout(self.layout)
            logger.info("MainWindow._init_ui() end.")
        except Exception as e:
            logger.critical(f"Error during MainWindow UI initialization (_init_ui): {str(e)}", exc_info=True)
            raise # Re-raise to propagate

    def _show_security_settings_dialog(self):
        """Opens the dialog for security settings."""
        dialog = SecuritySettingsDialog(self, security_manager=self.security_manager)
        dialog.exec_()

    def navigate_back(self):
        """Navigate to the previous directory or up to the drive list/system root."""
        if self.path_history:
            self.current_path = self.path_history.pop()
            self.refresh_current_directory()
        elif self.current_path != "/": # If at a drive root (e.g. C:/) and no history, go to "/"
            self.current_path = "/"
            self.refresh_current_directory()

    def navigate_to_path(self):
        """Navigate to the path entered in the path edit field."""
        path = self.path_edit.text()
        if path:
            # Ensure the path starts with a '/' if it's not a Windows drive letter
            if platform.system() == "Windows" and len(path) == 2 and path[1] == ':' and path[0].isalpha():
                # This looks like a drive root, e.g., "C:"
                normalized_path = f"{path.upper()}/"
            elif not path.startswith('/'):
                normalized_path = '/' + path
            else:
                normalized_path = path

            # Only append to history if actual path changes
            if normalized_path != self.current_path:
                self.path_history.append(self.current_path)
                self.current_path = normalized_path
                self.refresh_current_directory()

    def on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        """
        Handles double-clicks on items in the file browser.
        Navigates into directories. For files, triggers download if selected.
        """
        path = item.data(0, Qt.UserRole)  # Get the full path stored in UserRole
        is_dir = item.data(0, Qt.UserRole + 1) # Get if it's a directory (stored in UserRole + 1)
        
        if is_dir:
            # Only append to history if actual path changes
            if path != self.current_path:
                self.path_history.append(self.current_path)
                self.current_path = path
                self.refresh_current_directory()
        else:
            # If it's a file, trigger download if it's the only one selected
            if len(self.files_tree.selectedItems()) == 1:
                self.download_selected_files()

    def refresh_current_directory(self):
        """Updates the path edit and refreshes the file list for the current peer and path."""
        if not self.current_peer:
            self.files_tree.clear() # Clear files if no peer is selected
            self.path_edit.setText("")
            logger.warning("No peer selected to refresh current directory.")
            return
            
        self.path_edit.setText(self.current_path)
        self.refresh_peer_files()

    def refresh_peer_files(self):
        """
        Fetches and displays the file listing for the current peer and path.
        Requires a valid authentication token.
        """
        if not self.current_peer:
            logger.warning("Cannot refresh files: No peer selected.")
            QMessageBox.information(self, "No Peer Selected", "Please select a peer to browse its files.")
            return
        ip_port_str = self.current_peer.split("(")[-1].strip(")")
        ip, port_str = ip_port_str.split(":")
        port = int(port_str)
        token = self.get_peer_token(ip, port)
        if not token:
            logger.warning(f"Failed to get token for {self.current_peer}, cannot refresh files.")
            self.files_tree.clear()
            return
        if not self.security_manager.get_encryption_key():
            logger.error("Encryption key not loaded. Cannot decrypt directory listing.")
            QMessageBox.critical(self, "Security Error",
                                 "Encryption key not loaded. Cannot browse peer files securely.\n"
                                 "Please ensure you've entered the correct security code.")
            self.files_tree.clear()
            return
        try:
            items = browse_peer_path_cli(self.security_manager, ip, port, token, self.current_path)
            if items is None:
                logger.error(f"Failed to browse path '{self.current_path}' on peer {self.current_peer}.")
                QMessageBox.warning(self, "Browse Error", f"Failed to browse path '{self.current_path}' on peer.\n\nThis may be due to permissions, blacklisting, or the path not existing.")
                self.files_tree.clear()
                return
            self.update_files_tree(items)
            logger.info(f"Refreshed directory '{self.current_path}' on {self.current_peer} ({len(items)} items).")
        except Exception as e:
            logger.error(f"Unexpected error refreshing files for {self.current_peer} on path '{self.current_path}': {e}", exc_info=True)
            QMessageBox.warning(self, "Error", f"An unexpected error occurred while refreshing files:\n{e}")
            self.files_tree.clear()

    def update_files_tree(self, items: list[dict]):
        """Populates the FileBrowser QTreeWidget with the given list of file/folder items."""
        self.files_tree.clear() # Clear existing items
        
        # Sort items: directories first, then files, both alphabetically
        def sort_key(item):
            return (not item["is_dir"], item["name"].lower())
        items.sort(key=sort_key)

        for item_data in items:
            tree_item = QTreeWidgetItem([
                item_data["name"],
                self.files_tree.format_size(item_data["size"]), # Use FileBrowser's format_size method
                self.files_tree.format_date(item_data["modified"]) # Use FileBrowser's format_date method
            ])
            # Store full path and is_dir in item data for later retrieval
            tree_item.setData(0, Qt.UserRole, item_data["path"])
            tree_item.setData(0, Qt.UserRole + 1, item_data["is_dir"])
            
            # Set icon or color based on type
            if item_data["is_dir"]:
                tree_item.setForeground(0, Qt.blue) # Directories are blue
            
            self.files_tree.addTopLevelItem(tree_item)
        # self.files_tree.sortByColumn(0, Qt.AscendingOrder) # Manual sort applied, so no need for this.

    def download_selected_files(self):
        """Initiates download of selected files/folders from current peer."""
        try:
            logger.info("Starting download_selected_files()")
            if not self.current_peer:
                logger.warning("No peer selected for download")
                return
            selected_items = self.files_tree.selectedItems()
            if not selected_items:
                logger.warning("No items selected for download")
                return
            logger.debug(f"Selected items are ---- {selected_items}")
            download_dir = QFileDialog.getExistingDirectory(
                self, "Select Download Location",
                str(Path.home() / "Downloads"),
                QFileDialog.ShowDirsOnly
            )
            if not download_dir:
                logger.info("Download cancelled - no directory selected")
                return
            logger.debug("Download directory selected: %s", download_dir)
            peer_text = self.current_peer
            peer_name, ip_and_port = peer_text.split(' ')
            ip, port = ip_and_port.split(':')
            port = port.replace(")", "")
            ip = ip.replace("(", "")
            port = int(port)
            logger.debug("Peer information - IP: %s, Port: %d", ip, port)
            token = self.get_peer_token(ip, port)
            if not token:
                logger.error("Failed to get authentication token for peer %s", peer_text)
                self.handle_download_error("Failed to authenticate with peer")
                return
            # Prepare items list for download using remote metadata
            items_to_download = []
            any_folder_selected = False
            folder_item = None
            for item in selected_items:
                remote_path = self._get_item_path(item)
                is_folder = item.data(0, Qt.UserRole + 1)
                local_name = item.text(0)
                items_to_download.append([remote_path, local_name])
                if is_folder and not any_folder_selected:
                    any_folder_selected = True
                    folder_item = item
            # If any folder is selected, only download the first folder
            if any_folder_selected:
                remote_path = self._get_item_path(folder_item)
                local_name = folder_item.text(0)
                items_to_download = [[remote_path, local_name]]
                is_folder = True
            else:
                is_folder = False
            if not items_to_download:
                logger.warning("No valid items to download")
                return
            with self._operation_lock:
                if self.current_download:
                    logger.warning("Download already in progress")
                    QMessageBox.warning(self, "Download in Progress",
                                     "Please wait for the current download to finish.")
                    return
                logger.info("Creating new download process")
                self.current_download = DownloadProcess(self, security_manager=self.security_manager)
                self.current_download.progress.connect(self.update_download_progress)
                self.current_download.finished.connect(self.handle_download_finished)
                self.current_download.cleanup.connect(self.cleanup_download)
                self.current_progress = QProgressDialog("Preparing download...", "Cancel", 0, 100, self)
                self.current_progress.setWindowTitle("Downloading Files")
                self.current_progress.setWindowModality(Qt.WindowModal)
                self.current_progress.canceled.connect(self.cancel_download)
                self.current_progress.setAutoClose(False)
                self.current_progress.show()
                logger.info("Starting download process - Items: %d, Total size: %d Is folder %s",
                          len(items_to_download), sum(os.path.getsize(item[0]) if os.path.exists(item[0]) else 0 
                                                    for item in items_to_download),
                                                    is_folder
                                                    )
                self.current_download.start_download(
                    ip, port, token, items_to_download,
                    download_dir, is_folder
                )
        except Exception as e:
            logger.error("Error in download_selected_files", exc_info=True)
            self.handle_download_error(f"Download failed: {str(e)}")

    def update_download_progress(self, value: int, message: str):
        """Updates the progress dialog with current download progress."""
        try:
            logger.debug("Download progress update: %d%% - %s", value, message)
            if self.current_progress:
                self.current_progress.setValue(value)
                self.current_progress.setLabelText(message)
        except Exception as e:
            logger.error("Error updating download progress", exc_info=True)

    def handle_download_finished(self, success: bool, message: str):
        """Handles completion of download process."""
        try:
            if success:
                logger.info("Download completed successfully: %s", message)
            else:
                logger.error("Download failed: %s", message)
                
            if self.current_progress:
                if success:
                    self.current_progress.setLabelText("Download completed successfully!")
                else:
                    self.current_progress.setLabelText(f"Download failed: {message}")
                self.current_progress.setValue(100)
                
            # Schedule cleanup after a short delay
            self._schedule_cleanup()
            
        except Exception as e:
            logger.error("Error handling download completion", exc_info=True)

    def cleanup_download(self):
        """Cleans up resources after download completion."""
        try:
            logger.info("Starting download cleanup")
            with self._operation_lock:
                if self.current_progress:
                    logger.debug("Closing progress dialog")
                    self.current_progress.close()
                    self.current_progress = None

                if self.current_download:
                    logger.debug("Cleaning up download process")
                    self.current_download.deleteLater()
                    self.current_download = None

                self.is_operation_cancelled = False
                logger.info("Download cleanup completed")
                
        except Exception as e:
            logger.error("Error during download cleanup", exc_info=True)

    def cancel_download(self):
        """Cancels the current download operation."""
        try:
            logger.info("User requested download cancellation")
            with self._operation_lock:
                self.is_operation_cancelled = True
                if self.current_download:
                    logger.debug("Stopping current download process")
                    self.current_download.stop()
                    
                if self.current_progress:
                    logger.debug("Updating progress dialog for cancellation")
                    self.current_progress.setLabelText("Cancelling download...")
                    self.current_progress.setValue(100)
                    
            logger.info("Download cancellation initiated")
            
        except Exception as e:
            logger.error("Error cancelling download", exc_info=True)

    def upload_file_to_peer(self):
        """
        Prompts the user to select a file or folder and uploads it to the selected peer.
        Launches an UploadWorker in a separate thread.
        """
        # Reset cancellation flag for new operation
        with self._operation_lock:
            self.is_operation_cancelled = False
            
        selected_peer_item = self.peers_list.currentItem()
        if not selected_peer_item:
            logger.warning("Upload attempted without selecting a peer.")
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer to upload to.")
            return

        # Pre-check: Ensure encryption key is loaded before initiating upload
        if self.security_manager.get_encryption_key() is None:
            QMessageBox.critical(self, "Security Error",
                                 "Encryption key not loaded. Cannot upload/encrypt files securely.\n"
                                 "Please ensure you've entered the correct security code on startup.")
            logger.error("Upload blocked: Encryption key not loaded.")
            return

        peer_text = selected_peer_item.text()
        logger.info(f"Selected peer for upload: {peer_text}")
        ip_port_str = peer_text.split("(")[-1].strip(")")
        ip, port_str = ip_port_str.split(":")
        port = int(port_str)
        
        # Get token for the peer; this might block or show a warning
        token = self.get_peer_token(ip, port)
        if not token:
            logger.warning("Upload aborted due to token failure.")
            return
        logger.debug("Successfully obtained token for upload.")

        # Ask user what to upload (file or folder)
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Question)
        msg_box.setWindowTitle("Select Upload Type")
        msg_box.setText("Would you like to upload a single file or an entire folder?")
        msg_box.setInformativeText("Click 'Upload File' for a single file.\nClick 'Upload Folder' for a folder and its contents.")

        upload_file_button = msg_box.addButton("Upload File", QMessageBox.AcceptRole)
        upload_folder_button = msg_box.addButton("Upload Folder", QMessageBox.RejectRole)
        msg_box.setStandardButtons(QMessageBox.Cancel)
        msg_box.setDefaultButton(upload_file_button)
        msg_box.exec_()
        
        clicked_button = msg_box.clickedButton()

        is_folder = False
        source_path = None
        if clicked_button == upload_folder_button:
            is_folder = True
            source_path = QFileDialog.getExistingDirectory(
                self, "Select Folder to Upload (All contents will be included)"
            )
        elif clicked_button == upload_file_button:
            source_path, _ = QFileDialog.getOpenFileName(
                self, "Select File to Upload"
            )
        elif clicked_button == msg_box.button(QMessageBox.Cancel): # Explicitly check for Cancel button
            logger.info("Upload cancelled by user: Type selection dialog closed.")
            return # Exit the upload function early

        if not source_path:
            logger.info("Upload cancelled by user: No source file/folder selected.")
            return
        logger.info(f"Selected source for upload: {source_path}")

        # Get destination path on peer - now allows full absolute paths
        dialog = UploadDialog(self, is_folder)
        # Set initial path in dialog to current browsed path
        dialog.path_edit.setText(self.current_path)
        if dialog.exec_() != QDialog.Accepted: # Use QDialog.Accepted enum
            logger.info("Upload cancelled by user: No destination selected.")
            return
            
        dest_path = dialog.get_destination_path()
        logger.info(f"Selected destination path on peer: {dest_path}")

        # Create and show progress dialog
        progress_dialog = QProgressDialog(
            "Preparing upload...", "Cancel", 0, 100, self
        )
        progress_dialog.setWindowTitle("Upload Progress")
        progress_dialog.setWindowModality(Qt.WindowModal)
        progress_dialog.setMinimumDuration(0)
        progress_dialog.setAutoClose(False)
        progress_dialog.setAutoReset(False)
        progress_dialog.setMinimumWidth(400)
        progress_dialog.canceled.connect(self.cancel_upload) # Connect cancel button
        
        # Store progress dialog and worker reference under lock
        with self._operation_lock:
            self.current_progress = progress_dialog
        
        # Create and start UploadWorker thread
        worker = UploadWorker(ip, port, token, source_path, dest_path, is_folder, parent=self, security_manager=self.security_manager)
        
        with self._operation_lock:
            self.current_worker = worker
        
        # Connect signals from worker to update UI
        worker.progress.connect(self.update_upload_progress)
        worker.finished.connect(self.handle_upload_finished)
        
        worker.start() # Start the worker thread

        # Show main window's progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Initializing upload...")
        
    def update_upload_progress(self, value: int, message: str):
        """Updates the progress dialog and main window's progress bar during upload."""
        try:
            logger.debug("Upload progress update: %d%% - %s", value, message)
            if self.current_progress:
                self.current_progress.setValue(value)
                self.current_progress.setLabelText(message)
        except Exception as e:
            logger.error("Error updating upload progress", exc_info=True)

    def handle_upload_finished(self, success: bool, message: str):
        """Handles completion of upload process."""
        try:
            if success:
                logger.info("Upload completed successfully: %s", message)
            else:
                logger.error("Upload failed: %s", message)
                
            if self.current_progress:
                if success:
                    self.current_progress.setLabelText("Upload completed successfully!")
                else:
                    self.current_progress.setLabelText(f"Upload failed: {message}")
                self.current_progress.setValue(100)
                
            # Schedule cleanup after a short delay
            self._schedule_cleanup()
            
        except Exception as e:
            logger.error("Error handling upload completion", exc_info=True)

    def cleanup_upload(self):
        """Cleans up resources after upload completion."""
        try:
            logger.info("Starting upload cleanup")
            with self._operation_lock:
                if self.current_progress:
                    logger.debug("Closing progress dialog")
                    self.current_progress.close()
                    self.current_progress = None

                if self.current_worker:
                    logger.debug("Cleaning up upload worker")
                    self.current_worker.deleteLater()
                    self.current_worker = None

                self.is_operation_cancelled = False
                logger.info("Upload cleanup completed")
                
        except Exception as e:
            logger.error("Error during upload cleanup", exc_info=True)

    def cancel_upload(self):
        """Cancels the current upload operation."""
        try:
            logger.info("User requested upload cancellation")
            with self._operation_lock:
                self.is_operation_cancelled = True
                if self.current_worker:
                    logger.debug("Cancelling current upload worker")
                    self.current_worker.cancel()
                    
                if self.current_progress:
                    logger.debug("Updating progress dialog for cancellation")
                    self.current_progress.setLabelText("Cancelling upload...")
                    self.current_progress.setValue(100)
                    
            logger.info("Upload cancellation initiated")
            
        except Exception as e:
            logger.error("Error cancelling upload", exc_info=True)

    def _handle_operation_error(self):
        """
        A centralized handler for unexpected errors during file transfer operations.
        Attempts to stop ongoing operations and clean up resources.
        """
        logger.error("An operation error was detected, initiating cleanup.")
        with self._operation_lock:
            if not self.is_operation_cancelled: # Prevent multiple error handlers from acting
                self.is_operation_cancelled = True
                
                # Stop download if active
                if self.current_download and self.current_download.is_running:
                    logger.info("Stopping download process due to operation error.")
                    self.current_download.stop() # This will trigger cleanup_download
                
                # Stop upload if active
                if self.current_worker and self.current_worker.isRunning():
                    logger.info("Cancelling upload worker due to operation error.")
                    self.current_worker.cancel() # This will trigger handle_upload_finished and cleanup_upload
                
                # Close progress dialog immediately if it exists and wasn't explicitly cancelled
                if self.current_progress:
                    try:
                        self.current_progress.close()
                    except Exception as e:
                        logger.error(f"Error closing progress dialog on operation error: {e}")
                    finally:
                        self.current_progress = None # Clear reference
                        
                self.progress_bar.setVisible(False)
                self.progress_bar.setValue(0)
                self.progress_bar.setFormat("")

    def _process_ui_updates(self):
        """
        Periodically checks for and processes UI-related updates,
        including checking worker/process states for cleanup.
        """
        # This timer is mainly for ensuring cleanup happens even if signals are missed
        # or for processing very low-frequency UI updates.
        # It's less about raw performance and more about state synchronization.
        logger.debug("MainWindow._process_ui_updates() called.")
        
        # Check download process state for proactive cleanup if it stopped unexpectedly
        with self._operation_lock:
            if self.current_download and not self.current_download.is_running and not self._cleanup_in_progress:
                logger.debug("Download process detected as not running, initiating cleanup.")
                self.cleanup_download() # Call cleanup directly
                
            # Check upload worker state for proactive cleanup
            if self.current_worker and not self.current_worker.isRunning() and not self._cleanup_in_progress:
                logger.debug("Upload worker detected as not running, initiating cleanup.")
                self.cleanup_upload() # Call cleanup directly

    def closeEvent(self, event: QEvent):
        """
        Handles the window close event, ensuring all background operations and threads
        are gracefully shut down before the application exits.
        """
        logger.info("Close event triggered. Starting graceful shutdown.")
        
        try:
            # Stop all active timers
            for timer_name in ['timer', '_ui_update_timer', '_cleanup_timer', 'peer_health_check_timer']:
                if hasattr(self, timer_name):
                    timer = getattr(self, timer_name)
                    if timer.isActive():
                        timer.stop()
                        logger.debug(f"Stopped timer: {timer_name}")
            
            # Signal discovery thread to stop and unregister services
            self._discovery_running = False # Set flag for discovery thread to exit its loop
            if hasattr(self, 'discovery') and self.discovery:
                logger.info("Calling discovery.unregister()...")
                self.discovery.unregister() # This will block until Zeroconf resources are released
                logger.info("Discovery service unregistered.")
            
            # Cancel any ongoing upload/download operations with a timeout
            if hasattr(self, 'current_worker') and self.current_worker and self.current_worker.isRunning():
                logger.info("Cancelling current_worker if active during shutdown...")
                self.current_worker.cancel() # Signal worker to cancel
                if not self.current_worker.wait(3000): # Wait up to 3 seconds for it to finish
                    logger.warning("Upload worker did not finish gracefully, terminating.")
                    self.current_worker.terminate()
            
            if hasattr(self, 'current_download') and self.current_download and self.current_download.is_running:
                logger.info("Stopping current_download process if active during shutdown...")
                self.current_download.stop() # Signal process to stop
                if not self.current_download.process.waitForFinished(3000): # Wait up to 3 seconds
                    logger.warning("Download process did not finish gracefully, forcing close.")
            
            # Clear active token fetchers (stop any running threads)
            for peer_text in list(self.active_token_fetchers.keys()): # Iterate over copy
                fetcher = self.active_token_fetchers.pop(peer_text, None)
                if fetcher and fetcher.isRunning():
                    logger.debug(f"Stopping active TokenFetcher for {peer_text} during shutdown.")
                    fetcher.quit() # Request thread to exit
                    fetcher.wait(1000) # Wait for it to finish gracefully
                    fetcher.deleteLater() # Clean up QObject
            
            # Force any pending UI events to process one last time
            QApplication.processEvents()
            
            logger.info("All background operations requested to stop. Accepting close event.")
            event.accept() # Accept the close event, allowing the application to exit
            
        except Exception as e:
            logger.critical(f"CRITICAL ERROR during shutdown (closeEvent): {str(e)}", exc_info=True)
            QMessageBox.critical(self, "Shutdown Error", f"A critical error occurred during application shutdown: {str(e)}")
            event.ignore() # Prevent immediate exit if a critical error occurs during cleanup

    def on_peer_selected(self, item: QListWidgetItem):
        """
        Handles selection of a peer in the peer list.
        Sets the current peer and refreshes the file browser for that peer.
        """
        self.current_peer = item.text()
        self.current_path = "/" # Reset path to system root/drive list when a new peer is selected
        self.path_history = [] # Clear path history
        logger.info(f"Peer selected: {self.current_peer}. Resetting path to '/'.")
        self.refresh_peer_files()

    def update_peer_list(self):
        """
        Fetches the latest list of peers from the discovery service
        and updates the peer list in the UI, initiating online/token checks.
        """
        try:
            current_time = datetime.now()
            # Throttle updates to avoid excessive processing if called frequently
            if (current_time - self.last_peer_update).total_seconds() < self.peer_update_interval:
                return
                
            self.last_peer_update = current_time
            peers_from_discovery = self.discovery.get_peers() # Get raw {device_id: (ip, port)}
            logger.debug(f"update_peer_list: Discovered peers from discovery: {peers_from_discovery.keys()}")
            
            # Update peer status label
            if not peers_from_discovery:
                self.peer_status.setText("No peers discovered")
                self.peer_status.setStyleSheet("color: gray; font-weight: bold;")
            else:
                self.peer_status.setText(f"Discovered {len(peers_from_discovery)} peer(s)")
                self.peer_status.setStyleSheet("color: black; font-weight: bold;")
            
            # Build current UI items for comparison
            current_ui_peers = {} # {peer_text: QListWidgetItem}
            for i in range(self.peers_list.count()):
                item = self.peers_list.item(i)
                if item:
                    current_ui_peers[item.text()] = item
            
            discovered_peer_texts = set() # To track which discovered peers are now in UI
            
            # Process each discovered peer: add if new, update if exists
            for peer_id, (ip, port) in peers_from_discovery.items():
                peer_text = f"{peer_id} ({ip}:{port})"
                discovered_peer_texts.add(peer_text)
                
                if peer_text not in current_ui_peers:
                    # New peer: add to UI list and schedule async check
                    try:
                        item = QListWidgetItem(peer_text)
                        try:
                            item.setIcon(QIcon.fromTheme("network-wireless")) # Attempt to set an icon
                        except Exception as icon_e:
                            logger.warning(f"Failed to set peer icon for {peer_text}: {icon_e}")
                            pass
                        
                        item.setForeground(Qt.gray) # Initially grey (offline/unknown)
                        self.peers_list.addItem(item)
                        logger.info(f"Added new peer to list: {peer_text}. Initiating async check.")
                        # Schedule check for next event loop iteration
                        QTimer.singleShot(0, lambda p_text=peer_text, p_ip=ip, p_port=port: self._check_peer_online_async(p_text, p_ip, p_port))
                    except Exception as e:
                        logger.error(f"Error adding peer {peer_text} to list: {e}", exc_info=True)
                        continue
                else:
                    # Existing peer: Ensure its status is checked if enough time has passed
                    ip_port_str_key = f"{ip}:{port}" # Key for last_peer_check/peer_tokens
                    last_check_time = self.last_peer_check.get(ip_port_str_key)
                    if not last_check_time or (current_time - last_check_time).total_seconds() > self.peer_check_timeout / 2: # Re-check more often than token expiration
                        if peer_text not in self.active_token_fetchers or not self.active_token_fetchers[peer_text].isRunning():
                            logger.debug(f"Re-checking existing peer {peer_text} for online status/token.")
                            QTimer.singleShot(0, lambda p_text=peer_text, p_ip=ip, p_port=port: self._check_peer_online_async(p_text, p_ip, p_port))

            # Remove peers from UI that are no longer discovered
            peers_to_remove_from_ui = [
                peer_text for peer_text in current_ui_peers.keys() if peer_text not in discovered_peer_texts
            ]
            for peer_text in peers_to_remove_from_ui:
                self._remove_peer(peer_text) # Use the unified removal method
            
            logger.debug(f"Peer list updated. Current UI peers count: {self.peers_list.count()}.")
            logger.debug(f"Currently offline peers: {list(self.offline_peers)}")
            
        except Exception as e:
            logger.critical(f"CRITICAL ERROR updating peer list: {e}", exc_info=True)
            QTimer.singleShot(0, lambda: QMessageBox.warning(
                self, "Peer Update Error",
                "Failed to update peer list. Some peers may not be visible due to an internal error."
            ))

    def _check_peer_online_async(self, peer_text: str, ip: str, port: int):
        """
        Launches a TokenFetcher thread to asynchronously check a peer's online status
        and fetch its authentication token. Avoids duplicate concurrent checks.
        """
        logger.debug(f"Entering _check_peer_online_async for {peer_text}.")
        try:
            # Prevent launching multiple fetchers for the same peer simultaneously
            if peer_text in self.active_token_fetchers and self.active_token_fetchers[peer_text].isRunning():
                logger.debug(f"Skipping _check_peer_online_async for {peer_text}: TokenFetcher already active.")
                return

            fetcher = TokenFetcher(peer_text, ip, port, parent=self)
            self.active_token_fetchers[peer_text] = fetcher # Store reference

            # Connect signals
            fetcher.token_fetched.connect(self._handle_token_fetched)
            fetcher.peer_status_updated.connect(self._handle_peer_status_updated)
            fetcher.finished.connect(lambda: self._cleanup_token_fetcher(peer_text)) # Cleanup when finished
            
            fetcher.start()
            logger.debug(f"TokenFetcher started for {peer_text}.")

        except Exception as e:
            logger.critical(f"CRITICAL ERROR launching TokenFetcher for {peer_text}: {e}", exc_info=True)
            # Ensure cleanup on critical error for this fetcher
            if peer_text in self.active_token_fetchers:
                fetcher = self.active_token_fetchers.pop(peer_text)
                if fetcher.isRunning():
                    fetcher.quit()
                fetcher.wait(100)
                fetcher.deleteLater()

    def _handle_token_fetched(self, peer_text: str, token: str | None):
        """
        Callback triggered when a TokenFetcher thread successfully fetches a token
        or fails to do so. Updates internal token cache and peer status.
        """
        ip_port_str = peer_text.split("(")[-1].strip(")")
        if token:
            self.peer_tokens[ip_port_str] = token
            self.last_peer_check[ip_port_str] = datetime.now()
            self.peer_last_success[peer_text] = datetime.now() # Record last successful auth
            self.peer_connection_attempts[peer_text] = 0 # Reset attempts on success
            self.offline_peers.discard(peer_text) # Ensure removed from offline list
            logger.info(f"Token fetched and stored for {peer_text}.")
        else:
            logger.warning(f"Failed to fetch token for {peer_text}.")
            self.peer_connection_attempts[peer_text] = self.peer_connection_attempts.get(peer_text, 0) + 1
            self.offline_peers.add(peer_text) # Mark as offline if token fetch failed

    def _handle_peer_status_updated(self, peer_text: str, is_online: bool):
        """
        Callback triggered when a TokenFetcher updates the online status of a peer.
        Updates the UI to reflect the peer's status (color).
        """
        items = self.peers_list.findItems(peer_text, Qt.MatchExactly)
        if items:
            item = items[0]
            if is_online:
                item.setForeground(Qt.black) # Online peers are black
                if peer_text in self.offline_peers:
                    self.offline_peers.discard(peer_text)
                    logger.info(f"Peer is back online: {peer_text}")
            else:
                item.setForeground(Qt.gray) # Offline peers are gray
                if peer_text not in self.offline_peers:
                    self.offline_peers.add(peer_text)
                    logger.debug(f"Peer is offline: {peer_text}")

    def _cleanup_token_fetcher(self, peer_text: str):
        """Removes a finished TokenFetcher from the active list and cleans up its QObject."""
        fetcher = self.active_token_fetchers.pop(peer_text, None)
        if fetcher:
            logger.debug(f"TokenFetcher for {peer_text} finished and cleaned up from active list.")
            fetcher.deleteLater() # Schedule QObject for proper deletion

    def get_peer_token(self, ip: str, port: int) -> str | None:
        """
        Retrieves an authentication token for a given peer (IP:Port).
        Uses a cached token if available and not expired.
        Otherwise, attempts to synchronously fetch a new token, handling retries.
        This method can block the UI if a synchronous fetch is needed.
        """
        peer_addr = f"{ip}:{port}"
        peer_text_key = f"({peer_addr})"
        found_peer_text = None
        for i in range(self.peers_list.count()):
            item = self.peers_list.item(i)
            if item and item.text().endswith(f"({peer_addr})"):
                found_peer_text = item.text()
                break
        if found_peer_text:
            peer_text_key = found_peer_text
        current_time = datetime.now()
        if peer_addr in self.peer_tokens:
            last_check = self.last_peer_check.get(peer_addr)
            if last_check and (current_time - last_check).total_seconds() < self.peer_check_timeout:
                logger.debug(f"Using cached token for {peer_text_key}.")
                print(f"[TOKEN] Using cached token for {peer_text_key}: {self.peer_tokens[peer_addr]}")
                return self.peer_tokens[peer_addr]
        attempts = self.peer_connection_attempts.get(peer_text_key, 0)
        last_success = self.peer_last_success.get(peer_text_key)
        if attempts >= self.max_connection_attempts:
            if not last_success or (current_time - last_success).total_seconds() < self.peer_retry_delay:
                logger.warning(f"Too many failed token attempts for peer {peer_text_key}. Not attempting token fetch.")
                QMessageBox.warning(
                    self, "Connection Blocked",
                    f"Too many failed connection attempts to {peer_text_key}. Please wait a moment before trying again."
                )
                return None
            else:
                logger.info(f"Retry delay passed for {peer_text_key}. Resetting attempts and trying synchronous fetch.")
                self.peer_connection_attempts[peer_text_key] = 0
                attempts = 0
        session = requests.Session()
        session.verify = False
        retry_strategy = requests.adapters.Retry(
            total=0,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        try:
            logger.debug(f"Attempting synchronous token fetch for {peer_text_key}...")
            r = session.post(
                f"https://{ip}:{port}/auth",
                json={"device_id": settings.device_id},
                timeout=(5, 10)
            )
            r.raise_for_status()
            token_b64 = r.json()["access_token"]
            # Base64-decode and decrypt the token (FIXED: always decrypt before use)
            encrypted_token = base64.b64decode(token_b64)
            token = self.security_manager.decrypt_data(encrypted_token).decode('utf-8')
            self.peer_tokens[peer_addr] = token
            self.last_peer_check[peer_addr] = current_time
            self.peer_last_success[peer_text_key] = current_time
            self.peer_connection_attempts[peer_text_key] = 0
            self.offline_peers.discard(peer_text_key)
            logger.debug(f"Successfully obtained token for {peer_text_key} (synchronously).")
            print(f"[TOKEN] Fetched new token for {peer_text_key}: {token}")
            return token
        except requests.exceptions.HTTPError as e:
            self.peer_connection_attempts[peer_text_key] = attempts + 1
            logger.warning(f"Synchronous HTTP error getting token from {peer_text_key}: {e}")
            QMessageBox.warning(
                self, "Authentication Error",
                f"Server returned an error from {peer_text_key}: {e.response.status_code}. Details: {e.response.text}"
            )
            return None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            self.peer_connection_attempts[peer_text_key] = attempts + 1
            logger.warning(f"Synchronous network error getting token from {peer_text_key}: {e}")
            self.offline_peers.add(peer_text_key)
            QMessageBox.warning(
                self, "Connection Error",
                f"Could not connect to {peer_text_key}. The peer may be offline or unreachable."
            )
            return None
        except Exception as e:
            logger.error(f"Unexpected error in get_peer_token for {peer_text_key}: {e}", exc_info=True)
            self.peer_connection_attempts[peer_text_key] = attempts + 1
            QMessageBox.warning(
                self, "Authentication Error",
                f"An unexpected error occurred during token retrieval from {peer_text_key}: {e}"
            )
            return None
        finally:
            session.close()

    def handle_download_error(self, error_message):
        """Handle download errors with improved user feedback"""
        logger.error(f"Download error: {error_message}")
        
        # Parse error message for better user feedback
        if "Process error" in error_message:
            if "IndexError" in error_message:
                user_message = "Download failed: Invalid file information received from peer."
            elif "SyntaxError" in error_message:
                user_message = "Download failed: Invalid file encoding detected."
            elif "Connection" in error_message:
                user_message = "Download failed: Connection to peer was lost."
            else:
                user_message = f"Download failed: {error_message}"
        else:
            user_message = f"Download failed: {error_message}"
            
        QTimer.singleShot(0, lambda: QMessageBox.warning(
            self, "Download Error",
            user_message + "\n\nPlease try again or contact the peer owner if the problem persists."
        ))
        self._schedule_cleanup()

    def _schedule_cleanup(self):
        """Schedule cleanup to run in the main thread"""
        self._cleanup_timer.start(100)

    def _cleanup_worker(self):
        """Clean up worker resources"""
        try:
            if self.current_download:
                try:
                    if self.current_download.process.state() == QProcess.Running:
                        self.current_download.stop()
                    self.current_download.deleteLater()
                except Exception as e:
                    logger.error(f"Error cleaning up download process: {e}")
                finally:
                    self.current_download = None

            if self.current_progress:
                try:
                    self.current_progress.close()
                except Exception as e:
                    logger.error(f"Error closing progress dialog: {e}")
                finally:
                    self.current_progress = None

            self.is_operation_cancelled = False
        except Exception as e:
            logger.error(f"Error in worker cleanup: {e}")

    def _check_peer_health(self):
        """Periodically check health of connected peers"""
        logger.debug("Running periodic peer health check.")
        current_time = datetime.now()
        
        # Get a copy of the peer_connection_attempts keys as it might be modified
        for peer_text_key in list(self.peer_connection_attempts.keys()):
            try:
                # Ensure peer_text_key is associated with an item in the list
                items = self.peers_list.findItems(peer_text_key, Qt.MatchExactly)
                if not items:
                    logger.debug(f"Peer '{peer_text_key}' not found in UI list during health check. Removing from tracking.")
                    self._remove_peer_tracking_data(peer_text_key)
                    continue

                # Parse IP and Port from peer_text_key (e.g., "deviceA (IP:PORT)")
                # This logic should match how peer_text_key is formed in update_peer_list and _handle_token_fetched
                parts = peer_text_key.split('(')
                if len(parts) < 2 or ':' not in parts[-1].strip(')'):
                    logger.warning(f"Malformed peer_text_key '{peer_text_key}' during health check. Skipping.")
                    self._remove_peer_tracking_data(peer_text_key) # Remove malformed entry
                    continue
                
                ip_port_str = parts[-1].strip(')')
                ip, port_str = ip_port_str.split(":")
                port = int(port_str)
                
                attempts = self.peer_connection_attempts.get(peer_text_key, 0)
                last_success = self.peer_last_success.get(peer_text_key)
                
                # Logic for re-attempting token fetch for potentially offline/unresponsive peers
                if (peer_text_key in self.offline_peers or # If explicitly marked offline
                    (last_success and (current_time - last_success).total_seconds() > self.peer_check_timeout) or # Token expired
                    (attempts > 0 and (not last_success or (current_time - last_success).total_seconds() > self.peer_retry_delay))): # Failed attempts, retry delay passed
                    
                    if peer_text_key not in self.active_token_fetchers or not self.active_token_fetchers[peer_text_key].isRunning():
                        logger.info(f"Triggering async re-check for peer health/token for {peer_text_key}.")
                        self._check_peer_online_async(peer_text_key, ip, port)
                    else:
                        logger.debug(f"TokenFetcher already active for {peer_text_key}, skipping re-trigger.")
                
            except Exception as e:
                logger.error(f"Error processing peer {peer_text_key} in health check: {e}", exc_info=True)
                # If an error occurs here, it might be due to a corrupted entry, so remove it.
                self._remove_peer_tracking_data(peer_text_key)

    def _remove_peer(self, peer_text: str):
        """
        Safely removes a peer's entry from the UI list and all internal tracking dictionaries.
        This is typically called when a peer is no longer discovered by Zeroconf.
        """
        logger.info(f"Attempting to remove peer: {peer_text}.")
        
        # Remove from UI list
        items = self.peers_list.findItems(peer_text, Qt.MatchExactly)
        if items:
            row = self.peers_list.row(items[0])
            self.peers_list.takeItem(row)
            logger.debug(f"Removed '{peer_text}' from peers_list UI.")
        else:
            logger.debug(f"Peer '{peer_text}' not found in UI list during removal attempt.")

        # Remove from all internal tracking data structures
        self._remove_peer_tracking_data(peer_text)
        logger.info(f"Successfully removed peer: {peer_text}.")
            
    def _remove_peer_tracking_data(self, peer_text_key: str):
        """Helper to remove peer from all relevant tracking dictionaries."""
        ip_port_str = peer_text_key.split("(")[-1].strip(")") # Extract IP:PORT part
        
        if ip_port_str in self.peer_tokens:
            del self.peer_tokens[ip_port_str]
            logger.debug(f"Removed '{ip_port_str}' from peer_tokens.")
        if ip_port_str in self.last_peer_check:
            del self.last_peer_check[ip_port_str]
            logger.debug(f"Removed '{ip_port_str}' from last_peer_check.")
        
        # These use the full peer_text as key
        if peer_text_key in self.peer_connection_attempts:
            del self.peer_connection_attempts[peer_text_key]
            logger.debug(f"Removed '{peer_text_key}' from peer_connection_attempts.")
        if peer_text_key in self.peer_last_success:
            del self.peer_last_success[peer_text_key]
            logger.debug(f"Removed '{peer_text_key}' from peer_last_success.")
        if peer_text_key in self.offline_peers:
            self.offline_peers.discard(peer_text_key) # Use discard as it won't raise error if not present
            logger.debug(f"Removed '{peer_text_key}' from offline_peers set.")
        
        # Clean up any active TokenFetcher for this peer
        if peer_text_key in self.active_token_fetchers:
            fetcher = self.active_token_fetchers.pop(peer_text_key)
            if fetcher.isRunning():
                fetcher.quit()
                fetcher.wait(1000) # Give time for thread to exit
            fetcher.deleteLater() # Schedule QObject for deletion
            logger.debug(f"Removed and cleaned up TokenFetcher for '{peer_text_key}'.")

    def _get_item_path(self, item):
        """Returns the full remote path for a given QTreeWidgetItem."""
        return item.data(0, Qt.UserRole)


def browse_peer_path_cli(security_manager: SecurityManager, peer_ip: str, peer_port: int, token: str, path: str = "") -> list[dict] | None:
    """
    Browses a directory on a remote peer.
    Args:
        security_manager (SecurityManager): The security manager instance with the loaded key.
        peer_ip (str): The IP address of the peer.
        peer_port (int): The HTTP port of the peer.
        token (str): The authentication token.
        path (str): The path to browse on the remote peer (e.g., "/my_folder", "/").
    Returns:
        list[dict] | None: A list of dictionaries, each representing a file or directory, or None if an error occurs.
    """
    logger = setup_logger("browse_peer_path_cli")
    if not security_manager.get_encryption_key():
        logger.error("Encryption key not loaded. Cannot browse remote files.")
        return None

    # URL-encode the path to handle special characters
    encoded_path = urllib.parse.quote(path)
    url = f"https://{peer_ip}:{peer_port}/browse?path={encoded_path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        logger.info(f"Attempting to browse path '{path}' on peer at {url}...")
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        encrypted_data_b64 = response.json().get("data")
        if not encrypted_data_b64:
            logger.error("Browse response missing 'data' field or it's empty.")
            return None
        decrypted_data_bytes = security_manager.decrypt_data(base64.b64decode(encrypted_data_b64))
        browsed_content = json.loads(decrypted_data_bytes.decode('utf-8'))
        logger.info(f"Successfully browsed path '{path}'. Found {len(browsed_content)} items.")
        return browsed_content
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error during Browse: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error during Browse: {e}. Is the peer running at {peer_ip}:{peer_port}?")
        return None
    except requests.exceptions.Timeout:
        logger.error(f"Timeout during Browse with {peer_ip}:{peer_port}. Peer might be slow or unreachable.")
        return None
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON response from browse endpoint or decrypted data is not valid JSON.")
        return None
    except ValueError as e:
        logger.error(f"Error decrypting browse data: {e}. Possibly an encryption key mismatch or corrupted data.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during Browse: {e}", exc_info=True)
        return None


def run(app_instance=None):
    """
    Entry point for running the P2PShare GUI application.
    Initializes QApplication and displays the MainWindow.
    """
    logger.info("Starting P2PShare application (run function called)")
    if app_instance is None:
        app = QApplication(sys.argv)
        logger.info("QApplication instance created in run().")
    else:
        app = app_instance
        logger.info("Using existing QApplication instance in run().")

    # Initialize the security manager here if not already done in main.py
    # This assumes CONFIG_DIR is properly set up and accessible.
    global security_manager
    if not security_manager.is_initialized():
        # Attempt to load security on startup. If it fails, the user will be prompted.
        # This initial load doesn't show a dialog directly, that's handled in main.py's flow.
        try:
            security_manager.load_security(None) # Attempt to load without password, or mark as uninitialized
            if not security_manager.is_initialized():
                 logger.info("Security manager not initialized on startup, will prompt user.")
            else:
                 logger.info("Security manager loaded successfully on startup.")
        except Exception as e:
            logger.error(f"Error initializing security manager in GUI: {e}")

    win = MainWindow(security_manager)
    win.show()
    logger.info("Main window displayed from run().")
    
    # Do NOT call app.exec_() here if this function is intended to be called
    # by an external script (like main.py) that manages the event loop.
    # The main script (e.g., main.py) should be responsible for app.exec_().
    # pass
