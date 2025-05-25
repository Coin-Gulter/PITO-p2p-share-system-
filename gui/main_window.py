# p2pshare/gui/main_window.py

import time
import os
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel,
                             QPushButton, QListWidget, QListWidgetItem, QFileDialog,
                             QHBoxLayout, QMessageBox, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QCheckBox, QProgressBar, QLineEdit, QToolBar,
                             QDialog, QProgressDialog)
from PyQt5.QtCore import QTimer, Qt, QSize, pyqtSignal, QThread, QProcess, QObject
from PyQt5.QtGui import QIcon, QFont
import sys
import requests
from shared.discovery import PeerDiscovery
from shared.config import settings
from shared.logging_config import setup_logger
import threading
import json
from pathlib import Path
from datetime import datetime
import zipfile
import tempfile
import shutil
import multiprocessing
import base64

# Set up logger
logger = setup_logger(__name__)

class FileBrowser(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Name", "Size", "Modified"])
        self.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.setColumnWidth(0, 300)  # Name column
        self.setColumnWidth(1, 100)  # Size column
        self.setColumnWidth(2, 150)  # Modified column
        
    def format_size(self, size):
        """Format file size in human readable format"""
        if size is None:
            return ""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
        
    def format_date(self, timestamp):
        """Format timestamp to readable date"""
        if timestamp is None:
            return ""
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

class UploadDialog(QDialog):
    def __init__(self, parent=None, is_folder=False):
        super().__init__(parent)
        self.setWindowTitle("Upload to Peer")
        self.is_folder = is_folder
        
        layout = QVBoxLayout()
        
        # Destination path input
        path_layout = QHBoxLayout()
        self.path_label = QLabel("Destination Path:")
        self.path_edit = QLineEdit()
        self.path_edit.setText(str(Path.home()))  # Default to home directory
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_destination)
        
        path_layout.addWidget(self.path_label)
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.browse_button)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.upload_button = QPushButton("Upload")
        self.upload_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.upload_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(path_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def browse_destination(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Destination Directory", self.path_edit.text()
        )
        if path:
            self.path_edit.setText(path)
    
    def get_destination_path(self):
        return self.path_edit.text()

class ProgressFileReader:
    def __init__(self, file_obj, total_size, progress_callback, start_progress=0):
        self.file_obj = file_obj
        self.total_size = total_size
        self.progress_callback = progress_callback
        self.start_progress = start_progress
        self.bytes_read = 0
        self._last_progress_update = 0
        self._progress_update_interval = 0.1  # Update every 100ms
        self._chunk_size = 1024 * 1024  # Use 1MB chunks for better performance
        self._buffer = b''  # Buffer for partial chunks
        self._is_closed = False
        self._eof = False  # Track EOF state

    def read(self, size=None):
        """Read data from the file with improved streaming reliability"""
        if self._is_closed:
            return b''

        if self._is_cancelled():
            logger.info("Read operation cancelled")
            self._is_closed = True
            return b''

        try:
            # If we have buffered data and it's enough for the requested size
            if self._buffer:
                if size is None:
                    # Return all buffered data if no size specified
                    data = self._buffer
                    self._buffer = b''
                    self._update_progress(len(data))
                    return data
                elif len(self._buffer) >= size:
                    # Return requested amount from buffer
                    data = self._buffer[:size]
                    self._buffer = self._buffer[size:]
                    self._update_progress(len(data))
                    return data

            # If we've reached EOF and have no buffer, return empty
            if self._eof and not self._buffer:
                return b''

            # Read new data from file
            chunk = self.file_obj.read(self._chunk_size)
            if not chunk:  # EOF
                self._eof = True
                if not self._buffer:  # No more data to return
                    self._is_closed = True
                    return b''
                # Return remaining buffer
                data = self._buffer
                self._buffer = b''
                self._update_progress(len(data))
                return data

            # If we have a size request
            if size is not None:
                if len(chunk) > size:
                    # Split chunk and buffer the rest
                    data = chunk[:size]
                    self._buffer = chunk[size:] + self._buffer
                else:
                    # Use entire chunk
                    data = chunk
            else:
                # No size specified, use entire chunk
                data = chunk

            self._update_progress(len(data))
            return data

        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            self._is_closed = True
            raise

    def _update_progress(self, bytes_read):
        """Update progress with throttling"""
        self.bytes_read += bytes_read
        current_time = time.time()
        
        if (current_time - self._last_progress_update >= self._progress_update_interval or 
            self.bytes_read == self.total_size):
            progress = self.start_progress + int((self.bytes_read / self.total_size) * (100 - self.start_progress))
            self.progress_callback(progress, f"Uploading: {progress}%")
            self._last_progress_update = current_time

    def __len__(self):
        return self.total_size

    def close(self):
        """Close the file reader"""
        if not self._is_closed:
            self._is_closed = True
            try:
                self.file_obj.close()
            except:
                pass

    def __del__(self):
        """Ensure file is closed on deletion"""
        self.close()

    def _is_cancelled(self):
        if hasattr(self, 'worker_instance') and hasattr(self.worker_instance, '_is_cancelled'):
            return self.worker_instance._is_cancelled
        return False

class UploadWorker(QThread):
    """Worker thread for file/folder uploads"""
    progress = pyqtSignal(int, str)  # progress percentage, status message
    finished = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, ip, port, token, source_path, dest_path, is_folder):
        super().__init__()
        self.ip = ip
        self.port = port
        self.token = token
        self.source_path = str(Path(source_path).resolve())
        self.dest_path = str(Path(dest_path).resolve())
        self.is_folder = is_folder
        self._is_cancelled = False
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({"Authorization": f"Bearer {token}"})
        
    def run(self):
        try:
            logger.info(f"Starting upload worker for {'folder' if self.is_folder else 'file'}: {self.source_path}")
            if self.is_folder:
                self.upload_folder()
            else:
                self.upload_file()
        except Exception as e:
            if not self._is_cancelled:
                logger.error(f"Upload error: {str(e)}", exc_info=True)
                self.finished.emit(False, f"Upload failed: {str(e)}")
        finally:
            self._session.close()
    
    def cancel(self):
        """Cancel the upload operation"""
        logger.info("Upload cancellation requested")
        self._is_cancelled = True
        self._session.close()
    
    def _progress_reader(self, file_obj, total_size, start_progress=0):
        """Wraps a file object to provide progress updates during read operations."""
        reader = ProgressFileReader(file_obj, total_size, self.progress.emit, start_progress)
        reader.worker_instance = self
        return reader
    
    def upload_file(self):
        """Upload a single file with improved error handling"""
        if self._is_cancelled:
            return
            
        try:
            filename = Path(self.source_path).name
            file_size = os.path.getsize(self.source_path)
            
            logger.info(f"Starting file upload: {filename} ({file_size} bytes)")
            logger.debug(f"Source path: {self.source_path}")
            logger.debug(f"Destination path: {self.dest_path}")
            
            with open(self.source_path, "rb") as f:
                progress_file_reader = self._progress_reader(f, file_size)
                files = {
                    "file": (filename, progress_file_reader, "application/octet-stream")
                }
                data = {
                    "dest_path": self.dest_path
                }
                
                try:
                    self.progress.emit(0, "Starting upload...")
                    r = self._session.put(
                        f"https://{self.ip}:{self.port}/upload/{filename}",
                        files=files,
                        data=data,
                        timeout=30
                    )
                    
                    if self._is_cancelled:
                        logger.info("Upload cancelled after request")
                        return
                        
                    if r.ok:
                        response = r.json()
                        logger.info(f"File uploaded successfully to {response['path']}")
                        self.progress.emit(100, "Upload complete")
                        self.finished.emit(True, f"File uploaded successfully to {response['path']}")
                    else:
                        error_msg = f"Upload failed: {r.status_code}"
                        if r.text:
                            try:
                                error_detail = r.json().get("detail", r.text)
                                error_msg += f" - {error_detail}"
                            except:
                                error_msg += f" - {r.text}"
                        logger.error(error_msg)
                        self.finished.emit(False, error_msg)
                except requests.exceptions.Timeout:
                    if not self._is_cancelled:
                        logger.error("Upload timed out")
                        self.finished.emit(False, "Upload timed out")
                except requests.exceptions.ConnectionError as e:
                    if not self._is_cancelled:
                        logger.error(f"Connection error: {str(e)}")
                        self.finished.emit(False, "Connection lost during upload")
                except Exception as e:
                    if not self._is_cancelled:
                        logger.error(f"Upload error: {str(e)}", exc_info=True)
                        self.finished.emit(False, f"Upload error: {str(e)}")
        except Exception as e:
            if not self._is_cancelled:
                logger.error(f"Error preparing upload: {str(e)}", exc_info=True)
                self.finished.emit(False, f"Error preparing upload: {str(e)}")
    
    def _validate_zip_file(self, zip_path):
        """Validate zip file integrity before upload"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # Test zip file integrity
                if zipf.testzip() is not None:
                    raise ValueError("Zip file integrity check failed")
                
                # Check if zip file is not empty
                if not zipf.namelist():
                    raise ValueError("Zip file is empty")
                
                # Check for maximum file size (e.g., 2GB)
                total_size = sum(info.file_size for info in zipf.filelist)
                if total_size > 2 * 1024 * 1024 * 1024:  # 2GB
                    raise ValueError("Zip file exceeds maximum size limit of 2GB")
                
                # Validate file paths and names
                for name in zipf.namelist():
                    # Check for absolute paths
                    if name.startswith('/') or '\\' in name:
                        raise ValueError(f"Invalid path in zip: {name} (contains absolute path)")
                    
                    # Check for parent directory references
                    if '..' in name.split('/'):
                        raise ValueError(f"Invalid path in zip: {name} (contains parent directory reference)")
                    
                    # Check for invalid characters in filenames
                    invalid_chars = '<>:"|?*'
                    if any(char in name for char in invalid_chars):
                        raise ValueError(f"Invalid characters in filename: {name}")
                    
                    # Check for maximum path length (Windows limit)
                    if len(name) > 260:
                        raise ValueError(f"Path too long: {name}")
                
                return True
        except zipfile.BadZipFile:
            raise ValueError("Invalid zip file format")
        except Exception as e:
            raise ValueError(f"Zip file validation failed: {str(e)}")

    def _sanitize_filename(self, filename):
        """Sanitize filename to be safe for zip files"""
        # Replace invalid characters with underscore
        invalid_chars = '<>:"|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')
        
        # Ensure filename is not empty after sanitization
        if not filename:
            filename = 'unnamed_file'
            
        return filename

    def _get_relative_path(self, file_path, source_path):
        """Get a safe relative path for the zip file"""
        try:
            rel_path = os.path.relpath(file_path, source_path)
            # Convert to forward slashes for zip files
            rel_path = rel_path.replace('\\', '/')
            
            # Ensure path is relative and doesn't contain '..'
            if rel_path.startswith('..') or os.path.isabs(rel_path):
                raise ValueError(f"Invalid path in zip: {rel_path}")
                
            return rel_path
        except Exception as e:
            raise ValueError(f"Error creating relative path: {str(e)}")

    def _create_zip_file(self, source_path, temp_dir):
        """Create zip file with improved error handling and progress tracking"""
        zip_path = os.path.join(temp_dir, f"{Path(source_path).name}.zip")
        logger.debug(f"Creating zip file at: {zip_path}")
        
        try:
            # Calculate total size and validate files first
            total_size = 0
            file_count = 0
            files_to_zip = []
            
            for root, _, files in os.walk(source_path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        if not os.path.exists(file_path):
                            continue
                            
                        # Check file permissions
                        if not os.access(file_path, os.R_OK):
                            logger.warning(f"No read permission for file: {file_path}")
                            continue
                            
                        # Get relative path and sanitize filename
                        rel_path = self._get_relative_path(file_path, source_path)
                        safe_name = self._sanitize_filename(rel_path)
                        
                        # Skip if path is invalid
                        if '..' in safe_name or safe_name.startswith('/'):
                            logger.warning(f"Skipping invalid path: {file_path}")
                            continue
                            
                        file_size = os.path.getsize(file_path)
                        total_size += file_size
                        file_count += 1
                        files_to_zip.append((file_path, safe_name, file_size))
                        
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Error accessing file {file}: {str(e)}")
                        continue
            
            if file_count == 0:
                raise ValueError("No valid files found to zip")
            
            # Create zip file with progress tracking
            uploaded_size = 0
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zipf:
                for file_path, safe_name, file_size in files_to_zip:
                    if self._is_cancelled:
                        raise InterruptedError("Upload cancelled during zip creation")
                        
                    try:
                        zipf.write(file_path, safe_name)
                        
                        # Update progress
                        uploaded_size += file_size
                        progress = int((uploaded_size / total_size) * 50)  # First 50% for zipping
                        self.progress.emit(progress, f"Preparing folder: {progress}%")
                        
                    except Exception as e:
                        logger.warning(f"Error adding file {file_path} to zip: {str(e)}")
                        continue
            
            # Validate zip file before returning
            self._validate_zip_file(zip_path)
            return zip_path
            
        except Exception as e:
            # Clean up zip file if it exists
            if os.path.exists(zip_path):
                try:
                    os.remove(zip_path)
                except:
                    pass
            raise e

    def upload_folder(self):
        """Upload a folder with improved error handling and retry logic"""
        if self._is_cancelled:
            return
            
        try:
            folder_name = Path(self.source_path).name
            logger.info(f"Starting folder upload: {folder_name}")
            
            # Create temporary directory for zip file
            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    # Create and validate zip file
                    zip_path = self._create_zip_file(self.source_path, temp_dir)
                    
                    # Upload zip file with improved retry logic
                    max_retries = 3
                    retry_count = 0
                    last_error = None
                    base_wait_time = 2
                    
                    while retry_count < max_retries and not self._is_cancelled:
                        try:
                            file_size = os.path.getsize(zip_path)
                            logger.info(f"Uploading zip file: {file_size} bytes")
                            
                            # Validate zip file before each attempt
                            self._validate_zip_file(zip_path)
                            
                            # Configure session for streaming upload
                            session = requests.Session()
                            session.verify = False
                            
                            # Encode headers properly for Unicode characters
                            headers = {
                                "Authorization": f"Bearer {self.token}",
                                "Content-Type": "application/octet-stream",
                                "X-Folder-Name": base64.b64encode(folder_name.encode('utf-8')).decode('ascii'),
                                "X-Dest-Path": base64.b64encode(self.dest_path.encode('utf-8')).decode('ascii')
                            }
                            session.headers.update(headers)
                            
                            # Configure retry strategy for the upload
                            retry_strategy = requests.adapters.Retry(
                                total=2,
                                backoff_factor=0.5,
                                status_forcelist=[500, 502, 503, 504]
                            )
                            adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
                            session.mount("https://", adapter)
                            
                            try:
                                # Open file in binary mode for streaming
                                with open(zip_path, 'rb') as f:
                                    # Create a streaming upload with progress tracking
                                    progress_file_reader = self._progress_reader(f, file_size, 50)
                                    
                                    self.progress.emit(50, "Starting folder upload...")
                                    
                                    # Use streaming upload with increased timeout
                                    r = session.post(
                                        f"https://{self.ip}:{self.port}/upload-folder",
                                        data=progress_file_reader,
                                        timeout=(30, 300),  # (connect timeout, read timeout)
                                        stream=True  # Enable streaming mode
                                    )
                                    
                                    if self._is_cancelled:
                                        raise InterruptedError("Upload cancelled during transfer")
                                        
                                    if r.ok:
                                        response = r.json()
                                        logger.info(f"Folder uploaded successfully to {response['path']}")
                                        self.progress.emit(100, "Upload complete")
                                        self.finished.emit(True, f"Folder uploaded successfully to {response['path']}")
                                        return
                                    else:
                                        error_msg = f"Upload failed: {r.status_code}"
                                        if r.text:
                                            try:
                                                error_detail = r.json().get("detail", r.text)
                                                error_msg += f" - {error_detail}"
                                                
                                                # Handle specific error cases
                                                if "Invalid zip file" in error_detail:
                                                    raise ValueError("Server rejected zip file: " + error_detail)
                                                elif "Permission denied" in error_detail:
                                                    raise PermissionError("Permission denied on server: " + error_detail)
                                                elif "Path too long" in error_detail:
                                                    raise ValueError("Path too long on server: " + error_detail)
                                                elif "File upload incomplete" in error_detail:
                                                    raise ConnectionError("Upload was incomplete: " + error_detail)
                                            except:
                                                error_msg += f" - {r.text}"
                                                
                                        raise requests.exceptions.HTTPError(error_msg)
                                    
                            except requests.exceptions.RequestException as e:
                                if self._is_cancelled:
                                    raise InterruptedError("Upload cancelled during transfer")
                                raise
                                
                        except (ValueError, PermissionError, ConnectionError) as e:
                            # These errors should not be retried
                            raise
                        except Exception as e:
                            retry_count += 1
                            last_error = str(e)
                            if retry_count < max_retries:
                                wait_time = base_wait_time * (2 ** (retry_count - 1))
                                logger.warning(f"Upload attempt {retry_count} failed: {str(e)}. Retrying in {wait_time} seconds...")
                                time.sleep(wait_time)
                            else:
                                raise
                                
                    if retry_count >= max_retries:
                        raise Exception(f"Upload failed after {max_retries} attempts. Last error: {last_error}")
                        
                finally:
                    # Clean up zip file
                    if os.path.exists(zip_path):
                        try:
                            os.remove(zip_path)
                        except:
                            pass
                            
        except InterruptedError:
            logger.info("Folder upload cancelled")
            self.finished.emit(False, "Upload cancelled by user")
        except ValueError as e:
            logger.error(f"Validation error during upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: {str(e)}")
        except PermissionError as e:
            logger.error(f"Permission error during upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: {str(e)}")
        except TimeoutError as e:
            logger.error(f"Timeout during upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: {str(e)}")
        except ConnectionError as e:
            logger.error(f"Connection error during upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: {str(e)}")
        except Exception as e:
            if not self._is_cancelled:
                logger.error(f"Error preparing folder upload: {str(e)}", exc_info=True)
                self.finished.emit(False, f"Error preparing folder upload: {str(e)}")

class DownloadProcess(QObject):
    """Process for handling downloads"""
    progress = pyqtSignal(int, str)  # progress percentage, status message
    finished = pyqtSignal(bool, str)  # success, message
    cleanup = pyqtSignal()  # signal to clean up resources
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self._handle_output)
        self.process.finished.connect(self._handle_finished)
        self.process.errorOccurred.connect(self._handle_process_error)
        self.is_running = False
        self._last_progress_update = 0
        self._progress_update_interval = 0.1  # Update every 100ms
        
    def start_download(self, ip, port, token, items, download_dir, is_folder):
        """Start the download process with improved error handling"""
        try:
            if self.is_running:
                logger.warning("Download process already running")
                return
                
            # Convert items to base64 encoded JSON
            items_json = json.dumps(items, ensure_ascii=False)
            items_b64 = base64.b64encode(items_json.encode('utf-8')).decode('utf-8')
            
            # Build command
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'download_script.py')
            cmd = [
                sys.executable,
                script_path,
                ip,
                str(port),
                token,
                items_b64,
                download_dir,
                str(is_folder).lower()
            ]
            
            logger.info(f"Starting download process with command: {' '.join(cmd)}")
            
            # Start process
            self.process.start(cmd[0], cmd[1:])
            if not self.process.waitForStarted(5000):  # Wait up to 5 seconds
                raise RuntimeError("Failed to start download process")
                
            self.is_running = True
            
        except Exception as e:
            error_msg = f"Failed to start download: {str(e)}"
            logger.error(error_msg)
            self.finished.emit(False, error_msg)
            self.cleanup.emit()

    def stop(self):
        """Stop the download process"""
        logger.info("Stopping download process...")
        if self.process.state() == QProcess.Running:
            try:
                self.process.kill() # Terminate the process
                if not self.process.waitForFinished(3000): # Wait up to 3 seconds
                    logger.warning("Download process did not finish in time after kill.")
            except Exception as e:
                logger.error(f"Error stopping download process: {str(e)}")
        self.is_running = False
        self.cleanup.emit() # Ensure cleanup signal is emitted

    def _handle_output(self):
        """Handle process output with throttled progress updates"""
        try:
            output = self.process.readAllStandardOutput().data().decode('utf-8')
            current_time = time.time()
            
            for line in output.splitlines():
                try:
                    data = json.loads(line)
                    if 'progress' in data:
                        # Throttle progress updates
                        if current_time - self._last_progress_update >= self._progress_update_interval:
                            self.progress.emit(data['progress'], data.get('status', ''))
                            self._last_progress_update = current_time
                    elif 'error' in data:
                        logger.error(f"Download error: {data['error']}")
                        self.finished.emit(False, data['error'])
                        self.stop()
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON output: {line}")
                except Exception as e:
                    logger.error(f"Error processing output: {str(e)}")
        except Exception as e:
            logger.error(f"Error reading process output: {str(e)}")

    def _handle_finished(self, exit_code, exit_status):
        """Handle process completion with proper cleanup"""
        try:
            self.is_running = False
            if exit_code == 0:
                self.finished.emit(True, "Download completed successfully")
            else:
                error_msg = f"Download failed with exit code {exit_code}"
                logger.error(error_msg)
                self.finished.emit(False, error_msg)
        except Exception as e:
            logger.error(f"Error handling process completion: {str(e)}")
        finally:
            self.cleanup.emit()

    def _handle_process_error(self, error):
        """Handle process errors with proper cleanup"""
        try:
            error_msg = f"Process error: {error}"
            logger.error(error_msg)
            self.finished.emit(False, error_msg)
        except Exception as e:
            logger.error(f"Error handling process error: {str(e)}")
        finally:
            self.cleanup.emit()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        logger.info("Initializing main window")
        self.setWindowTitle("P2PShare")
        self.setGeometry(100, 100, 1200, 800)

        # Initialize state with improved defaults
        self.discovery = PeerDiscovery(port=settings.http_port)
        self.peer_tokens = {}
        self.last_peer_check = {}
        self.peer_check_timeout = 60  # Increased timeout to reduce auth requests
        self._operation_lock = threading.RLock()  # Use RLock instead of Lock for better deadlock prevention
        self.current_download = None
        self.current_worker = None
        self.current_progress = None
        self.is_operation_cancelled = False
        self.offline_peers = set()  # Track offline peers
        self.last_peer_update = datetime.now()
        self.peer_update_interval = 5  # Update peers every 5 seconds for better responsiveness
        self._discovery_running = True  # Flag to control discovery thread
        self._cleanup_in_progress = False  # Flag to track cleanup state
        
        # Add new peer connection tracking
        self.peer_connection_attempts = {}  # Track connection attempts per peer
        self.peer_last_success = {}  # Track last successful connection
        self.peer_retry_delay = 30  # Seconds to wait before retrying failed peers
        self.max_connection_attempts = 3  # Maximum number of connection attempts
        self.peer_health_check_timer = QTimer()
        self.peer_health_check_timer.timeout.connect(self._check_peer_health)
        self.peer_health_check_timer.start(10000)  # Check every 10 seconds
        
        # Start discovery thread with error handling
        try:
            self.discovery_thread = threading.Thread(target=self._run_discovery, daemon=True)
            self.discovery_thread.start()
            logger.info("Started peer discovery thread")
        except Exception as e:
            logger.error(f"Failed to start discovery thread: {str(e)}")
            QMessageBox.critical(self, "Error", "Failed to start peer discovery. The application may not function correctly.")

        # Create UI update timer with reduced frequency
        self._ui_update_timer = QTimer()
        self._ui_update_timer.timeout.connect(self._process_ui_updates)
        self._ui_update_timer.start(250)  # Update UI every 250ms for better performance
        
        # Create cleanup timer
        self._cleanup_timer = QTimer()
        self._cleanup_timer.setSingleShot(True)
        self._cleanup_timer.timeout.connect(self._delayed_cleanup)
        
        # Initialize UI with improved layout
        self._init_ui()
        
        # Start peer list update timer with increased frequency
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_peer_list)
        self.timer.start(self.peer_update_interval * 1000)  # Update every 5 seconds
        logger.info("Started peer list update timer")
        
        # Initialize state
        self.current_peer = None
        self.current_path = "/"
        self.path_history = []
        self.update_peer_list()  # Initial update

    def _run_discovery(self):
        """Run discovery with error handling and proper shutdown"""
        try:
            # Start the discovery service
            self.discovery.run()  # Use run() method
        except Exception as e:
            logger.error(f"Discovery thread error: {str(e)}")
            if self._discovery_running:  # Only show message if we're still supposed to be running
                QTimer.singleShot(0, lambda: QMessageBox.warning(
                    self, "Discovery Error",
                    "Peer discovery service encountered an error. Some features may be limited."
                ))
        finally:
            logger.info("Discovery thread exiting")
            self._discovery_running = False  # Ensure flag is set to False

    def _init_ui(self):
        """Initialize the user interface with improved layout and styling"""
        # Create main layout with better spacing
        self.layout = QVBoxLayout()
        self.layout.setSpacing(10)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Create splitter for peers and files with improved sizing
        self.splitter = QSplitter(Qt.Horizontal)
        
        # Left panel for peers with improved styling
        self.peers_panel = QWidget()
        self.peers_layout = QVBoxLayout()
        self.peers_layout.setSpacing(5)
        self.peers_panel.setLayout(self.peers_layout)
        
        # Add status label for peer count
        self.peer_status = QLabel("No peers discovered")
        self.peer_status.setStyleSheet("color: gray;")
        self.peers_layout.addWidget(self.peer_status)
        
        self.peers_list = QListWidget()
        self.peers_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 2px;
            }
            QListWidget::item {
                padding: 4px;
            }
            QListWidget::item:selected {
                background-color: #e0e0e0;
            }
        """)
        self.peers_list.itemClicked.connect(self.on_peer_selected)

        # Peer buttons with improved styling
        self.refresh_button = QPushButton("Refresh Peer List")
        self.refresh_button.setStyleSheet("""
            QPushButton {
                padding: 5px;
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.refresh_button.clicked.connect(self.update_peer_list)

        self.peers_layout.addWidget(self.peers_list)
        self.peers_layout.addWidget(self.refresh_button)
        
        # Right panel for files with improved layout
        self.files_panel = QWidget()
        self.files_layout = QVBoxLayout()
        self.files_layout.setSpacing(10)
        self.files_panel.setLayout(self.files_layout)
        
        # Navigation bar with improved styling
        self.nav_layout = QHBoxLayout()
        self.back_button = QPushButton("← Back")
        self.back_button.setStyleSheet("""
            QPushButton {
                padding: 5px 10px;
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.back_button.clicked.connect(self.navigate_back)
        
        self.path_edit = QLineEdit()
        self.path_edit.setStyleSheet("""
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
        """)
        self.path_edit.returnPressed.connect(self.navigate_to_path)
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setStyleSheet("""
            QPushButton {
                padding: 5px 10px;
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.refresh_button.clicked.connect(self.refresh_current_directory)
        
        self.nav_layout.addWidget(self.back_button)
        self.nav_layout.addWidget(self.path_edit, 1)  # Give path edit more space
        self.nav_layout.addWidget(self.refresh_button)
        
        # File browser with improved styling
        self.files_tree = FileBrowser()
        self.files_tree.setStyleSheet("""
            QTreeWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:selected {
                background-color: #e0e0e0;
            }
        """)
        self.files_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        
        # File operation buttons with improved styling
        self.files_buttons = QHBoxLayout()
        self.download_button = QPushButton("Download Selected")
        self.upload_button = QPushButton("Upload File")
        
        for button in [self.download_button, self.upload_button]:
            button.setStyleSheet("""
                QPushButton {
                    padding: 8px 15px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #45a049;
                }
                QPushButton:disabled {
                    background-color: #cccccc;
                }
            """)
        
        self.download_button.clicked.connect(self.download_selected_files)
        self.upload_button.clicked.connect(self.upload_file_to_peer)

        self.files_buttons.addWidget(self.download_button)
        self.files_buttons.addWidget(self.upload_button)
        
        # Progress bar with improved styling
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 4px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
        """)
        self.progress_bar.setVisible(False)
        
        self.files_layout.addLayout(self.nav_layout)
        self.files_layout.addWidget(self.files_tree)
        self.files_layout.addLayout(self.files_buttons)
        self.files_layout.addWidget(self.progress_bar)
        
        # Add panels to splitter with improved sizing
        self.splitter.addWidget(self.peers_panel)
        self.splitter.addWidget(self.files_panel)
        self.splitter.setSizes([250, 950])  # Adjusted panel sizes
        
        self.layout.addWidget(self.splitter)
        self.setLayout(self.layout)

    def navigate_back(self):
        """Navigate to the previous directory"""
        if self.path_history:
            self.current_path = self.path_history.pop()
            self.refresh_current_directory()

    def navigate_to_path(self):
        """Navigate to the path entered in the path edit"""
        path = self.path_edit.text()
        if path:
            self.path_history.append(self.current_path)
            self.current_path = path
            self.refresh_current_directory()

    def on_item_double_clicked(self, item, column):
        """Handle double click on a file or directory"""
        path = item.data(0, Qt.UserRole)  # Get the full path
        is_dir = item.data(0, Qt.UserRole + 1)  # Get if it's a directory
        
        if is_dir:
            self.path_history.append(self.current_path)
            self.current_path = path
            self.refresh_current_directory()

    def refresh_current_directory(self):
        """Refresh the current directory view"""
        if not self.current_peer:
            return
            
        self.path_edit.setText(self.current_path)
        self.refresh_peer_files()

    def refresh_peer_files(self):
        """Refresh the file list for the current directory"""
        if not self.current_peer:
            logger.warning("No peer selected for file refresh")
            return
            
        ip_port = self.current_peer.split("(")[-1].strip(")")
        ip, port = ip_port.split(":")
        
        # Get token for the peer
        token = self.get_peer_token(ip, port)
        if not token:
            logger.warning("Failed to get token for file refresh")
            return
            
        try:
            r = requests.get(
                f"https://{ip}:{port}/browse",
                params={"path": self.current_path},
                headers={"Authorization": f"Bearer {token}"},
                verify=False
            )
            if r.ok:
                items = r.json()
                self.update_files_tree(items)
                logger.info(f"Refreshed directory: {self.current_path} ({len(items)} items)")
            else:
                logger.warning(f"Failed to get directory listing: {r.status_code} {r.text}")
                QMessageBox.warning(self, "Error", f"Failed to get directory listing: {r.status_code}")
        except Exception as e:
            logger.error(f"Error refreshing files: {str(e)}", exc_info=True)
            QMessageBox.warning(self, "Error", f"Error refreshing files: {str(e)}")

    def update_files_tree(self, items):
        """Update the file tree with the list of items"""
        self.files_tree.clear()
        for item in items:
            tree_item = QTreeWidgetItem([
                item["name"],
                self.files_tree.format_size(item["size"]),
                self.files_tree.format_date(item["modified"])
            ])
            # Store full path and is_dir in item data
            tree_item.setData(0, Qt.UserRole, item["path"])
            tree_item.setData(0, Qt.UserRole + 1, item["is_dir"])
            # Set icon or style based on type
            if item["is_dir"]:
                tree_item.setForeground(0, Qt.blue)
            self.files_tree.addTopLevelItem(tree_item)

    def download_selected_files(self):
        """Download selected files and folders from the peer"""
        if not self.current_peer:
            logger.warning("No peer selected for download")
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer first")
            return
            
        selected_items = self.files_tree.selectedItems()
        if not selected_items:
            logger.warning("No items selected for download")
            QMessageBox.warning(self, "No Items Selected", "Please select files or folders to download")
            return
            
        # Reset cancellation flag
        self.is_operation_cancelled = False
            
        # Get download directory
        download_dir = QFileDialog.getExistingDirectory(
            self, "Select Download Directory", str(Path.home())
        )
        if not download_dir:
            logger.info("Download cancelled - no directory selected")
            return
            
        ip_port = self.current_peer.split("(")[-1].strip(")")
        ip, port = ip_port.split(":")
        
        # Get token for the peer
        token = self.get_peer_token(ip, port)
        if not token:
            logger.warning("Failed to get token for download")
            return
            
        # Prepare items list
        items = []
        for item in selected_items:
            path = item.data(0, Qt.UserRole)
            name = item.text(0)
            items.append([path, name])
        
        # Create and show progress dialog
        progress = QProgressDialog(
            "Preparing download...",
            "Cancel",
            0, 100,
            self
        )
        progress.setWindowTitle("Download Progress")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.canceled.connect(self.cancel_download)
        
        # Store progress dialog
        with self._operation_lock:
            self.current_progress = progress
        
        # Create and start download process
        download_process = DownloadProcess(self)
        download_process.progress.connect(self.update_download_progress)
        download_process.finished.connect(self.handle_download_finished)
        download_process.cleanup.connect(self.cleanup_download)
        
        # Store download process
        with self._operation_lock:
            self.current_download = download_process
        
        # Start the download
        is_folder = any(item.data(0, Qt.UserRole + 1) for item in selected_items)
        download_process.start_download(ip, port, token, items, download_dir, is_folder)

    def update_download_progress(self, value, message):
        """Update the progress dialog with download progress"""
        with self._operation_lock:
            if self.is_operation_cancelled:
                return
                
            if not self.current_progress:
                logger.debug("Progress dialog not available")
                return
                
            try:
                if not self.current_progress.wasCanceled():
                    self.current_progress.setValue(value)
                    self.current_progress.setLabelText(message)
            except RuntimeError as e:
                logger.warning(f"Progress dialog error: {str(e)}")
                self._handle_operation_error()
            except Exception as e:
                logger.error(f"Unexpected error updating progress: {str(e)}")
                self._handle_operation_error()
            
    def _handle_operation_error(self):
        """Handle operation errors consistently by stopping the operation and cleaning up."""
        logger.error("An operation error was detected, initiating cleanup.")
        with self._operation_lock:
            if not self.is_operation_cancelled: # Prevent multiple cancellations
                self.is_operation_cancelled = True
                
                # Stop download if active
                if self.current_download and self.current_download.is_running: # Check is_running
                    try:
                        logger.info("Stopping download process due to operation error.")
                        self.current_download.stop() # Use the refined stop method
                    except Exception as e:
                        logger.error(f"Error stopping download process on error: {str(e)}")
                
                # Stop upload if active
                if self.current_worker and self.current_worker.isRunning():
                    try:
                        logger.info("Cancelling upload worker due to operation error.")
                        self.current_worker.cancel()
                        # Worker should emit finished signal which triggers cleanup_upload
                    except Exception as e:
                        logger.error(f"Error cancelling upload worker on error: {str(e)}")
                
                # Close progress dialog immediately if it exists
                if self.current_progress:
                    try:
                        self.current_progress.close()
                        self.current_progress = None # Clear reference
                    except Exception as e:
                        logger.error(f"Error closing progress dialog on error: {str(e)}")
            
    def cancel_download(self):
        """Handle download cancellation"""
        try:
            with self._operation_lock:
                if not self.is_operation_cancelled:
                    logger.info("Download cancellation requested")
                    self.is_operation_cancelled = True
                    
                    # Store references before cleanup
                    download = self.current_download
                    progress = self.current_progress
                    
                    # Clear references first
                    self.current_download = None
                    self.current_progress = None
                    
                    # Stop the download process
                    if download:
                        download.stop()
                    
                    # Close progress dialog
                    if progress:
                        try:
                            progress.close()
                        except Exception as e:
                            logger.error(f"Error closing progress dialog: {str(e)}")
        except Exception as e:
            logger.error(f"Error in cancel_download: {str(e)}")

    def handle_download_finished(self, success, message):
        """Handle download completion"""
        try:
            # Show completion message in a non-blocking way
            if success:
                QTimer.singleShot(0, lambda: QMessageBox.information(self, "Success", message))
            else:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Download Failed", message))
                
            # Clean up
            with self._operation_lock:
                if self.current_progress:
                    try:
                        self.current_progress.close()
                    except Exception as e:
                        logger.error(f"Error closing progress dialog: {str(e)}")
                    finally:
                        self.current_progress = None
                        
                self.current_download = None
                self.is_operation_cancelled = False
        except Exception as e:
            logger.error(f"Error in handle_download_finished: {str(e)}")

    def cleanup_download(self):
        """Clean up download resources"""
        logger.debug("Cleanup_download called.")
        with self._operation_lock:
            progress_dialog = self.current_progress
            download_process = self.current_download
            
            self.current_progress = None
            self.current_download = None
            
            if progress_dialog:
                try:
                    logger.debug("Closing progress dialog in cleanup_download.")
                    progress_dialog.close()
                except Exception as e:
                    logger.error(f"Error closing progress dialog in cleanup_download: {str(e)}")
                    
            if download_process:
                try:
                    logger.debug("Stopping and deleting download process in cleanup_download.")
                    if download_process.process.state() == QProcess.Running:
                        download_process.stop() # Use the new stop method
                    download_process.deleteLater() # Important for QObject cleanup
                except Exception as e:
                    logger.error(f"Error cleaning up download process in cleanup_download: {str(e)}")
                    
            self.is_operation_cancelled = False # Reset
            logger.debug("Download resources cleaned up.")
            
    def upload_file_to_peer(self):
        """Upload files or folders to the selected peer"""
        # Reset cancellation flag
        self.is_operation_cancelled = False
        
        selected = self.peers_list.currentItem()
        if not selected:
            logger.warning("Upload attempted without selecting a peer")
            QMessageBox.warning(self, "No Peer Selected", 
                "Please select a peer to upload to")
            return

        peer_text = selected.text()
        logger.info(f"Selected peer for upload: {peer_text}")
        ip_port = peer_text.split("(")[-1].strip(")")
        ip, port = ip_port.split(":")
        logger.debug(f"Peer address: {ip}:{port}")

        # Get token for the peer
        token = self.get_peer_token(ip, port)
        if not token:
            logger.warning("Upload aborted due to token failure")
            return
        logger.debug("Successfully obtained token for upload")

        # Ask user what to upload with more descriptive text
        upload_type = QMessageBox.question(
            self, "Select Upload Type",
            "Would you like to upload a single file?\n\n"
            "Click 'Yes' to upload a file\n"
            "Click 'No' to upload a folder with all its contents",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        is_folder = upload_type == QMessageBox.StandardButton.No

        # Get source path
        if is_folder:
            source_path = QFileDialog.getExistingDirectory(
                self, "Select Folder to Upload (All contents will be included)"
            )
        else:
            source_path, _ = QFileDialog.getOpenFileName(
                self, "Select File to Upload"
            )
            
        if not source_path:
            logger.info("Upload cancelled - no source selected")
            return
        logger.info(f"Selected source for upload: {source_path}")

        # Get destination path
        dialog = UploadDialog(self, is_folder)
        if dialog.exec_() != QDialog.DialogCode.Accepted:
            logger.info("Upload cancelled - no destination selected")
            return
            
        dest_path = dialog.get_destination_path()
        logger.info(f"Selected destination path: {dest_path}")

        # Create and show progress dialog
        progress = QProgressDialog(
            "Preparing upload...",
            "Cancel",
            0, 100,
            self
        )
        progress.setWindowTitle("Upload Progress")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.canceled.connect(self.cancel_upload)
        
        # Store progress dialog
        with self._operation_lock:
            self.current_progress = progress
        
        # Create and start upload worker
        worker = UploadWorker(ip, port, token, source_path, dest_path, is_folder)
        
        # Store worker thread
        with self._operation_lock:
            self.current_worker = worker
        
        # Connect signals
        worker.progress.connect(self.update_upload_progress)
        worker.finished.connect(self.handle_upload_finished)
        
        # Start the worker
        worker.start()
        
    def update_upload_progress(self, value, message):
        """Update the progress dialog with upload progress"""
        with self._operation_lock:
            if self.is_operation_cancelled:
                return
                
            if not self.current_progress:
                logger.debug("Progress dialog not available")
                return
                
            try:
                if not self.current_progress.wasCanceled():
                    self.current_progress.setValue(value)
                    self.current_progress.setLabelText(message)
            except RuntimeError as e:
                logger.warning(f"Progress dialog error: {str(e)}")
                self._handle_operation_error()
            except Exception as e:
                logger.error(f"Unexpected error updating progress: {str(e)}")
                self._handle_operation_error()
            
    def handle_upload_finished(self, success, message):
        """Handle upload completion"""
        try:
            # Show completion message in a non-blocking way
            if success:
                QTimer.singleShot(0, lambda: QMessageBox.information(self, "Success", message))
            else:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "Upload Failed", message))
            # Ensure cleanup happens after the worker signals it's finished
            self.cleanup_upload() 
        except Exception as e:
            logger.error(f"Error in handle_upload_finished: {str(e)}")

    def cleanup_upload(self):
        """Clean up upload resources after worker has finished or was cancelled."""
        logger.debug("Cleanup_upload called.")
        with self._operation_lock:
            progress_dialog = self.current_progress
            worker = self.current_worker
            
            self.current_progress = None
            self.current_worker = None
            
            if progress_dialog:
                try:
                    logger.debug("Closing progress dialog in cleanup_upload.")
                    progress_dialog.close()
                except Exception as e:
                    logger.error(f"Error closing progress dialog in cleanup_upload: {str(e)}")
            
            if worker:
                try:
                    if worker.isRunning():
                        logger.warning("Upload worker was still running during cleanup_upload. Attempting to wait.")
                        worker.wait(500) # Brief wait
                        if worker.isRunning():
                             logger.warning("Terminating worker in cleanup_upload as it's still running.")
                             worker.terminate() # Last resort
                    logger.debug("Deleting worker in cleanup_upload.")
                    worker.deleteLater() # Important for QObject cleanup
                except Exception as e:
                    logger.error(f"Error cleaning up worker in cleanup_upload: {str(e)}")
                    
            self.is_operation_cancelled = False # Reset for next operation
            logger.debug("Upload resources cleaned up.")
            
    def cancel_upload(self):
        """Handle upload cancellation"""
        logger.info("Upload cancellation requested by user.")
        try:
            with self._operation_lock:
                if not self.is_operation_cancelled:
                    self.is_operation_cancelled = True
                    
                    worker = self.current_worker
                    progress_dialog = self.current_progress # Renamed for clarity
                    
                    self.current_worker = None
                    self.current_progress = None
                    
                    if worker and worker.isRunning():
                        logger.info("Signaling upload worker to cancel...")
                        worker.cancel() # This should signal the worker's internal loop
                        # Worker should clean itself up on cancel by emitting finished signal
                    
                    if progress_dialog:
                        try:
                            progress_dialog.close()
                        except Exception as e:
                            logger.error(f"Error closing progress dialog during upload cancel: {str(e)}")
            logger.info("Upload cancellation processed.")
        except Exception as e:
            logger.error(f"Error in cancel_upload: {str(e)}", exc_info=True)

    def _process_ui_updates(self):
        """Process pending UI updates and cleanup with improved performance"""
        try:
            with self._operation_lock:
                # Check download process
                if self.current_download and not self.current_download.process.state() == QProcess.Running:
                    self._cleanup_worker()
                
                # Check upload worker
                if self.current_worker and not self.current_worker.isRunning():
                    self.cleanup_upload()
                    
                # Process events less frequently
                if not hasattr(self, '_last_event_process'):
                    self._last_event_process = 0
                    
                current_time = time.time()
                if current_time - self._last_event_process >= 0.1:  # Process events every 100ms
                    QApplication.processEvents()
                    self._last_event_process = current_time
        except Exception as e:
            logger.error(f"Error in UI update processing: {str(e)}")

    def _delayed_cleanup(self):
        """Perform cleanup operations in a non-blocking way"""
        try:
            with self._operation_lock:
                # Clean up download process
                if self.current_download:
                    try:
                        if self.current_download.process.state() == QProcess.Running:
                            self.current_download.stop()
                        self.current_download.deleteLater()
                    except Exception as e:
                        logger.error(f"Error cleaning up download process: {str(e)}")
                    finally:
                        self.current_download = None

                # Clean up upload worker
                if self.current_worker:
                    try:
                        if self.current_worker.isRunning():
                            self.current_worker.terminate()
                            self.current_worker.wait(1000)
                        self.current_worker.deleteLater()
                    except Exception as e:
                        logger.error(f"Error cleaning up upload worker: {str(e)}")
                    finally:
                        self.current_worker = None

                # Clean up progress dialog
                if self.current_progress:
                    try:
                        self.current_progress.close()
                    except Exception as e:
                        logger.error(f"Error closing progress dialog: {str(e)}")
                    finally:
                        self.current_progress = None

                self.is_operation_cancelled = False
                
                # Process events to keep UI responsive
                QApplication.processEvents()
        except Exception as e:
            logger.error(f"Error in delayed cleanup: {str(e)}")

    def closeEvent(self, event):
        """Handle window close with improved cleanup"""
        logger.info("Close event triggered. Starting graceful shutdown.")
        
        try:
            # Stop all timers first
            for timer_name in ['timer', '_ui_update_timer', '_cleanup_timer', 'peer_health_check_timer']:
                if hasattr(self, timer_name):
                    timer = getattr(self, timer_name)
                    if timer.isActive():
                        timer.stop()
                        logger.debug(f"Stopped timer: {timer_name}")
            
            # Stop discovery service
            self._discovery_running = False
            if hasattr(self, 'discovery'):
                self.discovery.unregister()
            
            # Cancel any ongoing operations with timeout
            if hasattr(self, 'current_worker') and self.current_worker:
                self.current_worker.cancel()
                if not self.current_worker.wait(3000):  # Wait up to 3 seconds
                    logger.warning("Worker did not finish in time, forcing termination")
                    self.current_worker.terminate()
            
            # Clean up peer connections
            for peer_addr in list(self.peer_tokens.keys()):
                self._remove_peer(peer_addr)
            
            # Process any pending events
            QApplication.processEvents()
            
            # Accept the close event
            event.accept()
            
            # Start final cleanup
            logger.info("Starting final cleanup...")
            try:
                # Force quit after cleanup
                QApplication.quit()
            except Exception as e:
                logger.error(f"Error during final cleanup: {e}")
            finally:
                logger.info("Final cleanup completed")
                
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}", exc_info=True)
            # Ensure application exits even if cleanup fails
            QApplication.quit()

    def on_peer_selected(self, item):
        """Handle peer selection"""
        self.current_peer = item.text()
        self.refresh_peer_files()

    def update_peer_list(self):
        """Update the peer list with improved error handling and status updates"""
        try:
            current_time = datetime.now()
            if (current_time - self.last_peer_update).total_seconds() < self.peer_update_interval:
                return  # Skip update if not enough time has passed
                
            self.last_peer_update = current_time
            peers = self.discovery.get_peers()
            
            # Update peer status
            if not peers:
                self.peer_status.setText("No peers discovered")
                self.peer_status.setStyleSheet("color: gray;")
            else:
                self.peer_status.setText(f"Discovered {len(peers)} peer(s)")
                self.peer_status.setStyleSheet("color: black;")
            
            # Get current items for comparison
            current_items = set()
            for i in range(self.peers_list.count()):
                item = self.peers_list.item(i)
                if item:
                    current_items.add(item.text())
            
            # Track new peers to add
            new_peers = set()
            
            # Process each discovered peer
            for peer_id, (ip, port) in peers.items():
                peer_text = f"{peer_id} ({ip}:{port})"
                new_peers.add(peer_text)
                
                # Add peer if not already in list
                if peer_text not in current_items:
                    try:
                        item = QListWidgetItem(peer_text)
                        try:
                            item.setIcon(QIcon.fromTheme("network-wireless"))
                        except:
                            pass  # Icon not available, continue without it
                        
                        # Add peer immediately with gray color (will be updated in background)
                        item.setForeground(Qt.gray)
                        self.peers_list.addItem(item)
                        logger.info(f"Added new peer to list: {peer_text}")
                        
                        # Start background online check
                        QTimer.singleShot(0, lambda p_text=peer_text, p_ip=ip, p_port=port: self._check_peer_online(p_text, p_ip, p_port))
                    except Exception as e:
                        logger.error(f"Error adding peer {peer_text}: {str(e)}")
                        continue
            
            # Remove peers that are no longer in discovery list
            for i in range(self.peers_list.count() - 1, -1, -1):
                item = self.peers_list.item(i)
                if item and item.text() not in new_peers:
                    peer_addr = item.text().split("(")[-1].strip(")")
                    self.peers_list.takeItem(i)
                    if peer_addr in self.peer_tokens:
                        del self.peer_tokens[peer_addr]
                    self.offline_peers.discard(item.text())
                    logger.info(f"Removed peer from list: {item.text()}")
            
            # Log current state
            logger.info(f"Peer list updated. Current peers: {list(new_peers)}")
            logger.debug(f"Offline peers: {list(self.offline_peers)}")
            
            # Force UI update
            self.peers_list.viewport().update()
            
        except Exception as e:
            logger.error(f"Error updating peer list: {str(e)}", exc_info=True)
            QTimer.singleShot(0, lambda: QMessageBox.warning(
                self, "Peer Update Error",
                "Failed to update peer list. Some peers may not be visible."
            ))

    def _check_peer_online(self, peer_text: str, ip: str, port: int):
        """Check peer online status in background and update UI"""
        try:
            is_online = self.is_peer_online(ip, port)
            items = self.peers_list.findItems(peer_text, Qt.MatchExactly)
            if items:
                item = items[0]
                if is_online:
                    item.setForeground(Qt.black)
                    if peer_text in self.offline_peers:
                        self.offline_peers.discard(peer_text)
                        logger.info(f"Peer is back online: {peer_text}")
                else:
                    item.setForeground(Qt.gray)
                    if peer_text not in self.offline_peers:
                        self.offline_peers.add(peer_text)
                        logger.debug(f"Peer is offline: {peer_text}")
        except Exception as e:
            logger.error(f"Error checking peer status {peer_text}: {str(e)}")

    def is_peer_online(self, ip: str, port: int) -> bool:
        """Check if a peer is online with improved reliability"""
        try:
            # Try to ping the peer with increased timeout and better error handling
            session = requests.Session()
            session.verify = False  # Disable SSL verification for local network
            
            # Set a reasonable timeout
            timeout = (3, 5)  # (connect timeout, read timeout)
            
            # Add retry strategy
            retry_strategy = requests.adapters.Retry(
                total=2,  # number of retries
                backoff_factor=0.5,  # wait 0.5, 1, 2... seconds between retries
                status_forcelist=[500, 502, 503, 504]  # HTTP status codes to retry on
            )
            adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
            session.mount("https://", adapter)
            
            r = session.get(
                f"https://{ip}:{port}/ping",
                timeout=timeout,
                headers={"User-Agent": "P2PShare/1.0"}
            )
            
            if r.ok:
                try:
                    data = r.json()
                    if data.get("status") == "online":
                        logger.debug(f"Peer {ip}:{port} is online")
                        return True
                except ValueError:
                    logger.debug(f"Peer {ip}:{port} returned invalid JSON")
                    return False
                    
            logger.debug(f"Peer {ip}:{port} returned status {r.status_code}")
            return False
            
        except requests.exceptions.SSLError as e:
            # SSL errors are expected in local network with self-signed certs
            logger.debug(f"SSL error checking peer {ip}:{port}: {str(e)}")
            return True  # Consider SSL errors as "online" since the server is responding
            
        except requests.exceptions.ConnectionError as e:
            # Connection errors indicate the peer is truly offline
            logger.debug(f"Connection error checking peer {ip}:{port}: {str(e)}")
            return False
            
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout checking peer {ip}:{port}")
            return False
            
        except Exception as e:
            logger.error(f"Error checking peer {ip}:{port}: {str(e)}")
            return False
            
        finally:
            session.close()

    def get_peer_token(self, ip: str, port: int) -> str:
        """Get or refresh token for a peer with improved reliability"""
        peer_addr = f"{ip}:{port}"
        current_time = datetime.now()
        
        try:
            # Check if we have a valid cached token
            if peer_addr in self.peer_tokens:
                last_check = self.last_peer_check.get(peer_addr)
                if last_check and (current_time - last_check).total_seconds() < self.peer_check_timeout:
                    return self.peer_tokens[peer_addr]
            
            # Check connection attempts
            attempts = self.peer_connection_attempts.get(peer_addr, 0)
            if attempts >= self.max_connection_attempts:
                last_success = self.peer_last_success.get(peer_addr)
                if not last_success or (current_time - last_success).total_seconds() < self.peer_retry_delay:
                    logger.warning(f"Too many failed attempts for peer {peer_addr}")
                    QMessageBox.warning(
                        self, "Connection Error",
                        f"Too many failed connection attempts to {peer_addr}. Please try again later."
                    )
                    return None
            
            # Check if peer is online
            if not self.is_peer_online(ip, port):
                self.peer_connection_attempts[peer_addr] = attempts + 1
                logger.warning(f"Peer {peer_addr} is offline")
                self.offline_peers.add(peer_addr)
                QMessageBox.warning(
                    self, "Connection Error",
                    f"Peer {peer_addr} is offline. Please try again later."
                )
                return None
            
            # Try to get a new token with retry logic
            session = requests.Session()
            session.verify = False
            
            retry_strategy = requests.adapters.Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504]
            )
            adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
            session.mount("https://", adapter)
            
            try:
                r = session.post(
                    f"https://{ip}:{port}/auth",
                    json={"device_id": settings.device_id},
                    timeout=(3, 5)
                )
                r.raise_for_status()
                
                token = r.json()["token"]
                self.peer_tokens[peer_addr] = token
                self.last_peer_check[peer_addr] = current_time
                self.peer_last_success[peer_addr] = current_time
                self.peer_connection_attempts[peer_addr] = 0
                self.offline_peers.discard(peer_addr)
                
                logger.debug(f"Successfully obtained token for {peer_addr}")
                return token
                
            except requests.exceptions.HTTPError as e:
                self.peer_connection_attempts[peer_addr] = attempts + 1
                logger.warning(f"HTTP error getting token: {str(e)}")
                QMessageBox.warning(
                    self, "Authentication Error",
                    f"Server returned an error: {e.response.status_code}"
                )
                return None
                
            except requests.exceptions.Timeout:
                self.peer_connection_attempts[peer_addr] = attempts + 1
                logger.warning(f"Timeout getting token from {peer_addr}")
                QMessageBox.warning(
                    self, "Connection Timeout",
                    f"Connection to {peer_addr} timed out. Please try again."
                )
                return None
                
            except requests.exceptions.ConnectionError:
                self.peer_connection_attempts[peer_addr] = attempts + 1
                logger.warning(f"Connection error getting token from {peer_addr}")
                self.offline_peers.add(peer_addr)
                QMessageBox.warning(
                    self, "Connection Error",
                    f"Could not connect to {peer_addr}. The peer may be offline."
                )
                return None
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error getting token from {peer_addr}: {str(e)}", exc_info=True)
            QMessageBox.warning(
                self, "Authentication Error",
                f"An unexpected error occurred: {str(e)}"
            )
            return None

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
                    logger.error(f"Error cleaning up download process: {str(e)}")
                finally:
                    self.current_download = None

            if self.current_progress:
                try:
                    self.current_progress.close()
                except Exception as e:
                    logger.error(f"Error closing progress dialog: {str(e)}")
                finally:
                    self.current_progress = None

            self.is_operation_cancelled = False
        except Exception as e:
            logger.error(f"Error in worker cleanup: {str(e)}")

    def _check_peer_health(self):
        """Periodically check health of connected peers"""
        try:
            current_time = datetime.now()
            peers_to_remove = set()
            
            for peer_text in list(self.peer_tokens.keys()):
                try:
                    ip_port = peer_text.split("(")[-1].strip(")")
                    ip, port = ip_port.split(":")
                    
                    # Skip if we've tried too many times recently
                    attempts = self.peer_connection_attempts.get(peer_text, 0)
                    last_success = self.peer_last_success.get(peer_text)
                    
                    if attempts >= self.max_connection_attempts:
                        if last_success and (current_time - last_success).total_seconds() < self.peer_retry_delay:
                            continue
                        # Reset attempts if enough time has passed
                        self.peer_connection_attempts[peer_text] = 0
                    
                    # Check peer status
                    if self.is_peer_online(ip, port):
                        self.peer_last_success[peer_text] = current_time
                        self.peer_connection_attempts[peer_text] = 0
                        if peer_text in self.offline_peers:
                            self.offline_peers.remove(peer_text)
                            logger.info(f"Peer {peer_text} is back online")
                    else:
                        self.peer_connection_attempts[peer_text] = attempts + 1
                        if peer_text not in self.offline_peers:
                            self.offline_peers.add(peer_text)
                            logger.warning(f"Peer {peer_text} is offline (attempt {attempts + 1})")
                        
                        # Remove peer if too many failed attempts
                        if attempts >= self.max_connection_attempts:
                            peers_to_remove.add(peer_text)
                            
                except Exception as e:
                    logger.error(f"Error checking peer health for {peer_text}: {str(e)}")
                    continue
            
            # Remove failed peers
            for peer_text in peers_to_remove:
                self._remove_peer(peer_text)
                
        except Exception as e:
            logger.error(f"Error in peer health check: {str(e)}")

    def _remove_peer(self, peer_text):
        """Safely remove a peer from all tracking structures"""
        try:
            # Remove from UI
            items = self.peers_list.findItems(peer_text, Qt.MatchExactly)
            if items:
                self.peers_list.takeItem(self.peers_list.row(items[0]))
            
            # Remove from tracking structures
            ip_port = peer_text.split("(")[-1].strip(")")
            if ip_port in self.peer_tokens:
                del self.peer_tokens[ip_port]
            if ip_port in self.last_peer_check:
                del self.last_peer_check[ip_port]
            if peer_text in self.peer_connection_attempts:
                del self.peer_connection_attempts[peer_text]
            if peer_text in self.peer_last_success:
                del self.peer_last_success[peer_text]
            self.offline_peers.discard(peer_text)
            
            logger.info(f"Removed peer: {peer_text}")
            
        except Exception as e:
            logger.error(f"Error removing peer {peer_text}: {str(e)}")


def run():
    logger.info("Starting P2PShare application")
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    logger.info("Main window displayed")
    sys.exit(app.exec_())


if __name__ == "__main__":
    run()
