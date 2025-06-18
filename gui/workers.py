import os
import sys
import time
import json
import requests
import threading
import base64
import zipfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import platform # To detect OS for drive listing

from PyQt5.QtCore import QThread, pyqtSignal, QProcess, QObject
from PyQt5.QtWidgets import QInputDialog, QMessageBox, QLineEdit

# Import shared components needed by workers
from shared.security_manager import SecurityManager
from shared.config import CONFIG_DIR, settings # Assuming settings.device_id is needed
from shared.logging_config import setup_logger

logger = setup_logger(__name__)

# Initialize security_manager for workers as they need it for encryption/decryption
# This instance will be shared. The key needs to be explicitly set on it.
security_manager = SecurityManager(CONFIG_DIR)


class ProgressFileReader:
    """
    A file-like object wrapper that provides progress updates during read operations.
    Designed for streaming file content (e.g., in HTTP requests).
    """
    def __init__(self, file_obj, total_size, progress_callback, cancellation_check_callable, start_progress=0):
        self.file_obj = file_obj
        self.total_size = total_size
        self.progress_callback = progress_callback
        self.cancellation_check_callable = cancellation_check_callable # New: Callable to check for cancellation
        self.bytes_read = 0
        self.start_progress = start_progress
        self._last_progress_update = 0
        self._progress_update_interval = 0.1  # Update every 100ms
        self._chunk_size = 1024 * 1024  # Use 1MB chunks for better performance
        self._buffer = b''  # Buffer for partial chunks
        self._is_closed = False
        self._eof = False  # Track EOF state

    def read(self, size=None):
        """Read data from the file with improved streaming reliability and cancellation support."""
        if self._is_closed:
            return b''

        if self.cancellation_check_callable and self.cancellation_check_callable():
            logger.info("Read operation cancelled by external signal.")
            self._is_closed = True
            return b''

        try:
            # If we have buffered data and it's enough for the requested size
            if self._buffer:
                if size is None:
                    data = self._buffer
                    self._buffer = b''
                    self._update_progress(len(data))
                    return data
                elif len(self._buffer) >= size:
                    data = self._buffer[:size]
                    self._buffer = self._buffer[size:]
                    self._update_progress(len(data))
                    return data

            # If we've reached EOF and have no buffer, return empty
            if self._eof and not self._buffer:
                self._is_closed = True
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
            logger.error(f"Error reading file with progress: {str(e)}")
            self._is_closed = True
            raise

    def _update_progress(self, bytes_read):
        """Update progress with throttling to avoid excessive signal emissions."""
        self.bytes_read += bytes_read
        current_time = time.time()
        
        if (current_time - self._last_progress_update >= self._progress_update_interval or 
            self.bytes_read == self.total_size):
            progress = self.start_progress + int((self.bytes_read / self.total_size) * (100 - self.start_progress))
            self.progress_callback(progress, f"Transferring: {progress}%")
            self._last_progress_update = current_time

    def __len__(self):
        return self.total_size

    def close(self):
        """Close the underlying file object."""
        if not self._is_closed:
            self._is_closed = True
            try:
                self.file_obj.close()
            except Exception: # Catch any error on close
                pass

    def __del__(self):
        """Ensure file is closed on deletion."""
        self.close()


class UploadWorker(QThread):
    """
    Worker thread for file/folder uploads. Encrypts files before sending them
    to a peer's server via HTTP requests. Provides progress updates.
    Now supports uploading to any accessible absolute path on the remote peer.
    """
    progress = pyqtSignal(int, str)  # progress percentage, status message
    finished = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, ip: str, port: int, token: str, source_path: str, dest_path: str, is_folder: bool, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self.token = token
        self.source_path = str(Path(source_path).resolve()) # Source path is local absolute
        self.dest_path = dest_path # Dest path is remote absolute (passed as is)
        self.is_folder = is_folder
        self._is_cancelled = False # Internal flag for cancellation
        
        # Initialize requests session with SSL verification disabled and retry strategy
        self._session = requests.Session()
        self._session.verify = False # Disable SSL verification for local network
        self._session.headers.update({"Authorization": f"Bearer {token}"})
        
        retry_strategy = requests.adapters.Retry(
            total=2, # Number of retries
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504] # HTTP status codes to retry on
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("https://", adapter)

        # --- IMPORTANT: Ensure security_manager has the key in this thread's context ---
        # The key is loaded in main.py and stored in the global security_manager.
        # We need to explicitly tell this thread's context to use it if not already set.
        encryption_key_bytes = security_manager.get_encryption_key() # Get the key loaded by main.py
        if encryption_key_bytes:
            security_manager.set_encryption_key(encryption_key_bytes) # Set it for this thread's operations
            logger.debug("UploadWorker: Encryption key set for worker thread.")
        else:
            logger.error("UploadWorker: Encryption key NOT available. Uploads will fail encryption step.")
            # Set a flag or raise error in run() to prevent actual upload attempt
            self._encryption_key_missing = True # Custom flag
        # --- End IMPORTANT ---


    def run(self):
        """Main execution method for the thread. Handles upload logic."""
        try:
            # Check the custom flag set in __init__
            if hasattr(self, '_encryption_key_missing') and self._encryption_key_missing:
                raise ValueError("Encryption key is not loaded for UploadWorker. Cannot upload securely.")

            logger.info(f"Starting upload worker for {'folder' if self.is_folder else 'file'}: {self.source_path} to {self.dest_path}")
            if self.is_folder:
                self.upload_folder()
            else:
                self.upload_file()
        except InterruptedError:
            logger.info(f"Upload operation cancelled by user for {self.source_path}.")
            self.finished.emit(False, "Upload cancelled.")
        except ValueError as ve: # Catching specific ValueError from encryption key missing or general issues
            logger.error(f"Upload initialization error: {ve}", exc_info=True)
            self.finished.emit(False, f"Upload failed: {ve}. (Encryption key missing or invalid input?)")
        except Exception as e:
            if not self._is_cancelled: # Only report error if not cancelled by user
                logger.error(f"Upload unexpected error: {str(e)}", exc_info=True)
                self.finished.emit(False, f"Upload failed: {str(e)}")
        finally:
            self._session.close() # Ensure session is closed when thread finishes
    
    def cancel(self):
        """Sets the internal cancellation flag to stop the upload process."""
        logger.info("Upload cancellation requested internally or by user.")
        self._is_cancelled = True
        # Close the session to interrupt any ongoing requests
        try:
            self._session.close()
        except Exception as e:
            logger.debug(f"Error closing session during cancellation: {e}")
    
    def _cancellation_check(self) -> bool:
        """Callable for ProgressFileReader to check if cancellation is requested."""
        return self._is_cancelled

    def _progress_reader(self, file_obj, total_size, start_progress=0):
        """Wraps a file object to provide progress updates during read operations."""
        return ProgressFileReader(file_obj, total_size, self.progress.emit, self._cancellation_check, start_progress)
        
    def upload_file(self):
        """Encrypts a single file and uploads it to the peer."""
        if self._is_cancelled:
            return
            
        temp_encrypted_path = None
        try:
            filename = Path(self.source_path).name
            
            logger.info(f"Preparing file for upload (encrypting): {filename}")
            self.progress.emit(0, f"Encrypting {filename}...")

            # Read original content
            with open(self.source_path, 'rb') as f_read:
                original_data = f_read.read()

            # Encrypt data
            encrypted_data = security_manager.encrypt_data(original_data)
            encrypted_size = len(encrypted_data)
            
            # Write encrypted data to a temporary file for streaming
            with tempfile.NamedTemporaryFile(delete=False, dir=CONFIG_DIR) as temp_enc_file:
                temp_encrypted_path = Path(temp_enc_file.name)
                temp_enc_file.write(encrypted_data)
            
            logger.debug(f"Encrypted file written to temp: {temp_encrypted_path}, size: {encrypted_size} bytes")
            self.progress.emit(10, f"Encrypted {filename}...") # Update progress after encryption
            
            with open(temp_encrypted_path, "rb") as f_encrypted:
                progress_file_reader = self._progress_reader(f_encrypted, encrypted_size, start_progress=10) # Start progress from 10%
                files = {
                    "file": (filename, progress_file_reader, "application/octet-stream")
                }
                data = {
                    "dest_path": self.dest_path # dest_path is now absolute on remote
                }
                
                try:
                    self.progress.emit(10, "Starting upload...")
                    r = self._session.put(
                        f"https://{self.ip}:{self.port}/upload/{filename}",
                        files=files,
                        data=data, # For other form data
                        timeout=30 # Connect and read timeout
                    )
                    
                    if self._is_cancelled:
                        logger.info("Upload cancelled after request was made.")
                        raise InterruptedError("Upload cancelled by user.")
                        
                    if r.ok:
                        response = r.json()
                        logger.info(f"Encrypted file uploaded successfully to {response['path']}")
                        self.progress.emit(100, "Upload complete")
                        self.finished.emit(True, f"File uploaded successfully to {response['path']}")
                    else:
                        error_msg = f"Upload failed: {r.status_code}"
                        if r.text:
                            try:
                                error_detail = r.json().get("detail", r.text)
                                error_msg += f" - {error_detail}"
                            except json.JSONDecodeError:
                                error_msg += f" - {r.text}"
                        logger.error(error_msg)
                        self.finished.emit(False, error_msg)
                except requests.exceptions.Timeout:
                    if not self._is_cancelled:
                        logger.error("Upload timed out")
                        self.finished.emit(False, "Upload timed out.")
                except requests.exceptions.ConnectionError as e:
                    if not self._is_cancelled:
                        logger.error(f"Connection error: {str(e)}")
                        self.finished.emit(False, "Connection lost during upload.")
                except InterruptedError:
                    # Re-raise InterruptedError to be caught by run()
                    raise
                except Exception as e:
                    if not self._is_cancelled:
                        logger.error(f"Upload HTTP request error: {str(e)}", exc_info=True)
                        self.finished.emit(False, f"Upload error during transfer: {str(e)}")
        except ValueError as ve: # Catch encryption key errors or other validation issues
            logger.error(f"Encryption error for {filename}: {ve}", exc_info=True)
            self.finished.emit(False, f"Upload failed: Encryption error ({ve}).")
        except InterruptedError:
            raise # Propagate cancellation
        except Exception as e:
            if not self._is_cancelled:
                logger.error(f"Error preparing upload: {str(e)}", exc_info=True)
                self.finished.emit(False, f"Error preparing upload: {str(e)}")
        finally:
            if temp_encrypted_path and temp_encrypted_path.exists():
                os.unlink(temp_encrypted_path)
                logger.debug(f"Cleaned up temporary encrypted file: {temp_encrypted_path}")
    
    def _validate_zip_file(self, zip_path: Path):
        """Validate zip file integrity and contents (after encryption)."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # Test zip file integrity
                if zipf.testzip() is not None:
                    raise ValueError("Zip file integrity check failed")
                
                # Check if zip file is not empty
                if not zipf.namelist():
                    raise ValueError("Zip file is empty")
                
                # Check for maximum file size (e.g., 2GB of encrypted data)
                total_size = zip_path.stat().st_size
                if total_size > 2 * 1024 * 1024 * 1024:  # 2GB limit for the encrypted zip
                    raise ValueError(f"Zip file exceeds maximum size limit of 2GB (actual: {total_size} bytes)")
                
                # Validate file paths and names within the zip
                for name in zipf.namelist():
                    # Check for absolute paths - these should have been prevented during zip creation
                    if name.startswith('/') or name.startswith('\\') or (platform.system() == "Windows" and Path(name).drive):
                        raise ValueError(f"Invalid path in zip: {name} (contains absolute path or drive letter)")
                    
                    # Check for parent directory references
                    if '..' in Path(name).parts: # Use Path.parts for robust check
                        raise ValueError(f"Invalid path in zip: {name} (contains parent directory reference)")
                    
                    # Check for invalid characters in filenames (basic check, more comprehensive regex needed for strict compliance)
                    invalid_chars = '<>:"|?*\n\r' # Added newline/carriage return
                    if any(char in name for char in invalid_chars):
                        raise ValueError(f"Invalid characters in filename: {name}")
                    
                    # Check for maximum path length (Windows limit)
                    if len(name) > 260: # Max path length for Windows API without extended path prefix
                        raise ValueError(f"Path too long: {name}")
                
                return True
        except zipfile.BadZipFile:
            raise ValueError("Invalid zip file format (corrupted or not a zip)")
        except Exception as e:
            raise ValueError(f"Zip file validation failed: {str(e)}")

    def _create_zip_file(self, source_path: Path, temp_dir: Path) -> Path:
        """
        Creates a zip file from a source folder, encrypting each file's content
        before adding it to the zip. Provides progress updates.
        Handles source_path being a drive root on Windows (e.g., C:/).
        """
        zip_name = source_path.name if source_path.name else source_path.drive.replace(':', '') # Handle drive root
        zip_path = temp_dir / f"{zip_name}.zip"
        logger.debug(f"Creating zip file at: {zip_path}")
        
        try:
            total_original_size = 0
            files_to_zip_info = [] # (file_path, arcname, original_size)
            
            # First pass: collect file info and calculate total original size
            for root, _, files in os.walk(source_path):
                for file_name in files:
                    if self._is_cancelled:
                        raise InterruptedError("Folder upload cancelled during file scanning.")
                    try:
                        file_path = Path(root) / file_name
                        if not file_path.exists() or not os.access(file_path, os.R_OK):
                            logger.warning(f"Skipping inaccessible file: {file_path}")
                            continue
                        
                        # Calculate arcname (path within the zip file)
                        # If zipping a drive root (e.g. C:/), need special handling
                        if source_path.is_absolute() and not source_path.name: # It's a drive root
                            # Archive should start with the drive letter as a folder
                            arcname = Path(source_path.drive.replace(':', '')) / file_path.relative_to(source_path)
                        else:
                            # Standard relative path from the folder being zipped
                            arcname = file_path.relative_to(source_path)
                        
                        arcname = arcname.as_posix() # Use as_posix() for forward slashes in zip
                            
                        original_file_size = file_path.stat().st_size
                        total_original_size += original_file_size
                        files_to_zip_info.append((file_path, arcname, original_file_size))
                            
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Error accessing file {file_path}: {str(e)}")
                        continue
            
            if total_original_size == 0 and not files_to_zip_info: # Ensure it's not empty even if 0 size
                raise ValueError("No valid files found in folder to zip.")
            
            processed_original_size = 0
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zipf:
                for file_path, arcname, original_file_size in files_to_zip_info:
                    if self._is_cancelled:
                        raise InterruptedError("Folder upload cancelled during zip creation.")
                        
                    try:
                        with open(file_path, 'rb') as f_read:
                            original_data = f_read.read()

                        # Encrypt data
                        encrypted_data = security_manager.encrypt_data(original_data)
                        
                        # Add encrypted data to the zip using the sanitized relative path
                        zipf.writestr(arcname, encrypted_data)
                        
                        processed_original_size += original_file_size
                        # Progress for zipping/encryption is first 50%
                        progress = int((processed_original_size / total_original_size) * 50) if total_original_size > 0 else 0
                        self.progress.emit(progress, f"Preparing folder (encrypting): {progress}%")
                            
                    except Exception as e:
                        logger.error(f"Error encrypting or adding file {file_path} to zip: {str(e)}", exc_info=True)
                        raise # Re-raise to ensure error is handled
            
            # Validate the created zip file
            self._validate_zip_file(zip_path)
            logger.info(f"Zip file '{zip_path.name}' created successfully with encrypted contents.")
            return zip_path
                
        except InterruptedError:
            # If cancelled, clean up partially created zip file
            if zip_path.exists():
                os.unlink(zip_path)
            raise
        except Exception as e:
            # Clean up zip file if an error occurred during its creation
            if zip_path.exists():
                try:
                    os.unlink(zip_path)
                except Exception as cleanup_e:
                    logger.error(f"Error cleaning up partial zip file {zip_path}: {cleanup_e}")
            raise e

    def upload_folder(self):
        """Uploads an entire folder (zipped and encrypted) to the peer."""
        if self._is_cancelled:
            return
            
        temp_zip_dir = None
        try:
            folder_name = Path(self.source_path).name
            if not folder_name: # Handle case where source_path is a drive root like C:/
                folder_name = Path(self.source_path).drive.replace(':', '')
            
            logger.info(f"Starting folder upload: {folder_name} from local '{self.source_path}' to remote '{self.dest_path}'")
            
            # Create a temporary directory for the zip file using tempfile.TemporaryDirectory
            with tempfile.TemporaryDirectory(dir=CONFIG_DIR) as temp_dir_str:
                temp_zip_dir = Path(temp_dir_str)
                # Create and validate zip file (now includes encryption)
                zip_path = self._create_zip_file(Path(self.source_path), temp_zip_dir)
                
                max_retries = 3
                retry_count = 0
                last_error = None
                base_wait_time = 2
                
                while retry_count < max_retries and not self._is_cancelled:
                    try:
                        file_size = zip_path.stat().st_size # Size of the *encrypted* zip file
                        logger.info(f"Uploading encrypted zip file: {zip_path.name}, size: {file_size} bytes")
                        
                        # Open the zip file in binary mode for streaming
                        with open(zip_path, 'rb') as f:
                            # Create a streaming upload with progress tracking
                            # Progress starts from 50% as zipping/encryption took the first 50%
                            progress_file_reader = self._progress_reader(f, file_size, 50) 
                            
                            self.progress.emit(50, "Starting folder upload...")
                            
                            # Encode headers properly for Unicode characters and for folder upload
                            headers = {
                                "Authorization": f"Bearer {self.token}",
                                "Content-Type": "application/octet-stream", # Binary stream
                                "X-Folder-Name": base64.b64encode(folder_name.encode('utf-8')).decode('ascii'),
                                "X-Dest-Path": base64.b64encode(self.dest_path.encode('utf-8')).decode('ascii')
                            }
                            # Update session headers
                            self._session.headers.update(headers)

                            # Use streaming upload with increased timeouts for large files
                            r = self._session.post(
                                f"https://{self.ip}:{self.port}/upload-folder",
                                data=progress_file_reader,
                                timeout=(30, 600),  # (connect timeout, read timeout up to 10 minutes)
                                stream=True  # Enable streaming mode for large uploads
                            )
                            
                            if self._is_cancelled:
                                logger.info("Upload cancelled during transfer.")
                                raise InterruptedError("Upload cancelled during transfer.")
                                
                            if r.ok:
                                response = r.json()
                                logger.info(f"Folder uploaded successfully to {response['path']}")
                                self.progress.emit(100, "Upload complete")
                                self.finished.emit(True, f"Folder uploaded successfully to {response['path']}")
                                return # Exit on success
                            else:
                                error_msg = f"Folder upload failed: {r.status_code}"
                                if r.text:
                                    try:
                                        error_detail = r.json().get("detail", r.text)
                                        error_msg += f" - {error_detail}"
                                    except json.JSONDecodeError:
                                        error_msg += f" - {r.text}"
                                    
                                logger.error(f"HTTP Error during folder upload: {error_msg}")
                                raise requests.exceptions.HTTPError(error_msg) # Re-raise as HTTPError for retry logic
                                
                    except (requests.exceptions.RequestException, ValueError, PermissionError, InterruptedError) as e:
                        # These errors are either network issues, validation failures, or user cancellations
                        if isinstance(e, InterruptedError): # Always re-raise InterruptedError directly
                            raise
                        
                        retry_count += 1
                        last_error = str(e)
                        
                        if retry_count < max_retries:
                            wait_time = base_wait_time * (2 ** (retry_count - 1)) # Exponential backoff
                            logger.warning(f"Folder upload attempt {retry_count} failed: {str(e)}. Retrying in {wait_time} seconds...")
                            time.sleep(wait_time)
                        else:
                            # If max retries reached, raise the last error
                            raise Exception(f"Folder upload failed after {max_retries} attempts. Last error: {last_error}") from e
                            
                # If loop finishes due to cancellation or successful upload, this won't be reached.
                # If it finishes due to max_retries, the last exception will be raised.
        
        except InterruptedError:
            logger.info("Folder upload cancelled by user.")
            self.finished.emit(False, "Upload cancelled by user.")
        except ValueError as e: # From zip creation or validation
            logger.error(f"Validation or encryption error during folder upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: {str(e)}")
        except PermissionError as e:
            logger.error(f"Permission error during folder upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: Permission error - {str(e)}")
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during folder upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: Timeout - {str(e)}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during folder upload: {str(e)}")
            self.finished.emit(False, f"Upload failed: Connection lost - {str(e)}")
        except Exception as e:
            if not self._is_cancelled:
                logger.error(f"Unexpected error during folder upload: {str(e)}", exc_info=True)
                self.finished.emit(False, f"Upload failed: {str(e)}")


class DownloadProcess(QObject):
    """
    Manages the download process by spawning a separate Python process
    to handle the actual file transfer, decryption, and saving.
    Communicates with the subprocess via stdout for progress updates.
    Now supports downloading from any absolute path on the remote peer.
    """
    progress = pyqtSignal(int, str)  # progress percentage, status message
    finished = pyqtSignal(bool, str)  # success, message
    cleanup = pyqtSignal()  # signal to main window to clean up resources
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self._handle_output)
        self.process.finished.connect(self._handle_finished)
        self.process.errorOccurred.connect(self._handle_process_error)
        self.is_running = False
        self._last_progress_update = 0
        self._progress_update_interval = 0.1  # Update every 100ms
        
    def start_download(self, ip: str, port: int, token: str, items: list, download_dir: str, is_folder: bool):
        """
        Starts the download process by executing `download_script.py` in a new process.
        Passes necessary arguments including the encryption key.
        Items are now lists of [remote_absolute_path, original_name].
        """
        try:
            if self.is_running:
                logger.warning("Download process already running.")
                return
            
            # Get the encryption key from the main process's security_manager
            encryption_key_bytes = security_manager.get_encryption_key()
            if encryption_key_bytes is None:
                logger.error("Download blocked: Encryption key not loaded.")
                for i in range(3):
                    password, ok = QInputDialog.getText(None, "P2PShare Security Login",
                                                        "Enter your security code (password):",
                                                        QLineEdit.Password)
                    if not ok or not password:
                        QMessageBox.warning(None, "Security Warning", "Security code cannot be empty. Please enter your code.")
                        if not ok: 
                            logger.critical("Security code input cancelled. Exiting application.")
                        continue

                    if security_manager.load_security(password):
                        QMessageBox.information(None, "Security Login Success", "Security code accepted!")
                        break
                    else:
                        QMessageBox.warning(None, "Security Warning", "Incorrect security code. Please try again.")
            
            encryption_key_bytes = security_manager.get_encryption_key()
            if encryption_key_bytes is None:
                raise ValueError("Encryption key is not loaded. Cannot download/decrypt files securely.")
            
            # Base64 encode the encryption key to pass it as a command-line argument
            encryption_key_b64 = base64.b64encode(encryption_key_bytes).decode('utf-8')

            # Convert items (list of [remote_path, name]) to base64 encoded JSON
            items_json = json.dumps(items, ensure_ascii=False)
            items_b64 = base64.b64encode(items_json.encode('utf-8')).decode('utf-8')
            
            # Build command to execute the download script
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'download_script.py')
            cmd = [
                sys.executable, # Path to python interpreter
                script_path,
                ip,
                str(port),
                token,
                items_b64,
                download_dir,
                str(is_folder).lower(), # 'true' or 'false'
                encryption_key_b64 # This is the 8th argument (index 7)
            ]
            
            # Debugging: Print the full command list *before* starting the process
            # WARNING: Do not log the key itself in production logs!
            logger.debug(f"DownloadProcess cmd list: {cmd[:-1]} [encryption_key_b64_present: {bool(encryption_key_b64)}]")
            
            # Start the QProcess
            self.process.start(cmd[0], cmd[1:])
            if not self.process.waitForStarted(5000):  # Wait up to 5 seconds for process to start
                raise RuntimeError(f"Failed to start download process. Error: {self.process.errorString()}")
                
            self.is_running = True
            
        except ValueError as ve:
            error_msg = f"Failed to start download: {ve}. (Security key missing or invalid items?)"
            logger.error(error_msg, exc_info=True)
            self.finished.emit(False, error_msg)
            self.cleanup.emit() # Ensure cleanup is triggered
        except Exception as e:
            error_msg = f"Failed to start download process: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.finished.emit(False, error_msg)
            self.cleanup.emit() # Ensure cleanup is triggered

    def stop(self):
        """Stops the underlying QProcess, effectively cancelling the download."""
        logger.info("Stopping download process...")
        if self.process.state() == QProcess.Running:
            try:
                self.process.kill() # Terminate the process forcefully
                if not self.process.waitForFinished(3000): # Wait up to 3 seconds for termination
                    logger.warning("Download process did not finish in time after kill.")
            except Exception as e:
                logger.error(f"Error stopping download process: {str(e)}")
        self.is_running = False
        self.cleanup.emit() # Ensure cleanup signal is emitted upon stopping

    def _handle_output(self):
        """Reads stdout from the subprocess and processes JSON messages (progress, errors)."""
        try:
            output = self.process.readAllStandardOutput().data().decode('utf-8')
            current_time = time.time()
            
            for line in output.splitlines():
                try:
                    data = json.loads(line)
                    if 'progress' in data:
                        # Throttle progress updates to avoid overwhelming the GUI
                        if current_time - self._last_progress_update >= self._progress_update_interval:
                            self.progress.emit(data['progress'], data.get('status', ''))
                            self._last_progress_update = current_time
                    elif 'error' in data:
                        logger.error(f"Download subprocess error: {data['error']}")
                        self.finished.emit(False, data['error'])
                        self.stop() # Stop the process on receiving an error from subprocess
                    elif 'message' in data: # Generic messages from subprocess
                        logger.info(f"Download subprocess message: {data['message']}")
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON output from download process: {line}")
                except Exception as e:
                    logger.error(f"Error processing output line from download process: {str(e)}")
        except Exception as e:
            logger.error(f"Error reading process output: {str(e)}")

    def _handle_finished(self, exit_code: int, exit_status: QProcess.ExitStatus):
        """Handles the completion of the subprocess (normal exit or crash)."""
        try:
            self.is_running = False
            if exit_code == 0:
                self.finished.emit(True, "Download completed successfully")
            else:
                error_msg = f"Download failed with exit code {exit_code}. Exit status: {exit_status}"
                stderr_output = self.process.readAllStandardError().data().decode('utf-8')
                if stderr_output:
                    error_msg += f"\nStderr: {stderr_output.strip()}"
                logger.error(error_msg)
                self.finished.emit(False, error_msg)
        except Exception as e:
            logger.error(f"Error handling process completion: {str(e)}")
        finally:
            self.cleanup.emit() # Always ensure cleanup is triggered

    def _handle_process_error(self, process_error: QProcess.ProcessError):
        """Handles errors directly reported by QProcess (e.g., process failed to start)."""
        try:
            error_msg = f"Download process error: {self.process.errorString()} (Code: {process_error})"
            logger.error(error_msg)
            self.finished.emit(False, error_msg)
        except Exception as e:
            logger.error(f"Error handling QProcess error signal: {str(e)}")
        finally:
            self.cleanup.emit() # Always ensure cleanup is triggered


class TokenFetcher(QThread):
    """
    Worker thread for fetching/refreshing authentication tokens and checking peer online status
    without blocking the main GUI thread.
    """
    token_fetched = pyqtSignal(str, str) # Emits: peer_text, token (or None if failed)
    peer_status_updated = pyqtSignal(str, bool) # Emits: peer_text, is_online

    def __init__(self, peer_text: str, ip: str, port: int, parent=None):
        super().__init__(parent)
        self.peer_text = peer_text
        self.ip = ip
        self.port = port
        self.session = requests.Session()
        self.session.verify = False # Disable SSL verification for local network
        
        # Add retry strategy for all requests in this session
        retry_strategy = requests.adapters.Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

    def run(self):
        """Main execution method for the thread. Checks status and fetches token."""
        try:
            # First, check online status
            is_online = self._check_online()
            self.peer_status_updated.emit(self.peer_text, is_online)

            if is_online:
                # If online, try to fetch token
                token = self._fetch_token()
                self.token_fetched.emit(self.peer_text, token)
            else:
                self.token_fetched.emit(self.peer_text, None) # No token if offline
        except Exception as e:
            logger.error(f"Error in TokenFetcher for {self.peer_text}: {str(e)}", exc_info=True)
            self.peer_status_updated.emit(self.peer_text, False)
            self.token_fetched.emit(self.peer_text, None)
        finally:
            self.session.close() # Ensure session is closed

    def _check_online(self) -> bool:
        """Internal method to check if a peer's server is reachable and responsive."""
        try:
            r = self.session.get(f"https://{self.ip}:{self.port}/ping", timeout=(3, 5)) # Connect timeout, read timeout
            if r.ok:
                try:
                    data = r.json()
                    if data.get("status") == "online":
                        logger.debug(f"Peer {self.ip}:{self.port} is online.")
                        return True
                except json.JSONDecodeError:
                    logger.debug(f"Peer {self.ip}:{self.port} returned invalid JSON for ping.")
                    return False
                    
            logger.debug(f"Peer {self.ip}:{self.port} ping returned status {r.status_code}.")
            return False
            
        except requests.exceptions.SSLError:
            # If SSL handshake fails (e.g., self-signed cert), but connection made, assume online.
            logger.debug(f"SSL error pinging peer {self.ip}:{self.port}. Assuming online for self-signed certs.")
            return True
            
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logger.debug(f"Connection/Timeout error checking peer {self.ip}:{self.port}: {str(e)}")
            return False
            
        except Exception as e:
            logger.error(f"Unexpected error checking peer {self.ip}:{self.port}: {str(e)}", exc_info=True)
            return False
            

    def _fetch_token(self) -> str | None:
        """Internal method to request an authentication token from the peer."""
        try:
            r = self.session.post(
                f"https://{self.ip}:{self.port}/auth",
                json={"device_id": settings.device_id}, # Use current device's ID for authentication
                timeout=(3, 5)
            )
            r.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            token = r.json()["access_token"]  
            logger.debug(f"Successfully obtained token for {self.peer_text}.")
            return token
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching token from {self.peer_text}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in _fetch_token for {self.peer_text}: {str(e)}", exc_info=True)
            return None
