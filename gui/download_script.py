import sys
import requests
import json
import os
import tempfile
from pathlib import Path
import base64
import zipfile
import shutil
import time

# Import shared modules
from shared.security_manager import SecurityManager
from shared.config import CONFIG_DIR # Needed for SecurityManager
from shared.logging_config import setup_logger

logger = setup_logger(__name__)

# Re-initialize security_manager in this subprocess
# It will load the key passed via command line.
security_manager = SecurityManager(CONFIG_DIR)

class DecryptionError(Exception):
    """Custom exception for decryption failures."""
    pass

def print_json_message(progress=None, status=None, error=None, message=None):
    """Prints a JSON message to stdout for the parent process to read."""
    output = {}
    if progress is not None:
        output['progress'] = progress
    if status is not None:
        output['status'] = status
    if error is not None:
        output['error'] = error
    if message is not None:
        output['message'] = message
    print(json.dumps(output), flush=True) # Ensure output is flushed immediately

def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypts data using the loaded encryption key."""
    try:
        decrypted_data = security_manager.decrypt_data(encrypted_data)
        if decrypted_data is None:
            raise DecryptionError("Decryption returned None, likely incorrect key or corrupted data.")
        return decrypted_data
    except Exception as e:
        logger.error(f"Failed to decrypt data: {e}", exc_info=True)
        raise DecryptionError(f"Decryption failed: {e}")

def download_file_from_peer(ip, port, token, remote_path, local_filename, download_dir):
    """Downloads and decrypts a single file from the peer."""
    temp_encrypted_path = None
    try:
        url = f"https://{ip}:{port}/download"
        headers = {"Authorization": f"Bearer {token}"}
        params = {"path": remote_path} # remote_path is now the absolute path on the peer
        
        logger.info(f"Downloading file from {ip}:{port}{remote_path} to {download_dir}/{local_filename}")
        
        # Stream the download to a temporary encrypted file
        with tempfile.NamedTemporaryFile(delete=False, dir=CONFIG_DIR) as temp_file:
            temp_encrypted_path = Path(temp_file.name)
            logger.debug(f"Saving encrypted stream to temporary file: {temp_encrypted_path}")
            
            with requests.get(url, headers=headers, params=params, stream=True, verify=False, timeout=(30, 300)) as r:
                r.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                
                total_size = int(r.headers.get('content-length', 0))
                bytes_downloaded = 0
                last_progress = -1
                
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        temp_file.write(chunk)
                        bytes_downloaded += len(chunk)
                        
                        # Update progress
                        if total_size > 0:
                            progress = int((bytes_downloaded / total_size) * 100)
                            if progress != last_progress:
                                print_json_message(progress=progress, status=f"Downloading: {local_filename} ({progress}%)")
                                last_progress = progress
                print_json_message(progress=100, status=f"Downloaded encrypted: {local_filename}")
                logger.info(f"Finished downloading encrypted file to {temp_encrypted_path}. Total: {bytes_downloaded} bytes.")

        # Decrypt the temporary file
        logger.info(f"Decrypting {local_filename}...")
        print_json_message(progress=0, status=f"Decrypting: {local_filename} (0%)") # Reset progress for decryption phase
        
        with open(temp_encrypted_path, 'rb') as f_encrypted:
            encrypted_data = f_encrypted.read()
        
        decrypted_data = decrypt_data(encrypted_data) # Use the subprocess's security_manager
        
        output_path = Path(download_dir) / local_filename
        output_path.parent.mkdir(parents=True, exist_ok=True) # Ensure destination directory exists
        
        with open(output_path, 'wb') as f_out:
            f_out.write(decrypted_data)
        
        print_json_message(progress=100, status=f"Decrypted: {local_filename}")
        logger.info(f"File {local_filename} downloaded and decrypted successfully to {output_path}")
        return True

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error downloading {local_filename}: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    except DecryptionError as e:
        error_msg = f"Decryption error for {local_filename}: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    except Exception as e:
        error_msg = f"Unexpected error downloading {local_filename}: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    finally:
        if temp_encrypted_path and temp_encrypted_path.exists():
            os.unlink(temp_encrypted_path)
            logger.debug(f"Cleaned up temporary encrypted file: {temp_encrypted_path}")
    return False

def download_folder_from_peer(ip, port, token, remote_path, download_dir):
    """Downloads, decrypts, and extracts a zipped folder from the peer."""
    temp_zip_path = None
    try:
        url = f"https://{ip}:{port}/download-folder"
        headers = {"Authorization": f"Bearer {token}"}
        params = {"path": remote_path} # remote_path is now the absolute path on the peer
        
        logger.info(f"Downloading folder from {ip}:{port}{remote_path} to {download_dir}")
        
        # Stream the download to a temporary encrypted zip file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", dir=CONFIG_DIR) as temp_file:
            temp_zip_path = Path(temp_file.name)
            logger.debug(f"Saving encrypted zip stream to temporary file: {temp_zip_path}")

            with requests.get(url, headers=headers, params=params, stream=True, verify=False, timeout=(30, 600)) as r:
                r.raise_for_status()
                
                total_size = int(r.headers.get('content-length', 0))
                bytes_downloaded = 0
                last_progress = -1
                
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        temp_file.write(chunk)
                        bytes_downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = int((bytes_downloaded / total_size) * 50) # First 50% for download
                            if progress != last_progress:
                                print_json_message(progress=progress, status=f"Downloading folder: ({progress}%)")
                                last_progress = progress
                print_json_message(progress=50, status=f"Downloaded encrypted folder.")
                logger.info(f"Finished downloading encrypted zip to {temp_zip_path}. Total: {bytes_downloaded} bytes.")

        # Decrypt and extract the zip file
        logger.info(f"Decrypting and extracting folder from {temp_zip_path}...")
        print_json_message(progress=50, status="Decrypting folder...")
        
        decrypted_zip_data = None
        with open(temp_zip_path, 'rb') as f_encrypted:
            encrypted_data = f_encrypted.read()
        
        decrypted_zip_data = decrypt_data(encrypted_data) # Decrypt the entire zip data
        
        # Write decrypted data to a new temporary zip file for extraction
        temp_decrypted_zip_path = temp_zip_path.with_name(f"decrypted_{temp_zip_path.name}")
        with open(temp_decrypted_zip_path, 'wb') as f_decrypted:
            f_decrypted.write(decrypted_zip_data)
        
        logger.info(f"Decrypted zip saved to {temp_decrypted_zip_path}.")
        
        # Extract contents
        with zipfile.ZipFile(temp_decrypted_zip_path, 'r') as zip_ref:
            # Validate zip contents before extraction
            if zip_ref.testzip() is not None:
                raise ValueError("Decrypted zip file is corrupted.")
            
            # Determine the target directory for extraction
            # If original remote_path was '/', then output to download_dir / P2PShare_root_name
            # If original remote_path was '/my_folder', output to download_dir / my_folder
            
            # The zip file *should* contain contents under a single top-level directory
            # matching the original folder name or a placeholder for root.
            # Let's extract to download_dir, and the zip's internal structure will create subfolders.

            # Find the common base dir or folder name in the zip
            zip_contents_root = None
            if zip_ref.namelist():
                # Get the first part of the first name in the zip
                first_entry_parts = Path(zip_ref.namelist()[0]).parts
                if first_entry_parts:
                    zip_contents_root = first_entry_parts[0]
            
            if zip_contents_root:
                extract_path = Path(download_dir)
            else:
                extract_path = Path(download_dir) # Extract directly if no common root in zip

            # Extract with progress
            total_files_in_zip = len(zip_ref.namelist())
            for i, member in enumerate(zip_ref.infolist()):
                if member.is_dir():
                    continue # Skip directories, they are created by files
                
                extracted_size = member.file_size
                
                # Check for absolute paths or path traversal in zip names
                if Path(member.filename).is_absolute() or '..' in Path(member.filename).parts:
                    raise ValueError(f"Zip contains unsafe path: {member.filename}")

                # Ensure target path for extraction is within the designated download directory
                target_member_path = extract_path / member.filename
                if not target_member_path.is_relative_to(extract_path):
                     raise ValueError(f"Attempted path traversal during extraction: {member.filename}")

                print_json_message(progress=50 + int((i / total_files_in_zip) * 50),
                                   status=f"Extracting: {member.filename}")
                
                # Extract members
                try:
                    zip_ref.extract(member, path=extract_path)
                except Exception as e:
                    logger.error(f"Error extracting {member.filename}: {e}")
                    raise # Re-raise to trigger error handling
            
            print_json_message(progress=100, status="Extraction complete.")
            logger.info(f"Folder from {remote_path} downloaded, decrypted and extracted successfully to {extract_path}")
            return True

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error downloading folder: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    except DecryptionError as e:
        error_msg = f"Decryption error for folder: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    except zipfile.BadZipFile as e:
        error_msg = f"Corrupted zip file: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    except ValueError as e:
        error_msg = f"Zip validation error: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    except Exception as e:
        error_msg = f"Unexpected error downloading folder: {e}"
        logger.error(error_msg, exc_info=True)
        print_json_message(error=error_msg)
    finally:
        if temp_zip_path and temp_zip_path.exists():
            os.unlink(temp_zip_path)
            logger.debug(f"Cleaned up temporary encrypted zip: {temp_zip_path}")
        if 'temp_decrypted_zip_path' in locals() and temp_decrypted_zip_path.exists():
            os.unlink(temp_decrypted_zip_path)
            logger.debug(f"Cleaned up temporary decrypted zip: {temp_decrypted_zip_path}")
    return False


if __name__ == "__main__":
    # Command line arguments: ip, port, token, items_b64, download_dir, is_folder_str, encryption_key_b64
    if len(sys.argv) < 8:
        print_json_message(error="Missing arguments for download script.")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    token = sys.argv[3]
    items_b64 = sys.argv[4]
    download_dir = sys.argv[5]
    is_folder_str = sys.argv[6]
    encryption_key_b64 = sys.argv[7] # Retrieve the base64 encoded encryption key

    is_folder = is_folder_str.lower() == 'true'

    # Decode items JSON
    try:
        items_json = base64.b64decode(items_b64).decode('utf-8')
        items = json.loads(items_json)
    except Exception as e:
        print_json_message(error=f"Failed to decode items data: {e}")
        sys.exit(1)

    # Initialize SecurityManager with the passed encryption key
    try:
        encryption_key_bytes = base64.b64decode(encryption_key_b64)
        security_manager.set_encryption_key(encryption_key_bytes)
        logger.info("Encryption key successfully loaded in download_script.py subprocess.")
    except Exception as e:
        print_json_message(error=f"Failed to load encryption key in subprocess: {e}")
        sys.exit(1)

    # Assume only one item is passed for simplicity of current download logic
    # The client side sends a list of [path_on_peer, original_name]
    if not items:
        print_json_message(error="No items provided for download.")
        sys.exit(1)

    # Loop through items if multiple are supported, but for now take the first.
    # The current DownloadProcess logic seems to send all selected items in one go,
    # but the download functions themselves (download_file_from_peer/download_folder_from_peer)
    # only handle a single target. This needs alignment or a loop.
    # For now, let's process the first item.
    
    # Check if this is a single file or a folder download based on is_folder flag
    # The main_window sends `is_any_folder_selected`. If it's true, we need to treat
    # the entire `items` list as *one* logical folder/zip download, with `items[0][0]`
    # being the remote path of the folder to download.
    
    # If is_folder is True, we assume items contains a single entry [remote_folder_path, folder_name]
    # If is_folder is False, items can contain multiple files, each [remote_file_path, file_name]
    # For now, let's treat it as a single primary operation per subprocess for simplicity.
    
    success = False
    if is_folder:
        remote_path = items[0][0] # The remote path of the folder
        success = download_folder_from_peer(ip, port, token, remote_path, download_dir)
    else:
        # Loop through individual files if not a folder download
        for remote_path, local_filename in items:
            success = download_file_from_peer(ip, port, token, remote_path, local_filename, download_dir)
            if not success: # Stop if any single file download fails
                break

    if success:
        sys.exit(0)
    else:
        sys.exit(1)

