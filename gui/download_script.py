# p2pshare/gui/download_script.py

import sys
import requests
import json
import os
import zipfile
import tempfile
import shutil
import time
import base64
import logging

# Configure basic logging for this script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_json_message(type, **kwargs):
    """Prints a JSON message to stdout for communication with the parent GUI process."""
    message_data = {"type": type, **kwargs}
    print(json.dumps(message_data, ensure_ascii=False), flush=True) # Ensure it's flushed immediately

def sanitize_path_component(name):
    """Sanitize path component to be safe for file system."""
    # Replace invalid characters with underscore
    invalid_chars = '<>:"|?*\\' # Added backslash for Windows paths
    for char in invalid_chars:
        name = name.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    name = name.strip('. ')
    
    # Ensure name is not empty after sanitization
    if not name:
        name = 'unnamed'
            
    return name

def download_file(ip, port, token, item, download_dir):
    """Downloads a single file."""
    path, name = item[0], item[1]
    safe_name = sanitize_path_component(name)
    
    logger.info(f"Downloading file: {safe_name}")
    print_json_message("progress", value=0, message=f"Downloading {safe_name}...")

    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Bearer {token}"})

    retry_strategy = requests.adapters.Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    try:
        r = session.get(
            f"https://{ip}:{port}/download/file/{path}",
            stream=True,
            timeout=36000 # 10 hours
        )
        
        if r.ok:
            total_size = int(r.headers.get('content-length', 0))
            downloaded = 0
            file_path = os.path.join(download_dir, safe_name)
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True) # Ensure target dir exists
            
            with open(file_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        current_time = time.time()
                        if current_time - download_file.last_progress_update >= download_file.update_interval:
                            if total_size:
                                progress = int((downloaded / total_size) * 100)
                                print_json_message("progress", value=progress,
                                                   message=f"Downloading {safe_name}: {progress}%")
                            download_file.last_progress_update = current_time
            print_json_message("progress", value=100, message=f"Downloaded {safe_name}")
        else:
            error_msg = f"Failed to download {safe_name}: {r.status_code}"
            if r.text:
                try:
                    error_detail = r.json().get("detail", r.text)
                    error_msg += f" - {error_detail}"
                except:
                    error_msg += f" - {r.text}"
            logger.error(error_msg)
            print_json_message("error", message=error_msg)
            sys.exit(1)
    except requests.exceptions.Timeout:
        logger.error(f"Timeout downloading file {safe_name}")
        print_json_message("error", message=f"Timeout downloading file {safe_name}")
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error downloading file {safe_name}: {str(e)}")
        print_json_message("error", message=f"Connection error downloading file {safe_name}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error downloading file {safe_name}: {str(e)}", exc_info=True)
        print_json_message("error", message=f"Error downloading file {safe_name}: {str(e)}")
        sys.exit(1)
    finally:
        session.close()

# Initialize static variables for progress tracking
download_file.last_progress_update = 0
download_file.update_interval = 0.1

def download_folder(ip, port, token, items, download_dir):
    """Download and extract folders with improved error handling and performance"""
    total_items = len(items)
    chunk_size = 8192 * 4  # 32KB chunks
    last_progress_update = 0
    update_interval = 0.1  # Update progress every 100ms
    
    # Create session for better connection handling
    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Bearer {token}"})
    
    # Add retry logic to the session
    retry_strategy = requests.adapters.Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    try:
        for i, (path, name) in enumerate(items):
            try:
                # Use the original 'name' as the intended top-level folder name for the user
                original_folder_name = name
                # Sanitize the folder name for file system usage
                safe_name = sanitize_path_component(original_folder_name)
                
                logger.info(f"Downloading folder {i+1}/{total_items}: {original_folder_name}")
                print_json_message("progress", value=int((i / total_items) * 100),
                                   message=f"Downloading {original_folder_name}...")
                
                r = session.get(
                    f"https://{ip}:{port}/download-folder",
                    params={"path": path},
                    stream=True,
                    timeout=36000  # Increased to 10 hours
                )
                
                if r.ok:
                    total_size = int(r.headers.get('content-length', 0))
                    logger.info(f"Folder zip size: {total_size} bytes")
                    downloaded = 0
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        zip_path = os.path.join(temp_dir, f"{safe_name}.zip")
                        logger.debug(f"Creating temporary zip file at: {zip_path}")
                        
                        os.makedirs(os.path.dirname(zip_path), exist_ok=True) # Ensure target dir exists
                        
                        with open(zip_path, "wb") as f:
                            for chunk in r.iter_content(chunk_size=chunk_size):
                                if chunk:
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    
                                    # Throttle progress updates
                                    current_time = time.time()
                                    if current_time - last_progress_update >= update_interval:
                                        if total_size:
                                            progress = int((downloaded / total_size) * 50)
                                            print_json_message("progress", value=progress,
                                                               message=f"Downloading {original_folder_name}: {progress}%")
                                        last_progress_update = current_time
                        
                        print_json_message("progress", value=50,
                                           message=f"Extracting {original_folder_name}...")
                        
                        # Define the final target directory for the extracted contents
                        # This is where the contents should actually end up, without duplication
                        final_extract_root = os.path.join(download_dir, original_folder_name)
                        os.makedirs(final_extract_root, exist_ok=True)
                        logger.debug(f"Final extraction root: {final_extract_root}")

                        with zipfile.ZipFile(zip_path, 'r') as zipf:
                            namelist = zipf.namelist()
                            if not namelist:
                                logger.warning(f"Downloaded zip file for {original_folder_name} is empty.")
                                continue

                            # REVISED LOGIC FOR STRIPPING TOP-LEVEL DIRECTORY
                            strip_prefix = ""
                            if namelist[0].endswith('/') and len(namelist[0].split('/')) == 2: # Check if first entry is a single root folder itself (e.g. "book/")
                                # Also check if all other entries consistently start with this prefix
                                if all(entry.startswith(namelist[0]) for entry in namelist):
                                    strip_prefix = namelist[0]
                                    logger.debug(f"Identified simple top-level directory to strip: '{strip_prefix}'")
                            elif os.path.commonprefix(namelist) and os.path.commonprefix(namelist).endswith('/'):
                                # Use commonprefix if it forms a full directory name
                                detected_prefix = os.path.commonprefix(namelist)
                                if all(name.startswith(detected_prefix) for name in namelist) and len(namelist) > 1:
                                    strip_prefix = detected_prefix
                                    logger.debug(f"Identified common prefix to strip: '{strip_prefix}'")
                            
                            logger.debug(f"Determined strip_prefix: '{strip_prefix}' for zip with entries: {namelist[:5]}...")


                            total_files = len(namelist)
                            for j, file_in_zip in enumerate(namelist):
                                current_time = time.time()
                                if current_time - last_progress_update >= update_interval:
                                    progress = 50 + int((j / total_files) * 50)
                                    print_json_message("progress", value=progress,
                                                       message=f"Extracting {original_folder_name}: {progress}%")
                                    last_progress_update = current_time
                                    
                                try:
                                    # Calculate the path relative to the strip_prefix
                                    extracted_sub_path = file_in_zip[len(strip_prefix):]

                                    if not extracted_sub_path: # Skip if it's just the stripped root dir itself
                                        continue

                                    dest_path = os.path.join(final_extract_root, extracted_sub_path)
                                    
                                    # Critical security check: prevent path traversal
                                    abs_dest_path = os.path.abspath(dest_path)
                                    abs_root_path = os.path.abspath(final_extract_root)
                                    
                                    # Ensure the destination path is within the intended final_extract_root
                                    # and does not traverse upwards (e.g., ../)
                                    if not abs_dest_path.startswith(abs_root_path + os.sep) and abs_dest_path != abs_root_path:
                                        logger.warning(f"Path traversal attempt detected: {file_in_zip} would extract to {abs_dest_path}. Skipping.")
                                        continue

                                    # Create parent directories for the current file/folder
                                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

                                    # Extract file content
                                    info = zipf.getinfo(file_in_zip)
                                    if info.is_dir():
                                        os.makedirs(dest_path, exist_ok=True)
                                    else:
                                        with zipf.open(file_in_zip) as source, open(dest_path, 'wb') as dest:
                                            shutil.copyfileobj(source, dest)

                                except Exception as e:
                                    logger.error(f"Error extracting {file_in_zip} from {original_folder_name}: {str(e)}", exc_info=True)
                                    print_json_message("error", 
                                                        message=f"Error extracting {file_in_zip} from {original_folder_name}: {str(e)}")
                                    sys.exit(1)
                            
                        print_json_message("progress", value=int(((i + 1) / total_items) * 100),
                                           message=f"Completed {original_folder_name}")
                else:
                    error_msg = f"Failed to download folder {original_folder_name}: {r.status_code}"
                    if r.text:
                        try:
                            error_detail = r.json().get("detail", r.text)
                            error_msg += f" - {error_detail}"
                        except:
                            error_msg += f" - {r.text}"
                    logger.error(error_msg)
                    print_json_message("error", message=error_msg)
                    sys.exit(1)
            except requests.exceptions.Timeout:
                logger.error(f"Timeout downloading folder {original_folder_name}")
                print_json_message("error", message=f"Timeout downloading folder {original_folder_name}")
                sys.exit(1)
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error downloading folder {original_folder_name}: {str(e)}")
                print_json_message("error", message=f"Connection error downloading folder {original_folder_name}")
                sys.exit(1)
            except Exception as e:
                logger.error(f"Error downloading folder {original_folder_name}: {str(e)}", exc_info=True)
                print_json_message("error", message=f"Error downloading folder {original_folder_name}: {str(e)}")
                sys.exit(1)
    finally:
        session.close()

if __name__ == "__main__":
    if len(sys.argv) < 7:
        print_json_message("error", message="Usage: download_script.py <ip> <port> <token> <items_b64> <download_dir> <is_folder>")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    token = sys.argv[3]
    items_b64 = sys.argv[4]
    download_dir = sys.argv[5]
    is_folder_str = sys.argv[6] == 'true'

    try:
        items = json.loads(base64.b64decode(items_b64).decode('utf-8'))
        if is_folder_str:
            download_folder(ip, port, token, items, download_dir)
        else:
            # For single file download, items will contain only one item
            # Example: [["/path/to/file.txt", "file.txt"]]
            for item in items: # Iterate though items, even if it's just one file
                download_file(ip, port, token, item, download_dir)
        print_json_message("finished", success=True, message="Download(s) completed.")
    except Exception as e:
        logger.critical(f"Critical error in download_script: {str(e)}", exc_info=True)
        print_json_message("error", message=f"Critical error: {str(e)}")
        sys.exit(1)

