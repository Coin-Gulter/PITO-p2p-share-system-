import sys
import os
import json
import requests
import zipfile
import tempfile
import shutil
import time
import traceback
from pathlib import Path
import logging
from urllib3.exceptions import InsecureRequestWarning
import codecs
import argparse
import base64

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging to file with proper encoding
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'download.log')

# Configure logging with UTF-8 encoding
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

def safe_json_dumps(obj):
    """Safely convert object to JSON string with proper encoding"""
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception as e:
        logger.error(f"JSON encoding error: {str(e)}")
        return json.dumps(obj, ensure_ascii=True)

def print_json_message(message_type, value=None, message=None, error_details=None):
    """Print a JSON message to stdout with proper encoding"""
    try:
        data = {"type": message_type}
        if value is not None:
            data["progress"] = value
        if message is not None:
            data["status"] = message
        if error_details is not None:
            data["error_details"] = error_details
        print(json.dumps(data, ensure_ascii=False))
        sys.stdout.flush()
    except Exception as e:
        logger.error(f"Error printing JSON message: {str(e)}")
        print(json.dumps({
            "type": "error",
            "message": "Internal error occurred",
            "error_details": str(e)
        }, ensure_ascii=False))
        sys.stdout.flush()

def download_files(ip, port, token, items, download_dir):
    """Download individual files with improved error handling and performance"""
    total_items = len(items)
    chunk_size = 8192 * 4  # 32KB chunks
    last_progress_update = 0
    update_interval = 0.1  # Update progress every 100ms
    
    logger.info(f"Starting download of {total_items} files to {download_dir}")
    logger.debug(f"Download parameters: IP={ip}, Port={port}, Items={items}")
    
    # Create session for better connection handling
    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Bearer {token}"})
    
    try:
        for i, (path, name) in enumerate(items):
            try:
                # Sanitize filename
                safe_name = "".join(c for c in name if c.isalnum() or c in "._- ")
                if not safe_name:
                    safe_name = f"file_{i}"
                    
                logger.info(f"Downloading file {i+1}/{total_items}: {safe_name}")
                print_json_message("progress", value=int((i / total_items) * 100), 
                                 message=f"Downloading {safe_name}...")
                
                # Validate path
                if not path or not isinstance(path, str):
                    raise ValueError(f"Invalid path: {path}")
                    
                # Log request details
                url = f"https://{ip}:{port}/download"
                logger.debug(f"Making request to {url} for path: {path}")
                
                r = session.get(
                    url,
                    params={"path": path},
                    stream=True,
                    timeout=30
                )
                
                logger.debug(f"Response status: {r.status_code}")
                if r.text:
                    logger.debug(f"Response text: {r.text[:200]}...")  # Log first 200 chars
                
                if r.ok:
                    total_size = int(r.headers.get('content-length', 0))
                    logger.info(f"File size: {total_size} bytes")
                    downloaded = 0
                    dest_path = os.path.join(download_dir, safe_name)
                    
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    
                    with open(dest_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=chunk_size):
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                
                                # Throttle progress updates
                                current_time = time.time()
                                if current_time - last_progress_update >= update_interval:
                                    if total_size:
                                        progress = int((i + downloaded/total_size) / total_items * 100)
                                        print_json_message("progress", value=progress,
                                                         message=f"Downloading {safe_name}: {progress}%")
                                    last_progress_update = current_time
                    
                    logger.info(f"Successfully downloaded {safe_name}")
                    print_json_message("progress", value=int(((i + 1) / total_items) * 100),
                                     message=f"Downloaded {safe_name}")
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
                logger.error(f"Timeout downloading {name}")
                print_json_message("error", message=f"Timeout downloading {name}")
                sys.exit(1)
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error downloading {name}: {str(e)}")
                print_json_message("error", message=f"Connection error downloading {name}")
                sys.exit(1)
            except Exception as e:
                logger.error(f"Error downloading {name}: {str(e)}", exc_info=True)
                print_json_message("error", message=f"Error downloading {name}: {str(e)}")
                sys.exit(1)
    finally:
        session.close()

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
    
    try:
        for i, (path, name) in enumerate(items):
            try:
                # Sanitize folder name
                safe_name = "".join(c for c in name if c.isalnum() or c in "._- ")
                if not safe_name:
                    safe_name = f"folder_{i}"
                    
                logger.info(f"Downloading folder {i+1}/{total_items}: {safe_name}")
                print_json_message("progress", value=int((i / total_items) * 100),
                                 message=f"Downloading {safe_name}...")
                
                r = session.get(
                    f"https://{ip}:{port}/download-folder",
                    params={"path": path},
                    stream=True,
                    timeout=30
                )
                
                if r.ok:
                    total_size = int(r.headers.get('content-length', 0))
                    logger.info(f"Folder zip size: {total_size} bytes")
                    downloaded = 0
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        zip_path = os.path.join(temp_dir, f"{safe_name}.zip")
                        logger.debug(f"Creating temporary zip file at: {zip_path}")
                        
                        # Ensure parent directory exists
                        os.makedirs(os.path.dirname(zip_path), exist_ok=True)
                        
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
                                                             message=f"Downloading {safe_name}: {progress}%")
                                        last_progress_update = current_time
                        
                        print_json_message("progress", value=50,
                                         message=f"Extracting {safe_name}...")
                        extract_path = os.path.join(download_dir, safe_name)
                        os.makedirs(extract_path, exist_ok=True)
                        
                        with zipfile.ZipFile(zip_path, 'r') as zipf:
                            total_files = len(zipf.namelist())
                            for j, file in enumerate(zipf.namelist()):
                                # Throttle progress updates
                                current_time = time.time()
                                if current_time - last_progress_update >= update_interval:
                                    progress = 50 + int((j / total_files) * 50)
                                    print_json_message("progress", value=progress,
                                                     message=f"Extracting {safe_name}: {progress}%")
                                    last_progress_update = current_time
                                    
                                try:
                                    zipf.extract(file, extract_path)
                                except Exception as e:
                                    logger.error(f"Error extracting {file} from {safe_name}: {str(e)}")
                                    print_json_message("error", 
                                                     message=f"Error extracting {file} from {safe_name}: {str(e)}")
                                    sys.exit(1)
                        
                        print_json_message("progress", value=int(((i + 1) / total_items) * 100),
                                         message=f"Completed {safe_name}")
                else:
                    error_msg = f"Failed to download folder {safe_name}: {r.status_code}"
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
                logger.error(f"Timeout downloading folder {name}")
                print_json_message("error", message=f"Timeout downloading folder {name}")
                sys.exit(1)
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error downloading folder {name}: {str(e)}")
                print_json_message("error", message=f"Connection error downloading folder {name}")
                sys.exit(1)
            except Exception as e:
                logger.error(f"Error downloading folder {name}: {str(e)}", exc_info=True)
                print_json_message("error", message=f"Error downloading folder {name}: {str(e)}")
                sys.exit(1)
    finally:
        session.close()

def parse_arguments():
    """Parse command line arguments with improved error handling"""
    parser = argparse.ArgumentParser(description='Download files from peer')
    parser.add_argument('ip', help='Peer IP address')
    parser.add_argument('port', type=int, help='Peer port')
    parser.add_argument('token', help='Authentication token')
    parser.add_argument('items_json', help='Base64 encoded JSON string of items to download')
    parser.add_argument('download_dir', help='Directory to save downloaded files')
    parser.add_argument('is_folder', type=lambda x: x.lower() == 'true', help='Whether downloading folders')
    
    try:
        args = parser.parse_args()
        
        # Decode items JSON from base64
        try:
            items_json = base64.b64decode(args.items_json).decode('utf-8')
            args.items = json.loads(items_json)
        except Exception as e:
            logger.error(f"Failed to decode items JSON: {str(e)}")
            raise ValueError("Invalid items JSON format")
            
        return args
    except Exception as e:
        logger.error(f"Argument parsing error: {str(e)}")
        raise

def main():
    """Main function with improved argument handling and logging"""
    try:
        logger.info("Starting download script")
        
        # Parse command line arguments
        args = parse_arguments()
        
        # Validate arguments
        if not args.ip or not args.port or not args.token or not args.items or not args.download_dir:
            error_msg = "Invalid arguments"
            logger.error(f"{error_msg}: IP={args.ip}, Port={args.port}, "
                        f"Token length={len(args.token) if args.token else 0}, "
                        f"Items count={len(args.items) if args.items else 0}, "
                        f"Download dir={args.download_dir}")
            print_json_message("error", message=error_msg,
                             error_details="One or more required arguments are missing or invalid")
            sys.exit(1)
            
        # Ensure download directory exists
        try:
            os.makedirs(args.download_dir, exist_ok=True)
            logger.info(f"Ensured download directory exists: {args.download_dir}")
        except Exception as e:
            error_msg = f"Failed to create download directory: {str(e)}"
            logger.error(error_msg)
            print_json_message("error", message=error_msg,
                             error_details=traceback.format_exc())
            sys.exit(1)
        
        # Start download
        if args.is_folder:
            logger.info("Starting folder download")
            download_folder(args.ip, args.port, args.token, args.items, args.download_dir)
        else:
            logger.info("Starting file download")
            download_files(args.ip, args.port, args.token, args.items, args.download_dir)
            
        logger.info("Download completed successfully")
        print_json_message("progress", value=100, message="Download completed successfully")
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg, exc_info=True)
        print_json_message("error", message=error_msg,
                         error_details=traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 