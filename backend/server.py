# p2pshare/backend/server.py

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Body, Query, Form, Request, Header
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPBearer
import os, shutil, uuid
from pathlib import Path
import jwt
from shared.config import settings, CONFIG_DIR
from shared.logging_config import setup_logger
from pydantic import BaseModel
from typing import List, Optional
import stat
import tempfile
import zipfile
import time
from starlette.background import BackgroundTask
import base64
import platform # To detect OS for drive listing
from shared.security_manager import SecurityManager
import json

# Set up logger
logger = setup_logger(__name__)

# --- Security: Initialize SecurityManager for the server ---
# The encryption key is passed from main.py via an environment variable.
security_manager = None
try:
    encryption_key_b64 = os.environ.get('P2PSHARE_ENCRYPTION_KEY_B64')
    if encryption_key_b64:
        encryption_key_bytes = base64.b64decode(encryption_key_b64)
        # We don't need a password, just the raw key for the existing instance.
        # The config_dir is needed for potential temp file operations inside manager.
        security_manager = SecurityManager(config_dir=CONFIG_DIR, encryption_key=encryption_key_bytes)
        logger.info("Server-side SecurityManager initialized successfully with encryption key.")
    else:
        logger.error("P2PSHARE_ENCRYPTION_KEY_B64 environment variable not set. File encryption/decryption will fail.")
except Exception as e:
    logger.critical(f"Failed to initialize server-side SecurityManager: {e}", exc_info=True)
    # This is a critical failure, as the server cannot perform its core security functions.
    security_manager = None # Ensure it's None on failure

# Auth request model
class AuthRequest(BaseModel):
    device_id: str

class FileInfo(BaseModel):
    name: str
    path: str # This path will now be absolute (or drive-relative) from the client's perspective
    is_dir: bool
    size: Optional[int] = None
    modified: Optional[float] = None

class UploadResponse(BaseModel):
    status: str
    path: str
    message: Optional[str] = None

SECRET_KEY = settings.device_id + settings.device_id[::-1]
ALGORITHM = "HS256"
app = FastAPI()
# SHARE_DIR will no longer be a strict root, but kept for legacy or other uses if needed.
# For full filesystem sharing, the effective root for browsing becomes the OS root or drive list.
app.state.SHARE_DIR = Path.home() / ".p2pshare" # Still create a default P2PShare dir, but it's not the only browsable root.
security = HTTPBearer()

# --- Security: Blacklisted paths (crucial for full filesystem sharing) ---
# These are paths that should NEVER be exposed, even to authorized users.
# Add more as needed based on your OS and security requirements.
BLACKLISTED_PATHS = [
    Path('/etc').resolve(), # Linux/macOS system configuration
    Path('/bin').resolve(), # Linux/macOS binaries
    Path('/sbin').resolve(), # Linux/macOS system binaries
    Path('/dev').resolve(), # Linux/macOS device files
    Path('/proc').resolve(), # Linux virtual filesystem
    Path('/sys').resolve(), # Linux system information
    Path('/boot').resolve(), # Linux boot files
    Path('/root').resolve(), # Linux root user's home directory
    Path('/usr').resolve(),  # Linux user programs

    Path('C:/Windows').resolve(), # Windows system directory
    Path('C:/Program Files').resolve(), # Program installation directory
    Path('C:/Program Files (x86)').resolve(), # Program installation directory
    Path('C:/PerfLogs').resolve(), # Performance logs
    Path('C:/System Volume Information').resolve(), # System recovery information
    Path('C:/$Recycle.Bin').resolve(), # Recycle bin
    Path('C:/Users/Default').resolve(), # Default user profile
    Path('C:/Users/Public').resolve(), # Public user files
    # Add more specific sensitive user data paths if known, e.g., browser profiles, crypto wallets etc.
    # For user specific sensitive data it's harder to blacklist without knowing all user profiles
    # so relying on authentication and user trust becomes paramount.
]

# Ensure blacklisted paths are resolved once on startup for accurate comparison
BLACKLISTED_PATHS = [p.resolve() for p in BLACKLISTED_PATHS if p.exists()]
logger.info(f"Initialized blacklisted paths for full filesystem sharing: {BLACKLISTED_PATHS}")

def is_path_blacklisted(p: Path) -> bool:
    """Checks if a given path is blacklisted or within a blacklisted directory."""
    resolved_p = p.resolve()
    for blacklisted in BLACKLISTED_PATHS:
        if resolved_p == blacklisted or resolved_p.is_relative_to(blacklisted):
            logger.warning(f"Access to blacklisted path detected: {p} (resolved: {resolved_p}) is in {blacklisted}")
            return True
    return False

# Create share directory if not exists (still useful for default uploads if not specifying elsewhere)
os.makedirs(app.state.SHARE_DIR, exist_ok=True)
logger.info(f"Default P2PShare directory initialized at {app.state.SHARE_DIR}")

# --- Auth helpers ---
def create_jwt(device_id):
    payload = {"device_id": device_id}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Created JWT token for device {device_id}")
    return token

def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.debug(f"Successfully verified JWT token for device {payload['device_id']}")
        return payload["device_id"]
    except jwt.PyJWTError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        raise HTTPException(status_code=403, detail="Invalid token")

def require_auth(token=Depends(security)):
    return verify_jwt(token.credentials)

@app.get("/ping")
async def ping():
    """Simple endpoint to check if the server is online"""
    logger.debug("Received ping request")
    return {"status": "online", "device_id": settings.device_id}

# # The /files endpoint is still specific to the original SHARE_DIR
# @app.get("/files", dependencies=[Depends(require_auth)])
# def list_files():
#     """List visible files in the original P2PShare directory only (legacy)."""
#     try:
#         files = []
#         for f in get_share_dir().iterdir():
#             if (f.is_file() and 
#                 not f.name.startswith('.') and 
#                 not f.name.startswith('~') and
#                 f.parent == get_share_dir()):
#                 try:
#                     if os.access(f, os.R_OK):
#                         files.append(f.name)
#                 except Exception as e:
#                     logger.warning(f"Error accessing file {f}: {str(e)}")
#                     continue
#         logger.info(f"Listed {len(files)} files in legacy share directory")
#         return JSONResponse(files)
#     except Exception as e:
#         logger.error(f"Error listing files: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=500, detail=str(e))

# # The /files/{filename} endpoint is still specific to the original SHARE_DIR
# @app.get("/files/{filename}", dependencies=[Depends(require_auth)])
# def download_file_legacy(filename: str):
#     file_path = get_share_dir() / filename
#     if file_path.exists():
#         logger.info(f"Legacy file download requested: {filename}")
#         return FileResponse(file_path)
#     logger.warning(f"Legacy file not found: {filename}")
#     raise HTTPException(status_code=404, detail="File not found")

@app.post("/auth")
def auth(request: AuthRequest):
    logger.info(f"Authentication request from device: {request.device_id}")
    token = create_jwt(request.device_id)
    # Encrypt and base64-encode the token before returning
    if not security_manager or not security_manager.get_encryption_key():
        logger.critical("Auth endpoint called but security manager is not initialized with key. Cannot proceed.")
        raise HTTPException(status_code=500, detail="Server encryption is not configured.")
    encrypted_token = security_manager.encrypt_data(token.encode('utf-8'))
    encoded_token = base64.b64encode(encrypted_token).decode('utf-8')
    return {"access_token": encoded_token}

def get_file_info_for_client(full_item_path: Path) -> FileInfo:
    """
    Get information about a file or directory for client display.
    The 'path' in FileInfo will be the full absolute path with forward slashes.
    """
    try:
        stat_info = full_item_path.stat()
        
        # Ensure path is always presented with forward slashes for cross-platform consistency
        client_display_path = full_item_path.as_posix()
        
        # On Windows, for drive roots, Path('/').as_posix() returns '/'.
        # For 'C:/', Path('C:/').as_posix() returns 'C:/'.
        # For consistency, when browsing root, we want to see 'C:/', 'D:/' etc.
        # So we can keep it as is.
        if platform.system() == "Windows" and full_item_path.drive and not full_item_path.root:
            # This is a drive root like C: or D:. Path().as_posix() handles this as 'C:/'.
            pass
        elif platform.system() == "Windows" and not full_item_path.is_absolute():
            # This case ideally should not happen with resolved paths
            pass

        return FileInfo(
            name=full_item_path.name if full_item_path.name else str(full_item_path).replace(':', ''), # Name for drive root e.g. C or D
            path=client_display_path, # Full absolute path
            is_dir=full_item_path.is_dir(),
            size=stat_info.st_size if full_item_path.is_file() else None,
            modified=stat_info.st_mtime
        )
    except Exception as e:
        logger.error(f"Error getting file info for {full_item_path}: {str(e)}", exc_info=True)
        # Instead of raising HTTPException here, let list_directory handle skipping.
        raise

@app.get("/browse", dependencies=[Depends(require_auth)])
def list_directory(path: str = Query("/", description="Directory path to list")):
    """
    List contents of a directory.
    When path is "/", lists available drives on Windows or root directory contents on Unix-like systems.
    Otherwise, lists contents of the specified absolute path.
    The response is an encrypted blob of the JSON-encoded file list.
    """
    # Security: Ensure security manager is loaded, otherwise cannot encrypt response.
    if not security_manager or not security_manager.get_encryption_key():
        logger.critical("Browse endpoint called but security manager is not initialized with key. Cannot proceed.")
        raise HTTPException(status_code=500, detail="Server encryption is not configured.")
    try:
        target_path: Path
        items = []
        if path == "/":
            if platform.system() == "Windows":
                drive_letters = []
                for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    drive_path = Path(f"{drive}:/")
                    if drive_path.exists() and drive_path.is_dir():
                        drive_letters.append(drive_path)
                for drive_p in drive_letters:
                    if is_path_blacklisted(drive_p):
                        logger.warning(f"Skipping blacklisted drive: {drive_p}")
                        continue
                    try:
                        items.append(get_file_info_for_client(drive_p).model_dump())
                    except Exception as e:
                        logger.warning(f"Error getting info for drive {drive_p}: {e}")
                        continue
                logger.info(f"Listed available drives: {len(items)} items")
            else:
                target_path = Path('/')
                if is_path_blacklisted(target_path):
                    raise HTTPException(status_code=403, detail="Access to this path is forbidden.")
                for item_path in target_path.iterdir():
                    if is_path_blacklisted(item_path):
                        continue
                    try:
                        items.append(get_file_info_for_client(item_path).model_dump())
                    except Exception as e:
                        logger.warning(f"Could not stat {item_path}, skipping: {e}")
                        continue
                logger.info(f"Listed contents of root directory: {len(items)} items")
        else:
            target_path = Path(path).resolve()
            if not target_path.exists() or not target_path.is_dir():
                raise HTTPException(status_code=404, detail="Directory not found")
            if is_path_blacklisted(target_path):
                raise HTTPException(status_code=403, detail="Access to this path is forbidden.")
            for item_path in target_path.iterdir():
                if is_path_blacklisted(item_path):
                    continue
                try:
                    items.append(get_file_info_for_client(item_path).model_dump())
                except Exception as e:
                    logger.warning(f"Could not stat {item_path}, skipping: {e}")
                    continue
            logger.info(f"Listed contents of {path}: {len(items)} items")
        items_json = json.dumps(items)
        encrypted_data = security_manager.encrypt_data(items_json.encode('utf-8'))
        # Return as base64-encoded string in a JSON object (to match client expectation)
        return {"data": base64.b64encode(encrypted_data).decode("utf-8")}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing directory '{path}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to list directory: {e}")

@app.get("/file-info", dependencies=[Depends(require_auth)])
def get_file_info_endpoint(path: str = Query(..., description="Path to get info for")):
    """Get information about a specific file or directory (full absolute path)"""
    try:
        effective_path = Path(path).resolve()

        if not effective_path.exists():
            raise HTTPException(status_code=404, detail="File or directory not found")
        
        if is_path_blacklisted(effective_path):
            raise HTTPException(status_code=403, detail="Access to this path is restricted.")

        return get_file_info_for_client(effective_path)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting file info for {path}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error getting file info: {str(e)}")

@app.get("/download", dependencies=[Depends(require_auth)])
def download_file(path: str = Query(..., description="Path of file to download")):
    """
    Encrypts and downloads a file from any absolute location.
    The file is read, encrypted in memory, and then sent.
    """
    if not security_manager:
        raise HTTPException(status_code=500, detail="Server encryption is not configured. Cannot download file.")

    try:
        effective_path = Path(path).resolve()

        if not effective_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        if not effective_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        if is_path_blacklisted(effective_path):
            raise HTTPException(status_code=403, detail="Access to this path is restricted.")
            
        # Check read permissions
        if not os.access(effective_path, os.R_OK):
            raise HTTPException(status_code=403, detail="Permission denied to read file.")

        logger.info(f"File download requested: {path}. Reading and encrypting...")
        
        # Read file content
        with open(effective_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt the file data
        encrypted_data = security_manager.encrypt_data(file_data)
        
        logger.info(f"Sending encrypted file: {effective_path.name}, size: {len(encrypted_data)} bytes")

        # Return the encrypted data as a response
        return Response(
            content=encrypted_data,
            media_type='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{effective_path.name}"'}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error encrypting or sending file {path}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing file for download: {str(e)}")

@app.get("/download-folder", dependencies=[Depends(require_auth)])
def download_folder(path: str = Query(..., description="Path of folder to download")):
    """
    Zips a folder, encrypts the zip, and downloads it.
    The folder is zipped in a temporary location, then the zip file is
    encrypted in memory and sent as a response.
    """
    if not security_manager:
        raise HTTPException(status_code=500, detail="Server encryption is not configured. Cannot download folder.")

    temp_dir = None
    zip_path = None
    try:
        logger.info(f"Folder download requested for path: {path}")
        
        effective_path = Path(path).resolve()

        if not effective_path.exists():
            logger.warning(f"Folder not found: {effective_path}")
            raise HTTPException(status_code=404, detail="Folder not found")
        if not effective_path.is_dir():
            logger.warning(f"Path is not a folder: {effective_path}")
            raise HTTPException(status_code=400, detail="Path is not a folder")
            
        if is_path_blacklisted(effective_path):
            raise HTTPException(status_code=403, detail="Access to this path is restricted.")
            
        if not os.access(effective_path, os.R_OK):
            raise HTTPException(status_code=403, detail="Permission denied to read folder.")
            
        temp_dir = tempfile.mkdtemp()
        logger.debug(f"Created temporary directory: {temp_dir}")
            
        # If zipping a drive root (e.g., C:/), its name is empty. Use drive letter.
        # Otherwise, use the folder's name.
        folder_name_for_zip = effective_path.name if effective_path.name else effective_path.drive.replace(':', '')
        zip_filename = f"{folder_name_for_zip}_{int(time.time())}.zip"
        zip_path = Path(temp_dir) / zip_filename
        logger.info(f"Creating zip file: {zip_path}")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the directory
            for root, dirs, files in os.walk(effective_path):
                # Calculate path relative to the effective_path being zipped
                # Example: effective_path = C:/my_folder, root = C:/my_folder/sub
                # relative_to_zip_base = sub
                # If effective_path is C:/, root is C:/Program Files, relative_to_zip_base = Program Files
                current_item_path = Path(root)
                
                # Security: Check if current item path in walk is blacklisted
                if is_path_blacklisted(current_item_path):
                    logger.warning(f"Skipping blacklisted directory during zip: {current_item_path}")
                    # Remove blacklisted dirs from 'dirs' list to prevent os.walk from entering them
                    dirs[:] = [] 
                    continue

                try:
                    # Calculate relative path from the original folder being zipped to include in zip archive.
                    # On Windows, if zipping a drive root (e.g. C:/), relative_to('') would fail.
                    # We need to explicitly handle the archive name.
                    if effective_path.is_absolute() and not effective_path.name: # It's a drive root like C:/
                        # The base inside the zip will be the drive letter (e.g., C)
                        relative_to_zip_base = Path(effective_path.drive.replace(':', '')) / Path(root).relative_to(effective_path)
                    else:
                        relative_to_zip_base = Path(root).relative_to(effective_path)
                    
                    logger.debug(f"Processing directory for zip: {root} -> Archive path: {relative_to_zip_base}")
                    
                    for file in files:
                        file_path = Path(root) / file
                        if is_path_blacklisted(file_path):
                            logger.warning(f"Skipping blacklisted file during zip: {file_path}")
                            continue
                            
                        if not os.access(file_path, os.R_OK):
                            logger.warning(f"No read permission for file: {file_path}. Skipping.")
                            continue
                            
                        # The name in the archive should be the base archive path + relative filename
                        arcname = relative_to_zip_base / file_path.name
                        zipf.write(file_path, arcname.as_posix()) # Use as_posix() for zip compatibility
                        logger.debug(f"Added to zip: {file_path} as {arcname}")
                except PermissionError:
                    logger.warning(f"Permission denied to access {root}. Skipping contents.")
                    dirs[:] = [] # Skip further traversal into this directory
                    continue
                except Exception as e:
                    logger.warning(f"Failed to add file/directory to zip during walk {root}: {str(e)}")
                    continue # Try to continue zipping other files
        
        logger.info(f"Zip file created successfully: {zip_path}. Encrypting for download...")
        
        if not zip_path.exists() or not os.access(zip_path, os.R_OK):
            raise HTTPException(status_code=500, detail="Failed to create or read zip file")
        
        # Read the created zip file's content
        with open(zip_path, 'rb') as f_zip:
            zip_data = f_zip.read()

        # Encrypt the zip data
        encrypted_zip_data = security_manager.encrypt_data(zip_data)
        
        logger.info(f"Sending encrypted folder: {zip_filename}, size: {len(encrypted_zip_data)} bytes")

        def cleanup_after_send():
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary directory {temp_dir}: {str(e)}")
                
        response = Response(
            content=encrypted_zip_data,
            media_type='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename="{zip_filename}.enc"'},
            background=BackgroundTask(cleanup_after_send)
        )
        return response
            
    except zipfile.BadZipFile as e:
        logger.error(f"Failed to create zip file: {str(e)}", exc_info=True)
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail="Failed to create zip file")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating zip file: {str(e)}", exc_info=True)
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Error creating zip file: {str(e)}")

@app.put("/upload/{filename}", dependencies=[Depends(require_auth)])
async def upload_file(
    filename: str,
    file: UploadFile = File(...),
    dest_path: str = Form(...)
):
    """Upload a file to a specific absolute path"""
    try:
        if not filename or not isinstance(filename, str):
            raise HTTPException(status_code=400, detail="Invalid filename")
            
        safe_filename = "".join(c for c in filename if c.isalnum() or c in "._- ")
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid filename after sanitization")
            
        # Convert destination path to absolute path
        effective_dest_path = Path(dest_path).resolve()

        # Security check: disallow upload to blacklisted paths
        if is_path_blacklisted(effective_dest_path):
            raise HTTPException(status_code=403, detail="Cannot upload to a restricted system path.")

        # Check for traversal using '..' after resolve to be safe, though resolve typically handles this.
        if ".." in effective_dest_path.parts:
            raise HTTPException(status_code=400, detail="Path traversal (..) not allowed in destination.")

        if not effective_dest_path.exists():
            raise HTTPException(status_code=404, detail="Destination directory not found")
        if not effective_dest_path.is_dir():
            raise HTTPException(status_code=400, detail="Destination path is not a directory")
            
        # Check write permissions for the destination directory
        if not os.access(effective_dest_path, os.W_OK):
            raise HTTPException(status_code=403, detail="Permission denied to write to destination directory.")

        full_path = effective_dest_path / safe_filename
        
        if full_path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"File already exists at {full_path}"
            )
            
        logger.info(f"Uploading file to: {full_path}")
        
        content_length = file.headers.get('content-length')
        if content_length:
            try:
                file_size = int(content_length)
                logger.info(f"File size: {file_size} bytes")
            except ValueError:
                logger.warning("Invalid content-length header")
                file_size = None
        else:
            file_size = None
            
        try:
            with open(full_path, "wb") as out_file:
                chunk_size = 8192 * 4  # 32KB chunks
                total_written = 0
                last_log = 0
                
                while chunk := await file.read(chunk_size):
                    out_file.write(chunk)
                    total_written += len(chunk)
                    
                    if file_size and total_written - last_log >= file_size * 0.1:
                        progress = int((total_written / file_size) * 100)
                        logger.debug(f"Upload progress: {progress}%")
                        last_log = total_written
                        
            logger.info(f"File successfully saved to {full_path}")
            return UploadResponse(
                status="success",
                path=str(full_path),
                message="File uploaded successfully"
            )
        except Exception as e:
            try:
                if full_path.exists():
                    full_path.unlink()
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up partial file: {str(cleanup_error)}")
            raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload-folder", dependencies=[Depends(require_auth)])
async def upload_folder(
    request: Request,
    dest_path: str = Header(..., alias="X-Dest-Path"),
    folder_name: str = Header(..., alias="X-Folder-Name")
):
    """Upload and extract a folder from a zip file to a specific absolute path"""
    temp_dir = None
    zip_path = None
    full_path = None # Initialize full_path for cleanup in case of early error

    try:
        # Decode base64 headers
        try:
            folder_name = base64.b64decode(folder_name.encode('ascii')).decode('utf-8')
            dest_path = base64.b64decode(dest_path.encode('ascii')).decode('utf-8')
        except Exception as e:
            logger.error(f"Error decoding headers: {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid header encoding")
            
        # Validate inputs
        if not folder_name or not isinstance(folder_name, str):
            raise HTTPException(status_code=400, detail="Invalid folder name")
            
        safe_folder_name = "".join(c for c in folder_name if c.isalnum() or c in "._- ")
        if not safe_folder_name:
            raise HTTPException(status_code=400, detail="Invalid folder name after sanitization")
            
        # Convert destination path to absolute path
        effective_dest_path = Path(dest_path).resolve()

        # Security check: disallow upload to blacklisted paths
        if is_path_blacklisted(effective_dest_path):
            raise HTTPException(status_code=403, detail="Cannot upload to a restricted system path.")

        # Check for traversal using '..' after resolve
        if ".." in effective_dest_path.parts:
            raise HTTPException(status_code=400, detail="Path traversal (..) not allowed in destination.")

        if not effective_dest_path.exists():
            raise HTTPException(status_code=404, detail="Destination directory not found")
        if not effective_dest_path.is_dir():
            raise HTTPException(status_code=400, detail="Destination path is not a directory")
            
        # Check write permissions for the destination directory
        if not os.access(effective_dest_path, os.W_OK):
            raise HTTPException(status_code=403, detail="Permission denied to write to destination directory.")
            
        full_path = effective_dest_path / safe_folder_name # Set full_path here
        
        if full_path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Folder already exists at {full_path}"
            )
            
        logger.info(f"Uploading folder to: {full_path}")
        
        content_length = request.headers.get('content-length')
        if content_length:
            try:
                file_size = int(content_length)
                logger.info(f"Zip file size: {file_size} bytes")
                if file_size > 2 * 1024 * 1024 * 1024 * 1024: # 2TB, effectively unlimited for most purposes
                    raise HTTPException(status_code=400, detail="Zip file exceeds maximum size limit of 2TB")
            except ValueError:
                logger.warning("Invalid content-length header")
                file_size = None
        else:
            file_size = None
            
        temp_dir = tempfile.mkdtemp()
        zip_path = Path(temp_dir) / f"{safe_folder_name}.zip"
        logger.debug(f"Creating temporary zip file at: {zip_path}")
        
        try:
            with open(zip_path, "wb") as out_file:
                chunk_size = 1024 * 1024  # 1MB chunks for better performance
                total_written = 0
                last_progress = 0
                
                async for chunk in request.stream():
                    if not chunk:  # EOF
                        break
                        
                    out_file.write(chunk)
                    total_written += len(chunk)
                    
                    if file_size:
                        current_progress = int((total_written / file_size) * 100)
                        if current_progress - last_progress >= 5:
                            logger.debug(f"Upload progress: {current_progress}% ({total_written}/{file_size} bytes)")
                            last_progress = current_progress
                            
            if file_size and total_written != file_size:
                raise HTTPException(
                    status_code=400,
                    detail=f"File upload incomplete. Expected {file_size} bytes but received {total_written} bytes"
                )
                
            logger.info(f"Zip file upload complete: {total_written} bytes written")
            
            if not zip_path.exists() or zip_path.stat().st_size == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Uploaded file is empty or does not exist"
                )
                
        except Exception as e:
            logger.error(f"Error saving zip file: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error saving zip file: {str(e)}")
            
        # Validate zip file before extraction
        try:
            if not zip_path.exists():
                raise HTTPException(status_code=400, detail="Zip file not found after upload")
            if zip_path.stat().st_size == 0:
                raise HTTPException(status_code=400, detail="Uploaded file is empty")
                
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                test_result = zipf.testzip()
                if test_result is not None:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Zip file integrity check failed at: {test_result}"
                    )
                
                if not zipf.namelist():
                    raise HTTPException(status_code=400, detail="Zip file is empty")
                
                for name in zipf.namelist():
                    name = name.replace('\\', '/')
                    
                    if name.startswith('/') or name.startswith('\\'):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid path in zip: {name} (contains absolute path)"
                        )
                    
                    if '..' in Path(name).parts: # Using Path.parts for robustness
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid path in zip: {name} (contains parent directory reference)"
                        )
                    
                    invalid_chars = '<>:"|?*'
                    if any(char in name for char in invalid_chars):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid characters in filename: {name}"
                        )
                    
                    if len(name) > 260:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Path too long: {name}"
                        )
                
                full_path.mkdir(parents=True, exist_ok=True)
                
                total_files = len(zipf.namelist())
                for i, name in enumerate(zipf.namelist()):
                    try:
                        safe_name = name.replace('\\', '/')
                        target_path = full_path / safe_name
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        with zipf.open(name) as source, open(target_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        
                        if (i + 1) % 10 == 0:
                            progress = int(((i + 1) / total_files) * 100)
                            logger.debug(f"Extraction progress: {progress}%")
                            
                    except Exception as e:
                        logger.error(f"Error extracting {name}: {str(e)}")
                        if full_path.exists():
                            shutil.rmtree(full_path)
                        raise HTTPException(
                            status_code=500,
                            detail=f"Error extracting {name}: {str(e)}"
                        )
                        
        except zipfile.BadZipFile as e:
            logger.error(f"Invalid zip file format: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Invalid zip file format: {str(e)}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error processing zip file: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error processing zip file: {str(e)}")
            
        logger.info(f"Folder successfully extracted to {full_path}")
        return UploadResponse(
            status="success",
            path=str(full_path),
            message="Folder uploaded and extracted successfully"
        )
        
    except HTTPException:
        if full_path and full_path.exists():
            try:
                shutil.rmtree(full_path)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up partial folder: {str(cleanup_error)}")
        raise
    except Exception as e:
        logger.error(f"Error uploading folder: {str(e)}", exc_info=True)
        if full_path and full_path.exists():
            try:
                shutil.rmtree(full_path)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up partial folder: {str(cleanup_error)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try:
                if zip_path and zip_path.exists():
                    zip_path.unlink()
                shutil.rmtree(temp_dir)
                logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary directory {temp_dir}: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting server...")
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=5000,
        ssl_certfile="certs/device_cert.pem",
        ssl_keyfile="certs/device_key.pem",
    )
