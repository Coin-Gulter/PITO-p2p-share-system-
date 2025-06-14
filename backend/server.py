# p2pshare/backend/server.py

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Body, Query, Form, Request, Header
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer
import os, shutil, uuid
from pathlib import Path
import jwt
from shared.config import settings
from shared.logging_config import setup_logger
from pydantic import BaseModel
from typing import List, Optional
import stat
import tempfile
import zipfile
import time
from starlette.background import BackgroundTask
import base64

# Set up logger
logger = setup_logger(__name__)

# Auth request model
class AuthRequest(BaseModel):
    device_id: str

class FileInfo(BaseModel):
    name: str
    path: str
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
app.state.SHARE_DIR = Path.home() / "P2PShare"
security = HTTPBearer()

def get_share_dir():
    return app.state.SHARE_DIR

# Re-expose SHARE_DIR at module level for backward compatibility
SHARE_DIR = property(get_share_dir)

# Create share directory if not exists
os.makedirs(get_share_dir(), exist_ok=True)
logger.info(f"Share directory initialized at {get_share_dir()}")

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

@app.get("/files", dependencies=[Depends(require_auth)])
def list_files():
    """List visible files in the share directory"""
    try:
        # Get all files in the directory
        files = []
        for f in get_share_dir().iterdir():
            # Only include regular files (not directories) that are visible
            # and are in the temp directory (to avoid listing system files)
            if (f.is_file() and 
                not f.name.startswith('.') and 
                not f.name.startswith('~') and
                f.parent == get_share_dir()):  # Only list files directly in the share directory
                try:
                    # Check if file is readable
                    if os.access(f, os.R_OK):
                        files.append(f.name)
                except Exception as e:
                    logger.warning(f"Error accessing file {f}: {str(e)}")
                    continue
                    
        logger.info(f"Listed {len(files)} files in share directory")
        return JSONResponse(files)
    except Exception as e:
        logger.error(f"Error listing files: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/files/{filename}", dependencies=[Depends(require_auth)])
def download_file(filename: str):
    file_path = get_share_dir() / filename
    if file_path.exists():
        logger.info(f"File download requested: {filename}")
        return FileResponse(file_path)
    logger.warning(f"File not found: {filename}")
    raise HTTPException(status_code=404, detail="File not found")


@app.post("/auth")
def auth(request: AuthRequest):
    logger.info(f"Authentication request from device: {request.device_id}")
    token = create_jwt(request.device_id)
    return {"token": token}

def get_file_info(path: Path) -> FileInfo:
    """Get information about a file or directory"""
    try:
        stat_info = path.stat()
        return FileInfo(
            name=path.name,
            path=str(path),
            is_dir=path.is_dir(),
            size=stat_info.st_size if path.is_file() else None,
            modified=stat_info.st_mtime
        )
    except Exception as e:
        logger.error(f"Error getting file info for {path}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/browse", dependencies=[Depends(require_auth)])
def list_directory(path: str = Query("/", description="Directory path to list")):
    """List contents of a directory"""
    try:
        # Convert to absolute path and normalize
        abs_path = Path(path).resolve()
        
        # Security check: prevent directory traversal
        if not abs_path.exists():
            raise HTTPException(status_code=404, detail="Directory not found")
            
        if not abs_path.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
            
        # List directory contents
        items = []
        for item in abs_path.iterdir():
            try:
                items.append(get_file_info(item))
            except Exception as e:
                logger.warning(f"Error getting info for {item}: {str(e)}")
                continue
                
        logger.info(f"Listed directory: {path} ({len(items)} items)")
        return items
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing directory {path}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/file-info", dependencies=[Depends(require_auth)])
def get_file_info_endpoint(path: str = Query(..., description="Path to get info for")):
    """Get information about a specific file or directory"""
    try:
        abs_path = Path(path).resolve()
        if not abs_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        return get_file_info(abs_path)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting file info for {path}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download", dependencies=[Depends(require_auth)])
def download_file(path: str = Query(..., description="Path of file to download")):
    """Download a file from any location"""
    try:
        file_path = Path(path).resolve()
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        if not file_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
            
        logger.info(f"File download requested: {path}")
        return FileResponse(
            file_path,
            filename=file_path.name,
            media_type='application/octet-stream'
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading file {path}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download-folder", dependencies=[Depends(require_auth)])
def download_folder(path: str = Query(..., description="Path of folder to download")):
    """Download a folder as a zip file"""
    temp_dir = None
    try:
        # Log the incoming request
        logger.info(f"Folder download requested for path: {path}")
        
        # Convert to absolute path and normalize
        try:
            folder_path = Path(path).resolve()
            logger.debug(f"Resolved path to: {folder_path}")
        except Exception as e:
            logger.error(f"Failed to resolve path {path}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=400, detail=f"Invalid path: {str(e)}")
        
        # Check if path exists and is a directory
        if not folder_path.exists():
            logger.warning(f"Folder not found: {folder_path}")
            raise HTTPException(status_code=404, detail="Folder not found")
        if not folder_path.is_dir():
            logger.warning(f"Path is not a folder: {folder_path}")
            raise HTTPException(status_code=400, detail="Path is not a folder")
            
        # Check if we have read permissions
        try:
            os.access(folder_path, os.R_OK)
        except Exception as e:
            logger.error(f"No read permission for folder {folder_path}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=403, detail="No permission to read folder")
            
        # Create a temporary directory for the zip file
        try:
            temp_dir = tempfile.mkdtemp()
            logger.debug(f"Created temporary directory: {temp_dir}")
        except Exception as e:
            logger.error(f"Failed to create temporary directory: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to create temporary directory")
            
        # Create zip file name using folder name and timestamp
        zip_filename = f"{folder_path.name}_{int(time.time())}.zip"
        zip_path = Path(temp_dir) / zip_filename
        logger.info(f"Creating zip file: {zip_path}")
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the directory
            for root, dirs, files in os.walk(folder_path):
                try:
                    # Get relative path for files in zip, including the parent folder name
                    rel_path = Path(root).relative_to(folder_path.parent)
                    logger.debug(f"Processing directory: {rel_path}")
                    
                    # Add files to zip
                    for file in files:
                        try:
                            file_path = Path(root) / file
                            # Check if file is readable
                            if not os.access(file_path, os.R_OK):
                                logger.warning(f"No read permission for file: {file_path}")
                                continue
                                
                            # Add file to zip with relative path including parent folder
                            zipf.write(file_path, rel_path / file)
                            logger.debug(f"Added to zip: {file_path}")
                        except Exception as e:
                            logger.warning(f"Failed to add file {file} to zip: {str(e)}")
                            continue
                except Exception as e:
                    logger.warning(f"Failed to process directory {root}: {str(e)}")
                    continue
        
        logger.info(f"Zip file created successfully: {zip_path}")
        
        # Check if zip file was created and is readable
        if not zip_path.exists():
            raise HTTPException(status_code=500, detail="Failed to create zip file")
        if not os.access(zip_path, os.R_OK):
            raise HTTPException(status_code=500, detail="No permission to read zip file")
            
        # Create a custom response that will clean up the temp directory after sending
        def cleanup_after_send():
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary directory {temp_dir}: {str(e)}")
                
        # Return the zip file with cleanup callback
        response = FileResponse(
            zip_path,
            filename=zip_filename,
            media_type='application/zip',
            background=BackgroundTask(cleanup_after_send)  # Clean up after sending
        )
        return response
            
    except zipfile.BadZipFile as e:
        logger.error(f"Failed to create zip file: {str(e)}", exc_info=True)
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail="Failed to create zip file")
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
    """Upload a file to a specific path"""
    try:
        # Validate filename
        if not filename or not isinstance(filename, str):
            raise HTTPException(status_code=400, detail="Invalid filename")
            
        # Sanitize filename
        safe_filename = "".join(c for c in filename if c.isalnum() or c in "._- ")
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid filename after sanitization")
            
        # Convert destination path to absolute path
        try:
            dest_path = Path(dest_path).resolve()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid destination path: {str(e)}")
        
        # Security check: ensure destination is within allowed paths
        if not dest_path.exists():
            raise HTTPException(status_code=404, detail="Destination directory not found")
        if not dest_path.is_dir():
            raise HTTPException(status_code=400, detail="Destination path is not a directory")
            
        # Create full destination path
        full_path = dest_path / safe_filename
        
        # Check if file already exists
        if full_path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"File already exists at {full_path}"
            )
            
        logger.info(f"Uploading file to: {full_path}")
        
        # Get file size from content-length header
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
            
        # Save the file with progress tracking
        try:
            with open(full_path, "wb") as out_file:
                chunk_size = 8192 * 4  # 32KB chunks
                total_written = 0
                last_log = 0
                
                while chunk := await file.read(chunk_size):
                    out_file.write(chunk)
                    total_written += len(chunk)
                    
                    # Log progress every 10%
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
            # Clean up partial file on error
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
    """Upload and extract a folder from a zip file using raw streaming"""
    temp_dir = None
    zip_path = None
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
            
        # Sanitize folder name
        safe_folder_name = "".join(c for c in folder_name if c.isalnum() or c in "._- ")
        if not safe_folder_name:
            raise HTTPException(status_code=400, detail="Invalid folder name after sanitization")
            
        # Convert destination path to absolute path
        try:
            dest_path = Path(dest_path).resolve()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid destination path: {str(e)}")
            
        # Security check: ensure destination is within allowed paths
        if not dest_path.exists():
            raise HTTPException(status_code=404, detail="Destination directory not found")
        if not dest_path.is_dir():
            raise HTTPException(status_code=400, detail="Destination path is not a directory")
            
        # Create full destination path
        full_path = dest_path / safe_folder_name
        
        # Check if folder already exists
        if full_path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Folder already exists at {full_path}"
            )
            
        logger.info(f"Uploading folder to: {full_path}")
        
        # Get file size from content-length header
        content_length = request.headers.get('content-length')
        if content_length:
            try:
                file_size = int(content_length)
                logger.info(f"Zip file size: {file_size} bytes")
                # Check if file is too large (e.g., 2TB)
                if file_size > 2 * 1024 * 1024 * 1024 * 1024: # 2TB, effectively unlimited for most purposes
                    raise HTTPException(status_code=400, detail="Zip file exceeds maximum size limit of 2TB")
            except ValueError:
                logger.warning("Invalid content-length header")
                file_size = None
        else:
            file_size = None
            
        # Create temporary directory for the upload
        temp_dir = tempfile.mkdtemp()
        zip_path = Path(temp_dir) / f"{safe_folder_name}.zip"
        logger.debug(f"Creating temporary zip file at: {zip_path}")
        
        # Save zip file with progress tracking and proper streaming
        try:
            with open(zip_path, "wb") as out_file:
                chunk_size = 1024 * 1024  # 1MB chunks for better performance
                total_written = 0
                last_log = 0
                last_progress = 0
                
                # Read file in chunks until EOF
                async for chunk in request.stream():
                    if not chunk:  # EOF
                        break
                        
                    out_file.write(chunk)
                    total_written += len(chunk)
                    
                    # Log progress every 5%
                    if file_size:
                        current_progress = int((total_written / file_size) * 100)
                        if current_progress - last_progress >= 5:
                            logger.debug(f"Upload progress: {current_progress}% ({total_written}/{file_size} bytes)")
                            last_progress = current_progress
                            
            # Verify file was completely written
            if file_size and total_written != file_size:
                raise HTTPException(
                    status_code=400,
                    detail=f"File upload incomplete. Expected {file_size} bytes but received {total_written} bytes"
                )
                
            logger.info(f"Zip file upload complete: {total_written} bytes written")
            
            # Verify the file exists and has content
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
            # First check if file exists and has content
            if not zip_path.exists():
                raise HTTPException(status_code=400, detail="Zip file not found after upload")
            if zip_path.stat().st_size == 0:
                raise HTTPException(status_code=400, detail="Uploaded file is empty")
                
            # Try to open as zip file
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # Test zip file integrity
                test_result = zipf.testzip()
                if test_result is not None:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Zip file integrity check failed at: {test_result}"
                    )
                
                # Check if zip file is not empty
                if not zipf.namelist():
                    raise HTTPException(status_code=400, detail="Zip file is empty")
                
                # Validate zip contents
                for name in zipf.namelist():
                    # Convert backslashes to forward slashes for consistency
                    name = name.replace('\\', '/')
                    
                    # Check for absolute paths
                    if name.startswith('/') or name.startswith('\\'):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid path in zip: {name} (contains absolute path)"
                        )
                    
                    # Check for parent directory references
                    if '..' in name.split('/'):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid path in zip: {name} (contains parent directory reference)"
                        )
                    
                    # Check for invalid characters
                    invalid_chars = '<>:"|?*'
                    if any(char in name for char in invalid_chars):
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid characters in filename: {name}"
                        )
                    
                    # Check for maximum path length (Windows limit)
                    if len(name) > 260:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Path too long: {name}"
                        )
                
                # Create destination directory
                full_path.mkdir(parents=True, exist_ok=True)
                
                # Extract files with progress tracking
                total_files = len(zipf.namelist())
                for i, name in enumerate(zipf.namelist()):
                    try:
                        # Convert path separators for Windows
                        safe_name = name.replace('\\', '/')
                        
                        # Calculate target path
                        target_path = full_path / safe_name
                        
                        # Ensure parent directory exists
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Extract file
                        with zipf.open(name) as source, open(target_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        
                        # Log progress every 10 files
                        if (i + 1) % 10 == 0:
                            progress = int(((i + 1) / total_files) * 100)
                            logger.debug(f"Extraction progress: {progress}%")
                            
                    except Exception as e:
                        logger.error(f"Error extracting {name}: {str(e)}")
                        # Clean up partial extraction
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
        # Clean up partial folder on error
        if full_path and full_path.exists():
            try:
                shutil.rmtree(full_path)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up partial folder: {str(cleanup_error)}")
        raise
    except Exception as e:
        logger.error(f"Error uploading folder: {str(e)}", exc_info=True)
        # Clean up partial folder on error
        if full_path and full_path.exists():
            try:
                shutil.rmtree(full_path)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up partial folder: {str(cleanup_error)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temporary directory and zip file
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
