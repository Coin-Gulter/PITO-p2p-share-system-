import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
import httpx
from pathlib import Path
import tempfile
import shutil
import os
import sys
import zipfile
import io
import asyncio
from typing import AsyncGenerator

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.server import app, create_jwt, SHARE_DIR
from shared.config import settings

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def auth_token():
    return create_jwt(settings.device_id)

@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}

@pytest.fixture
def temp_share_dir():
    """Create a temporary share directory for testing"""
    temp_dir = tempfile.mkdtemp()
    original_share_dir = app.state.SHARE_DIR
    app.state.SHARE_DIR = Path(temp_dir)
    
    def cleanup_dir():
        for item in Path(temp_dir).iterdir():
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            except Exception as e:
                print(f"Warning: Failed to clean up {item}: {e}")
    cleanup_dir()
    yield temp_dir
    cleanup_dir()
    shutil.rmtree(temp_dir)
    app.state.SHARE_DIR = original_share_dir

@pytest_asyncio.fixture
async def async_client():
    """Create an async test client"""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

def test_ping(client):
    """Test the ping endpoint"""
    response = client.get("/ping")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["device_id"] == settings.device_id

def test_auth(client):
    """Test authentication endpoint"""
    response = client.post("/auth", json={"device_id": settings.device_id})
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert isinstance(data["token"], str)

def test_auth_invalid_device(client):
    """Test authentication with invalid device ID"""
    response = client.post("/auth", json={"device_id": "invalid_device"})
    assert response.status_code == 200  # Still returns a token, but it won't work for protected endpoints

def test_list_files_empty(client, auth_headers, temp_share_dir):
    """Test listing files in empty directory"""
    # Double check directory is empty
    assert len(list(Path(temp_share_dir).iterdir())) == 0
    
    response = client.get("/files", headers=auth_headers)
    assert response.status_code == 200
    files = response.json()
    assert isinstance(files, list)
    assert len(files) == 0

def test_list_files_with_content(client, auth_headers, temp_share_dir):
    """Test listing files with content"""
    # Ensure directory is empty first
    for item in Path(temp_share_dir).iterdir():
        if item.is_file():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)
    
    # Create test files
    test_files = ["test1.txt", "test2.txt"]
    for filename in test_files:
        file_path = Path(temp_share_dir) / filename
        file_path.write_text("test content")
    
    # Verify only our test files exist
    assert len(list(Path(temp_share_dir).iterdir())) == len(test_files)
    
    response = client.get("/files", headers=auth_headers)
    assert response.status_code == 200
    files = response.json()
    assert isinstance(files, list)
    assert len(files) == len(test_files)
    assert all(filename in files for filename in test_files)

def test_download_file(client, auth_headers, temp_share_dir):
    """Test downloading a file"""
    # Create test file
    test_content = "test content"
    test_file = "test.txt"
    file_path = os.path.join(temp_share_dir, test_file)
    with open(file_path, "w") as f:
        f.write(test_content)
    
    # Use the correct endpoint
    response = client.get(f"/download?path={file_path}", headers=auth_headers)
    assert response.status_code == 200
    assert response.content.decode() == test_content

def test_download_nonexistent_file(client, auth_headers):
    """Test downloading a non-existent file"""
    response = client.get("/download?path=/nonexistent/path/file.txt", headers=auth_headers)
    assert response.status_code == 404

def test_browse_directory(client, auth_headers, temp_share_dir):
    """Test browsing directory contents"""
    # Create test directory structure
    test_dir = os.path.join(temp_share_dir, "test_dir")
    os.makedirs(test_dir)
    test_file = os.path.join(test_dir, "test.txt")
    with open(test_file, "w") as f:
        f.write("test content")
    
    response = client.get(f"/browse?path={test_dir}", headers=auth_headers)
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["name"] == "test.txt"
    assert items[0]["is_dir"] is False

def test_upload_file(client, auth_headers, temp_share_dir):
    """Test uploading a file"""
    test_content = b"test content"
    files = {"file": ("test.txt", test_content)}
    data = {"dest_path": temp_share_dir}
    
    response = client.put(
        "/upload/test.txt",
        headers=auth_headers,
        files=files,
        data=data
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["path"] == str(Path(temp_share_dir) / "test.txt")
    
    # Verify file was created
    uploaded_file = os.path.join(temp_share_dir, "test.txt")
    assert os.path.exists(uploaded_file)
    with open(uploaded_file, "rb") as f:
        assert f.read() == test_content

def test_upload_file_invalid_path(client, auth_headers):
    """Test uploading to invalid path"""
    test_content = b"test content"
    files = {"file": ("test.txt", test_content)}
    data = {"dest_path": "/nonexistent/path"}
    
    response = client.put(
        "/upload/test.txt",
        headers=auth_headers,
        files=files,
        data=data
    )
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_upload_folder(async_client, auth_headers, temp_share_dir):
    """Test uploading and extracting a folder"""
    # Create a test zip file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_zip:
        with zipfile.ZipFile(temp_zip.name, "w") as zipf:
            zipf.writestr("test_folder/test.txt", "test content")
            zipf.writestr("test_folder/subfolder/test2.txt", "test content 2")
    
    try:
        with open(temp_zip.name, "rb") as f:
            files = {"file": ("test_folder.zip", f)}
            data = {
                "dest_path": temp_share_dir,
                "folder_name": "test_folder"
            }
            response = await async_client.post(
                "/upload-folder",
                headers=auth_headers,
                files=files,
                data=data
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["path"] == str(Path(temp_share_dir) / "test_folder")
            
            # Verify folder was created with contents
            folder_path = Path(temp_share_dir) / "test_folder"
            assert folder_path.exists()
            assert (folder_path / "test.txt").exists()
            assert (folder_path / "subfolder" / "test2.txt").exists()
            
            # Verify file contents
            assert (folder_path / "test.txt").read_text() == "test content"
            assert (folder_path / "subfolder" / "test2.txt").read_text() == "test content 2"
    finally:
        if os.path.exists(temp_zip.name):
            os.unlink(temp_zip.name)

@pytest.mark.asyncio
async def test_download_folder(async_client, auth_headers, temp_share_dir):
    """Test downloading a folder as zip"""
    # Create test folder structure
    test_folder = Path(temp_share_dir) / "test_folder"
    test_folder.mkdir()
    (test_folder / "test.txt").write_text("test content")
    (test_folder / "subfolder").mkdir()
    (test_folder / "subfolder" / "test2.txt").write_text("test content 2")
    
    response = await async_client.get(
        f"/download-folder?path={test_folder}",
        headers=auth_headers
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    
    # Verify zip contents
    with zipfile.ZipFile(io.BytesIO(response.content)) as zipf:
        assert "test_folder/test.txt" in zipf.namelist()
        assert "test_folder/subfolder/test2.txt" in zipf.namelist()
        assert zipf.read("test_folder/test.txt").decode() == "test content"
        assert zipf.read("test_folder/subfolder/test2.txt").decode() == "test content 2"

def test_unauthorized_access(client):
    """Test accessing protected endpoints without auth"""
    endpoints = [
        ("GET", "/files"),
        ("GET", "/download?path=/test.txt"),
        ("GET", "/browse?path=/"),
        ("PUT", "/upload/test.txt"),
        ("POST", "/upload-folder"),
        ("GET", "/download-folder?path=/test")
    ]
    
    for method, endpoint in endpoints:
        if method == "GET":
            response = client.get(endpoint)
        elif method == "PUT":
            response = client.put(endpoint)
        elif method == "POST":
            response = client.post(endpoint)
        assert response.status_code == 403 