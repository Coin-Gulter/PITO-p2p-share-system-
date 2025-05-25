import pytest
import os
import tempfile
import shutil
from pathlib import Path
from shared.config import Settings, CONFIG_DIR
import sys

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from shared.config import settings, Settings, CONFIG_DIR

# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)

# Create a test settings instance
def create_test_settings(temp_cert_dir, test_port, test_share_dir):
    return Settings(
        device_id="test_device_123",
        share_dir=Path(test_share_dir),
        http_port=test_port,
        tls_cert=Path(temp_cert_dir) / "device_cert.pem",
        tls_key=Path(temp_cert_dir) / "device_key.pem",
        ca_cert=Path(temp_cert_dir) / "ca.pem"
    )

@pytest.fixture(scope="session")
def temp_cert_dir():
    """Create a temporary directory for test certificates"""
    temp_dir = tempfile.mkdtemp()
    cert_dir = Path(temp_dir)
    cert_dir.mkdir(exist_ok=True)
    
    # Create test certificates
    from shared.cert_manager import ensure_certificates
    ensure_certificates()
    
    yield temp_dir
    
    # Cleanup
    shutil.rmtree(temp_dir)

@pytest.fixture(scope="session")
def test_port():
    """Test port for server"""
    return 5001  # Use a different port than production

@pytest.fixture
def test_share_dir():
    """Create a temporary share directory for testing"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Ensure directory is empty
        for item in Path(temp_dir).iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)

@pytest.fixture(autouse=True)
def setup_test_environment(temp_cert_dir, test_port, test_share_dir, monkeypatch):
    """Setup test environment before each test"""
    # Create test settings
    test_settings = create_test_settings(temp_cert_dir, test_port, test_share_dir)
    
    # Patch the settings module to use our test settings
    monkeypatch.setattr("shared.config.settings", test_settings)
    
    yield
    
    # No cleanup needed as temp directories are handled by their fixtures

@pytest.fixture
def mock_logger(monkeypatch):
    """Mock logger to prevent actual logging during tests"""
    class MockLogger:
        def __init__(self):
            self.messages = []
            self.level = "INFO"
        
        def debug(self, msg, *args, **kwargs):
            self.messages.append(("DEBUG", msg))
        
        def info(self, msg, *args, **kwargs):
            self.messages.append(("INFO", msg))
        
        def warning(self, msg, *args, **kwargs):
            self.messages.append(("WARNING", msg))
        
        def error(self, msg, *args, **kwargs):
            self.messages.append(("ERROR", msg))
        
        def critical(self, msg, *args, **kwargs):
            self.messages.append(("CRITICAL", msg))
    
    logger = MockLogger()
    monkeypatch.setattr("shared.logging_config.setup_logger", lambda *args: logger)
    return logger

@pytest.fixture
def test_file():
    """Create a test file with content"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test content")
        return f.name

@pytest.fixture
def test_directory():
    """Create a test directory with files"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Create some test files
        for i in range(3):
            with open(os.path.join(temp_dir, f"test{i}.txt"), "w") as f:
                f.write(f"test content {i}")
        
        # Create a subdirectory with files
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir)
        for i in range(2):
            with open(os.path.join(subdir, f"subtest{i}.txt"), "w") as f:
                f.write(f"subtest content {i}")
        
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir) 