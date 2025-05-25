import pytest
from PyQt5.QtCore import QObject, QTimer
from PyQt5.QtTest import QSignalSpy
import threading
import time
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from main import ServerManager
from shared.config import settings

class TestServerManager:
    @pytest.fixture
    def server_manager(self):
        """Create a ServerManager instance for testing"""
        manager = ServerManager()
        yield manager
        manager.stop()  # Cleanup after tests
    
    def test_server_manager_initialization(self, server_manager):
        """Test ServerManager initialization"""
        assert server_manager.server is None
        assert server_manager.should_run is True
        assert server_manager.config.app == "backend.server:app"
        assert server_manager.config.host == "0.0.0.0"
        assert server_manager.config.port == settings.http_port
        assert server_manager.config.ssl_certfile == str(settings.tls_cert)
        assert server_manager.config.ssl_keyfile == str(settings.tls_key)
    
    def test_server_error_signal(self, server_manager):
        """Test server error signal emission"""
        spy = QSignalSpy(server_manager.server_error)
        
        # Simulate an error
        error_message = "Test error"
        server_manager.server_error.emit(error_message)
        
        assert len(spy) == 1
        assert spy[0][0] == error_message
    
    def test_server_start_stop(self, server_manager, monkeypatch):
        """Test server start and stop functionality"""
        # Mock the server
        mock_server = MagicMock()
        monkeypatch.setattr("uvicorn.Server", lambda *args, **kwargs: mock_server)
        
        # Start server
        server_manager.start()
        assert server_manager.server is not None
        assert server_manager.server_thread is not None
        assert server_manager.server_thread.is_alive()
        
        # Stop server
        server_manager.stop()
        assert server_manager.should_run is False
        # Give thread time to clean up
        server_manager.server_thread.join(timeout=2)
        assert not server_manager.server_thread.is_alive()
    
    def test_server_restart_on_error(self, server_manager, monkeypatch):
        """Test server restart on error"""
        spy = QSignalSpy(server_manager.server_error)
        
        # Mock the server with a run method that raises an exception
        mock_server = MagicMock()
        mock_server.run.side_effect = Exception("Test server error")
        monkeypatch.setattr("uvicorn.Server", lambda *args, **kwargs: mock_server)
        
        # Start server
        server_manager.start()
        time.sleep(0.1)  # Give time for error to occur
        
        # Verify error signal was emitted
        assert len(spy) > 0
        assert "Test server error" in spy[0][0]
        
        # Verify server was marked for restart
        assert server_manager.should_run is True
    
    def test_server_cleanup(self, server_manager, monkeypatch):
        """Test server cleanup on stop"""
        # Mock the server
        mock_server = MagicMock()
        monkeypatch.setattr("uvicorn.Server", lambda *args, **kwargs: mock_server)
        
        # Start server
        server_manager.start()
        assert server_manager.server is not None
        
        # Stop server
        server_manager.stop()
        
        # Verify cleanup
        assert server_manager.should_run is False
        assert mock_server.should_exit is True
    
    def test_server_thread_daemon(self, server_manager, monkeypatch):
        """Test server thread is daemon"""
        # Mock the server
        mock_server = MagicMock()
        monkeypatch.setattr("uvicorn.Server", lambda *args, **kwargs: mock_server)
        
        server_manager.start()
        assert server_manager.server_thread.daemon is True
        server_manager.stop()
    
    def test_multiple_start_stop(self, server_manager, monkeypatch):
        """Test multiple start/stop cycles"""
        # Mock the server
        mock_server = MagicMock()
        monkeypatch.setattr("uvicorn.Server", lambda *args, **kwargs: mock_server)
        
        for i in range(3):
            # Reset server state
            server_manager.server = None
            server_manager.server_thread = None
            server_manager.should_run = True
            
            # Start server
            server_manager.start()
            assert server_manager.server is not None
            assert server_manager.server_thread is not None
            assert server_manager.server_thread.is_alive()
            
            # Stop server
            server_manager.stop()
            assert server_manager.should_run is False
            
            # Give thread time to clean up
            if server_manager.server_thread:
                server_manager.server_thread.join(timeout=2)
                assert not server_manager.server_thread.is_alive()
            
            # Small delay between cycles
            time.sleep(0.1)
    
    def test_server_error_handling(self, server_manager, monkeypatch):
        """Test server error handling and logging"""
        spy = QSignalSpy(server_manager.server_error)
        
        # Mock the server with a run method that raises different types of exceptions
        mock_server = MagicMock()
        mock_server.run.side_effect = ConnectionError("Connection failed")
        monkeypatch.setattr("uvicorn.Server", lambda *args, **kwargs: mock_server)
        
        # Start server
        server_manager.start()
        time.sleep(0.1)  # Give time for error to occur
        
        # Verify error was caught and signal emitted
        assert len(spy) > 0
        assert "Connection failed" in spy[0][0]
        
        server_manager.stop()
    
    def test_server_config_validation(self, server_manager):
        """Test server configuration validation"""
        # Verify critical config settings
        assert server_manager.config.workers == 1  # Single worker for testing
        assert server_manager.config.reload is False  # No auto-reload in production
        assert server_manager.config.loop == "asyncio"
        assert server_manager.config.timeout_keep_alive == 30
        assert server_manager.config.timeout_graceful_shutdown == 10 