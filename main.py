# main.py

import threading
import uvicorn
from gui.main_window import run as run_gui
from shared.cert_manager import ensure_certificates
from shared.config import settings
import sys
from PyQt5.QtCore import QTimer, QObject, pyqtSignal
import logging
from shared.logging_config import setup_logger

# Set up logger
logger = setup_logger(__name__)

class ServerManager(QObject):
    """Manages the backend server lifecycle"""
    server_error = pyqtSignal(str)  # Signal for server errors
    
    def __init__(self):
        super().__init__()
        self.server = None
        self.config = uvicorn.Config(
            "backend.server:app",
            host="0.0.0.0",
            port=settings.http_port,
            ssl_certfile=str(settings.tls_cert),
            ssl_keyfile=str(settings.tls_key),
            log_level="debug",
            reload=False,
            workers=1,
            loop="asyncio",
            timeout_keep_alive=30,
            timeout_graceful_shutdown=10
        )
        self.should_run = True
        
    def start(self):
        """Start the server in a non-blocking way"""
        try:
            logger.info(f"Starting backend server on port {settings.http_port}")
            self.server = uvicorn.Server(self.config)
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            logger.info("Backend server thread started")
        except Exception as e:
            logger.error(f"Failed to start server: {str(e)}", exc_info=True)
            self.server_error.emit(str(e))
            
    def _run_server(self):
        """Run the server in a loop with error handling"""
        while self.should_run:
            try:
                self.server.run()
            except Exception as e:
                logger.error(f"Server error: {str(e)}", exc_info=True)
                self.server_error.emit(str(e))
                if self.should_run:
                    logger.info("Attempting to restart server in 5 seconds...")
                    QTimer.singleShot(5000, self.start)
                break
                
    def stop(self):
        """Stop the server gracefully"""
        self.should_run = False
        if self.server:
            try:
                self.server.should_exit = True
                if hasattr(self.server, 'handle_exit'):
                    self.server.handle_exit(None, None)
            except Exception as e:
                logger.error(f"Error stopping server: {str(e)}", exc_info=True)

def main():
    """Main entry point with improved error handling"""
    try:
        # Ensure TLS certificate exists
        ensure_certificates()
        logger.info(f"Starting application with device_id: {settings.device_id}")
        logger.info(f"Backend will run on port {settings.http_port}")

        # Create and start server manager
        server_manager = ServerManager()
        server_manager.server_error.connect(lambda msg: logger.error(f"Server error: {msg}"))
        server_manager.start()

        # Launch GUI
        run_gui()
        
        # Cleanup when GUI closes
        server_manager.stop()
        
    except Exception as e:
        logger.error(f"Application startup error: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
