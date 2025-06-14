# main.py

import threading
import uvicorn
from gui.main_window import run as run_gui_app
from shared.cert_manager import ensure_certificates
from shared.config import settings
import sys
from PyQt5.QtCore import QTimer, QObject, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMessageBox # Import QApplication and QMessageBox
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
            # Get the port from the settings (settings get from environment variables)
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
                    # Note: QTimer needs a QApplication event loop, which might not be fully ready here.
                    # This might be safer to handle in the main GUI thread.
                    # QTimer.singleShot(5000, self.start)
                    pass # Placeholder, as restarting server from here is tricky without GUI loop
                break
                
    def stop(self):
        """Stop the server gracefully"""
        self.should_run = False
        if self.server:
            try:
                self.server.should_exit = True
                if hasattr(self.server, 'handle_exit'):
                    self.server.handle_exit(None, None)
                logger.info("Server graceful shutdown requested.")
            except Exception as e:
                logger.error(f"Error stopping server: {str(e)}", exc_info=True)

def main():
    """Main entry point with improved error handling for GUI loop"""
    app = None # Initialize app to None
    try:
        # Ensure TLS certificate exists
        ensure_certificates()
        logger.info(f"Starting application with device_id: {settings.device_id}")
        logger.info(f"Backend will run on port {settings.http_port}")

        # Create and start server manager
        server_manager = ServerManager()
        server_manager.server_error.connect(lambda msg: logger.error(f"Server runtime error: {msg}"))
        server_manager.start()
        
        # Launch GUI
        logger.info("Main: Creating QApplication instance...")
        app = QApplication(sys.argv)
        logger.info("Main: QApplication instance created.")

        from gui.main_window import MainWindow # Import here to avoid circular dependencies if any
        win = MainWindow()
        logger.info("Main: MainWindow instance created.")
        
        win.show()
        logger.info("Main: Main window displayed.")
        
        # This is the main event loop for the GUI. Execution blocks here until the GUI closes.
        logger.info("Main: Entering QApplication event loop...")
        sys.exit(app.exec_()) # This is where the application's main loop runs
        logger.info("Main: Exited QApplication event loop.")
        
    except Exception as e:
        logger.critical(f"Application critical error: {str(e)}", exc_info=True)
        # Attempt to show a message box, though it might fail if GUI context is broken
        if app:
            try:
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setText("P2PShare has encountered a critical error and needs to close.")
                msg_box.setInformativeText(f"Error details: {str(e)}")
                msg_box.setWindowTitle("Critical Application Error")
                msg_box.setStandardButtons(QMessageBox.Ok)
                msg_box.exec_()
            except Exception as mb_e:
                logger.error(f"Failed to display QMessageBox: {str(mb_e)}")
        sys.exit(1)
    finally:
        # Cleanup when GUI closes or on error
        if 'server_manager' in locals(): # Check if server_manager was created
            logger.info("Main: Stopping backend server during cleanup.")
            server_manager.stop()
        logger.info("Main: Application shutdown complete.")


if __name__ == "__main__":
    main()