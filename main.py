import threading
import uvicorn
from gui.main_window import run as run_gui_app
from shared.cert_manager import ensure_certificates
from shared.config import settings, CONFIG_DIR
from shared.security_manager import SecurityManager
import sys
from PyQt5.QtCore import QTimer, QObject, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMessageBox, QInputDialog, QLineEdit 
import logging
import base64
import os
from shared.logging_config import setup_logger

# Set up logger
logger = setup_logger(__name__)

# Global Security Manager instance
security_manager = SecurityManager(CONFIG_DIR)

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
                    pass 
                break # Exit loop on unhandled server error
                
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
    """Main entry point with improved error handling for GUI loop and security setup"""
    app = None 
    try:
        logger.info("Main: Checking for TLS certificates...")
        ensure_certificates()
        logger.info("Main: TLS certificates check complete.")
        
        logger.info("Main: Starting P2PShare application with device_id: %s", settings.device_id)
        logger.info("Main: Backend will run on port %s", settings.http_port)

        # Create QApplication instance early for dialogs
        logger.info("Main: Creating QApplication instance...")
        app = QApplication(sys.argv)
        logger.info("Main: QApplication instance created.")

        # --- Security Setup ---
        global security_manager 
        encryption_key_successfully_loaded = False # Track if key is successfully loaded/initialized

        if not security_manager.is_initialized():
            logger.info("Security not initialized. Prompting for security code.")
            while True:
                password, ok = QInputDialog.getText(None, "P2PShare Security Setup",
                                                    "Enter a new security code (password) for encryption:",
                                                    QLineEdit.Password)
                if not ok or not password:
                    QMessageBox.warning(None, "Security Warning", "Security code cannot be empty. Please enter a valid code.")
                    if not ok: 
                        logger.critical("Security code input cancelled. Exiting application.")
                        sys.exit(1)
                    continue
                
                confirm_password, ok_confirm = QInputDialog.getText(None, "P2PShare Security Setup",
                                                                    "Confirm your security code:",
                                                                    QLineEdit.Password)
                if not ok_confirm or password != confirm_password:
                    QMessageBox.warning(None, "Security Warning", "Security codes do not match. Please try again.")
                    if not ok_confirm: 
                        logger.critical("Security code confirmation cancelled. Exiting application.")
                        sys.exit(1)
                    continue
                
                if security_manager.initialize_security(password):
                    QMessageBox.information(None, "Security Setup Complete", "Security code set successfully!")
                    encryption_key_successfully_loaded = True # Key is set internally now
                    break
                else:
                    QMessageBox.critical(None, "Security Error", "Failed to initialize security. Check logs for details.")
                    logger.critical("Failed to initialize security. Exiting application.")
                    sys.exit(1)
        else:
            logger.info("Security already initialized. Prompting for security code to load.")
            for i in range(3):
                password, ok = QInputDialog.getText(None, "P2PShare Security Login",
                                                    "Enter your security code (password):",
                                                    QLineEdit.Password)
                if not ok or not password:
                    QMessageBox.warning(None, "Security Warning", "Security code cannot be empty. Please enter your code.")
                    if not ok: 
                        logger.critical("Security code input cancelled. Exiting application.")
                        sys.exit(1)
                    continue

                if security_manager.load_security(password):
                    QMessageBox.information(None, "Security Login Success", "Security code accepted!")
                    encryption_key_successfully_loaded = True # Key is loaded internally now
                    break
                else:
                    QMessageBox.warning(None, "Security Warning", "Incorrect security code. Please try again.")
        
        # --- IMPORTANT: Verify encryption key is indeed loaded after security setup/login ---
        # No 'set_encryption_key' call needed. Just check if it's available.
        if not encryption_key_successfully_loaded: # This flag confirms if load/init was successful
            logger.critical("Main: Encryption key NOT available after security setup/load. Exiting application.")
            QMessageBox.critical(None, "Security Error", "Encryption key could not be loaded. Please ensure correct security code and try again.")
            sys.exit(1)
        else:
            # Retrieve the key which is now confirmed to be loaded internally.
            encryption_key_bytes = security_manager.get_encryption_key() 
            if encryption_key_bytes: # Double check, should always be true if encryption_key_successfully_loaded is true
                # Set environment variable with encryption key for subprocesses (like download_script.py)
                os.environ['P2PSHARE_ENCRYPTION_KEY_B64'] = base64.b64encode(encryption_key_bytes).decode('utf-8')
                logger.info("Main: Encryption key confirmed as loaded and set in environment for backend and subprocesses.")
            else:
                logger.critical("Main: Internal error - encryption_key_successfully_loaded is True but get_encryption_key returned None. Exiting.")
                QMessageBox.critical(None, "Internal Error", "An internal error prevented encryption key access. Please restart.")
                sys.exit(1)

        # --- End Security Setup / Key Passing ---


        # Create and start server manager
        server_manager = ServerManager()
        server_manager.server_error.connect(lambda msg: logger.error(f"Server runtime error: {msg}"))
        server_manager.start()
        
        # Now, create and run the main GUI window.
        # It relies on the global security_manager being correctly loaded.
        from gui.main_window import MainWindow 
        win = MainWindow(security_manager) 
        logger.info("Main: MainWindow instance created.")
        
        win.show()
        logger.info("Main: Main window displayed.")
        
        logger.info("Main: Entering QApplication event loop...")
        sys.exit(app.exec_()) 
        logger.info("Main: Exited QApplication event loop.")
        
    except Exception as e:
        logger.critical(f"Application critical error: {str(e)}", exc_info=True)
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
        if 'server_manager' in locals() and server_manager.should_run: 
            logger.info("Main: Stopping backend server during cleanup.")
            server_manager.stop()
        # Clean up the environment variable after use to avoid lingering sensitive data
        if 'P2PSHARE_ENCRYPTION_KEY_B64' in os.environ:
            del os.environ['P2PSHARE_ENCRYPTION_KEY_B64']
            logger.debug("Main: Cleaned up P2PSHARE_ENCRYPTION_KEY_B64 environment variable.")
        logger.info("Main: Application shutdown complete.")


if __name__ == "__main__":
    main()
