import logging
import sys
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler

# Create logs directory in user's home
LOG_DIR = os.path.join(os.getcwd(),"logs/")
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

def setup_logger(name: str, log_file: str = None) -> logging.Logger:
    """
    Set up a logger with both file and console handlers
    
    Args:
        name: Name of the logger (usually __name__)
        log_file: Optional specific log file name, defaults to module name
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Create formatters
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    
    # Console handler (DEBUG and above - show all logs)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)  # Changed from INFO to DEBUG
    console_handler.setFormatter(formatter)
    
    # File handler (DEBUG and above)
    if log_file is None:
        # Use module name as log file name
        log_file = f"{name.split('.')[-1]}.log"
    
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, log_file),
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger 