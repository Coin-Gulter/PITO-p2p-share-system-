# p2pshare/shared/config.py

import os
import uuid
import socket
import random
from pathlib import Path
from dataclasses import dataclass
import logging # Import logging

# Set up a logger for this module
logger = logging.getLogger(__name__)

@dataclass
class Settings:
    device_id: str
    share_dir: Path
    http_port: int
    tls_cert: Path
    tls_key: Path
    ca_cert: Path

def get_machine_id():
    """
    Generate a stable machine ID using hostname and MAC address.
    This is used as a fallback if a more readable ID isn't generated or specified.
    """
    try:
        # Get hostname
        hostname = socket.gethostname()
        
        # Get MAC address
        mac = uuid.getnode()
        mac_str = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        
        # Combine hostname and MAC for a unique but stable ID
        machine_id = f"{hostname}-{mac_str}"
        return machine_id
    except Exception as e:
        logger.warning(f"Could not generate stable machine ID from hostname/MAC: {e}. Falling back to random UUID.")
        # Fallback to a random UUID if we can't get machine info
        return str(uuid.uuid4())

def generate_human_readable_device_id():
    """
    Generates a human-readable, yet unique, device ID.
    Combines an adjective, a noun, and a short random alphanumeric suffix.
    """
    adjectives = [
        "Silent", "Swift", "Bright", "Hidden", "Secure", "Private", "Roaming",
        "Gentle", "Brave", "Clever", "Vivid", "Calm", "Mystic", "Daring", "Zen"
    ]
    nouns = [
        "Node", "Share", "Beacon", "Vault", "Harbor", "Link", "Guard",
        "Echo", "Nexus", "Portal", "Shield", "Whisper", "Key", "Relay", "Haven"
    ]
    
    # Select random adjective and noun
    adj = random.choice(adjectives)
    noun = random.choice(nouns)
    
    # Add a short random alphanumeric suffix for uniqueness
    suffix = ''.join(random.choices('0123456789abcdefghijklmnopqrstuvwxyz', k=4))
    
    device_id = f"{adj}{noun}-{suffix}"
    logger.info(f"Generated new human-readable device ID: {device_id}")
    return device_id

def find_available_port(start_port: int = 5000, end_port: int = 6000) -> int:
    """
    Finds an available TCP port within a specified range.
    Tries to bind a socket to the port to check availability.
    """
    logger.info(f"Attempting to find an available port between {start_port} and {end_port}...")
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Set a timeout for the bind operation (optional but good practice)
                s.settimeout(0.1) 
                s.bind(("0.0.0.0", port))
                logger.info(f"Port {port} is available.")
                return port
        except (OSError, socket.error) as e:
            logger.debug(f"Port {port} is in use or unavailable: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while checking port {port}: {e}")
    
    logger.critical(f"No available port found in range {start_port}-{end_port}. Using default {start_port} (might fail).")
    # Fallback to the start_port if no free port is found, though it might lead to a crash.
    return start_port 

# Setup defaults and resolve paths
HOME = Path.cwd()
CONFIG_DIR = HOME / ".p2pshare"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Configuration directory: {CONFIG_DIR}")

# Get or create device ID
DEVICE_ID_FILE = CONFIG_DIR / "device_id"
device_id = None
if DEVICE_ID_FILE.exists():
    device_id = DEVICE_ID_FILE.read_text().strip()
    logger.info(f"Found existing device ID: {device_id}")
else:
    # Generate device id environment variable
    device_id = generate_human_readable_device_id()
    
    # Write the chosen device ID to file for persistence
    DEVICE_ID_FILE.write_text(device_id)
    logger.info(f"Device ID saved to: {DEVICE_ID_FILE}")

# Determine the HTTP port
chosen_http_port = int(os.environ.get("HTTP_PORT", "0")) # Use 0 to indicate dynamic search if not set
if chosen_http_port == 0: # If environment variable not set or set to 0
    chosen_http_port = find_available_port(start_port=5000, end_port=6000)
else:
    logger.info(f"Using HTTP port from environment variable: {chosen_http_port}")


settings = Settings(
    device_id=device_id,
    share_dir=HOME / "P2PShare",
    http_port=chosen_http_port,
    tls_cert=CONFIG_DIR / "device_cert.pem",
    tls_key=CONFIG_DIR / "device_key.pem",
    ca_cert=CONFIG_DIR / "ca.pem"
)

# Create shared dir if not exists
settings.share_dir.mkdir(exist_ok=True)
logger.info(f"Share directory: {settings.share_dir} (created if not exists)")
