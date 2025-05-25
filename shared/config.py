# p2pshare/shared/config.py

import os
import uuid
import socket
from pathlib import Path
from dataclasses import dataclass

@dataclass
class Settings:
    device_id: str
    share_dir: Path
    http_port: int
    tls_cert: Path
    tls_key: Path
    ca_cert: Path

def get_machine_id():
    """Generate a stable machine ID using hostname and MAC address"""
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
        # Fallback to a random UUID if we can't get machine info
        return str(uuid.uuid4())

# Setup defaults and resolve paths
HOME = Path.home()
CONFIG_DIR = HOME / ".p2pshare"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Get or create device ID
DEVICE_ID_FILE = CONFIG_DIR / "device_id"
if not DEVICE_ID_FILE.exists():
    device_id = os.environ.get("DEVICE_ID") or get_machine_id()
    DEVICE_ID_FILE.write_text(device_id)
else:
    device_id = DEVICE_ID_FILE.read_text().strip()

settings = Settings(
    device_id=device_id,
    share_dir=HOME / "P2PShare",
    http_port=int(os.environ.get("HTTP_PORT", "5000")),
    tls_cert=CONFIG_DIR / "device_cert.pem",
    tls_key=CONFIG_DIR / "device_key.pem",
    ca_cert=CONFIG_DIR / "ca.pem"
)

# Create shared dir if not exists
settings.share_dir.mkdir(exist_ok=True)
