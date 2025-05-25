# p2pshare/shared/token_store.py

import json
from pathlib import Path
from typing import Optional
from shared.logging_config import setup_logger

# Set up logger
logger = setup_logger(__name__)

TOKEN_FILE = Path.home() / ".p2pshare" / "tokens.json"

# Ensure token file exists
if not TOKEN_FILE.exists():
    logger.info(f"Creating new token file at {TOKEN_FILE}")
    TOKEN_FILE.write_text("{}")

def load_tokens() -> dict:
    try:
        tokens = json.loads(TOKEN_FILE.read_text())
        logger.debug(f"Loaded {len(tokens)} tokens from storage")
        return tokens
    except Exception as e:
        logger.error(f"Failed to load tokens: {str(e)}", exc_info=True)
        return {}

def save_tokens(tokens: dict):
    try:
        TOKEN_FILE.write_text(json.dumps(tokens, indent=2))
        logger.debug(f"Saved {len(tokens)} tokens to storage")
    except Exception as e:
        logger.error(f"Failed to save tokens: {str(e)}", exc_info=True)

def get_token_for_peer(device_id: str) -> Optional[str]:
    tokens = load_tokens()
    token = tokens.get(device_id)
    if token:
        logger.debug(f"Retrieved token for peer {device_id}")
    else:
        logger.debug(f"No token found for peer {device_id}")
    return token

def store_token_for_peer(device_id: str, token: str):
    tokens = load_tokens()
    tokens[device_id] = token
    save_tokens(tokens)
    logger.info(f"Stored new token for peer {device_id}")

def delete_token_for_peer(device_id: str):
    tokens = load_tokens()
    if device_id in tokens:
        del tokens[device_id]
        save_tokens(tokens)
        logger.info(f"Deleted token for peer {device_id}")
    else:
        logger.debug(f"No token to delete for peer {device_id}")
