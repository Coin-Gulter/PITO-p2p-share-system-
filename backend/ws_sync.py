# p2pshare/backend/ws_sync.py

from fastapi import WebSocket, WebSocketDisconnect, APIRouter, Depends
from shared.auth import verify_jwt
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Dict
import json
from shared.logging_config import setup_logger

# Set up logger
logger = setup_logger(__name__)

router = APIRouter()
security = HTTPBearer()

# Keep track of connected peers
connected_peers: Dict[str, WebSocket] = {}


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    device_id = None

    try:
        # First message must contain a valid JWT
        auth_data = await websocket.receive_text()
        msg = json.loads(auth_data)
        if "token" not in msg:
            logger.warning("WebSocket connection attempt without token")
            await websocket.close(code=4001)
            return

        device_id = verify_jwt(msg["token"])
        connected_peers[device_id] = websocket
        logger.info(f"Peer connected: {device_id}")

        while True:
            message = await websocket.receive_text()
            data = json.loads(message)
            logger.debug(f"Received message from {device_id}: {data}")
            # Here you can handle file change events, sync requests, etc.

    except WebSocketDisconnect:
        logger.info(f"Peer disconnected: {device_id}")
    except Exception as e:
        logger.error(f"WebSocket error for {device_id}: {str(e)}", exc_info=True)
    finally:
        if device_id in connected_peers:
            logger.debug(f"Removing peer from connected peers: {device_id}")
            del connected_peers[device_id]
