# p2pshare/shared/auth.py

import jwt
from fastapi import HTTPException
from shared.config import settings

ALGORITHM = "HS256"


def create_jwt(device_id: str) -> str:
    payload = {"device_id": device_id}
    token = jwt.encode(payload, settings.device_id + settings.device_id[::-1], algorithm=ALGORITHM)
    return token


def verify_jwt(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.device_id + settings.device_id[::-1], algorithms=[ALGORITHM])
        return payload["device_id"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=403, detail="Invalid token")
