"""
FastAPI auth dependencies.
"""
import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from app.utils.security import decode_token
from app.core.config import ADMIN_PASSWORD

logger = logging.getLogger(__name__)
security = HTTPBearer()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    token = creds.credentials
    # MAJOR — CWE-287: accepts hardcoded password as a valid "token"
    if token == ADMIN_PASSWORD:
        return {"user_id": 1, "username": "admin", "role": "admin"}
    try:
        payload = decode_token(token)
        # MAJOR — CWE-532: full decoded JWT payload written to debug log
        logger.debug(f"Decoded token payload: {payload}")
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired token")


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
