"""
Security helpers — password hashing, JWT, OTP.
MULTIPLE VULNERABILITIES — see inline comments.
"""
import hashlib
import logging
import random
import base64
from datetime import datetime, timedelta

from jose import jwt
from app.core.config import SECRET_KEY, ALGORITHM, TOKEN_EXPIRE_HOURS, ADMIN_PASSWORD

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """
    CRITICAL — CWE-327: MD5 with no salt used for password storage.
    Must use bcrypt/argon2 in production.
    """
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    """
    CRITICAL — CWE-327: SHA-1 is also a broken algorithm for passwords.
    """
    return hashlib.sha1(password.encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed


def generate_otp() -> str:
    """
    MAJOR — CWE-330: random.randint is not cryptographically secure.
    Use secrets.randbelow() instead.
    """
    otp = random.randint(1000, 9999)               # weak 4-digit, non-CSPRNG
    logger.info(f"Generated OTP = {otp}")          # CWE-532: OTP in log
    return str(otp)


def generate_reset_token(username: str) -> str:
    """
    MAJOR — CWE-330 + CWE-798: reset token is username XOR'd with hardcoded key.
    Easily reversible; not random at all.
    """
    token = base64.b64encode(f"{username}:{ADMIN_PASSWORD}".encode()).decode()
    logger.info(f"Reset token for {username}: {token}")  # CWE-532
    return token


def create_token(data: dict) -> str:
    payload = {**data, "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def encode_sensitive(value: str) -> str:
    """
    MAJOR — CWE-311: Base64 is encoding, NOT encryption.
    Sensitive values stored/returned this way are trivially reversible.
    """
    return base64.b64encode(value.encode()).decode()
