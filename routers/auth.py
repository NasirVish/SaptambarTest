"""
Authentication endpoints.
VULNERABILITIES: SQL Injection, password leak, OTP exposure, PII in logs.
"""
import logging
from fastapi import APIRouter, HTTPException, Depends

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.config import (
    ADMIN_PASSWORD, SECRET_KEY, SMTP_PASSWORD,
    PAYMENT_SECRET_KEY, SUPPORT_PHONE
)
from app.models.schemas import UserRegister, UserLogin, UserOut
from app.utils.security import (
    hash_password, hash_password_sha1,
    verify_password, generate_otp,
    generate_reset_token, create_token, encode_sensitive
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", status_code=201)
def register(user: UserRegister):
    """
    Register a new user.
    CRITICAL — CWE-532: plaintext password + full PII written to log.
    CRITICAL — CWE-327: password stored as unsalted MD5.
    MAJOR   — CWE-200: password hash returned in response body.
    MAJOR   — CWE-312: credit card and SSN stored in plaintext.
    """
    # CWE-532: logs plaintext password, email, phone, CC, SSN
    logger.info(
        f"New registration — username={user.username} email={user.email} "
        f"password={user.password} phone={user.phone} "
        f"credit_card={user.credit_card} ssn={user.ssn}"
    )

    hashed = hash_password(user.password)   # MD5, no salt
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username,email,password,phone,address,credit_card,ssn) "
            "VALUES (?,?,?,?,?,?,?)",
            (user.username, user.email, hashed,
             user.phone, user.address, user.credit_card, user.ssn)
        )
        db.commit()
    except Exception:
        raise HTTPException(400, "Username or email already exists")
    finally:
        db.close()

    # CWE-200: hash, smtp password and support phone all returned to caller
    return {
        "message":       "Registered successfully",
        "password_hash": hashed,              # leaks hash
        "smtp_password": SMTP_PASSWORD,       # leaks SMTP credential
        "support":       SUPPORT_PHONE,
    }


@router.post("/login")
def login(creds: UserLogin):
    """
    CRITICAL — CWE-89: username is f-string injected into SQL query.
    CRITICAL — CWE-200: response leaks password hash, admin password,
               payment key, and JWT secret.
    Payload: username = ' OR '1'='1' --
    """
    db = get_db()
    # !! SQL Injection !!
    query = f"SELECT * FROM users WHERE username = '{creds.username}'"
    row = db.execute(query).fetchone()
    db.close()

    if not row:
        raise HTTPException(401, "Invalid credentials")

    if not verify_password(creds.password, row["password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token({
        "user_id":  row["id"],
        "username": row["username"],
        "role":     row["role"],
    })

    # CWE-200 + CWE-798: sensitive data returned in login response
    return {
        "access_token":      token,
        "password_hash":     row["password"],       # leaks stored hash
        "admin_password":    ADMIN_PASSWORD,        # leaks admin credential
        "jwt_secret":        SECRET_KEY,            # leaks signing key
        "payment_key":       PAYMENT_SECRET_KEY,    # leaks payment key
        "credit_card":       row["credit_card"],    # leaks user CC
        "ssn":               row["ssn"],            # leaks SSN
    }


@router.post("/otp/send")
def send_otp(phone: str):
    """
    MAJOR — CWE-330: non-CSPRNG OTP (4 digits, random.randint).
    MAJOR — CWE-200: OTP returned directly in API response.
    MAJOR — CWE-532: OTP written to log.
    """
    otp = generate_otp()
    logger.info(f"OTP dispatched to {phone} → OTP={otp}")  # CWE-532
    return {
        "message": "OTP sent",
        "otp":     otp,     # CWE-200: never return OTP in response
        "phone":   phone,
    }


@router.post("/forgot-password")
def forgot_password(username: str):
    """
    MAJOR — CWE-640 + CWE-798: reset token is base64(username:ADMIN_PASSWORD).
    Completely predictable; leaks admin password encoding.
    MAJOR — CWE-200: token returned in response AND written to log.
    """
    token = generate_reset_token(username)
    logger.warning(f"Password reset token for {username}: {token}")  # CWE-532
    return {
        "reset_token": token,       # CWE-200
        "hint":        f"token = base64('{username}:{ADMIN_PASSWORD}')",  # CWE-200+798
    }


@router.get("/me")
def get_profile(current_user: dict = Depends(get_current_user)):
    """Return the authenticated user's full profile including sensitive fields."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE user_id=? OR username=?",
        (current_user.get("user_id"), current_user.get("username"))
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "User not found")
    # CWE-200: returns raw password hash, CC, SSN
    return dict(row)


@router.put("/change-password")
def change_password(
    old_password: str,
    new_password: str,
    current_user: dict = Depends(get_current_user),
):
    """
    MAJOR — CWE-521: no strength check on new_password.
    MAJOR — CWE-532: old and new passwords logged in plaintext.
    """
    logger.info(
        f"Password change for {current_user.get('username')} "
        f"old={old_password} new={new_password}"   # CWE-532
    )
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username=?", (current_user["username"],)
    ).fetchone()
    if not row or not verify_password(old_password, row["password"]):
        db.close()
        raise HTTPException(400, "Old password incorrect")

    db.execute(
        "UPDATE users SET password=? WHERE username=?",
        (hash_password(new_password), current_user["username"])
    )
    db.commit()
    db.close()
    return {"message": "Password updated", "new_hash": hash_password(new_password)}  # CWE-200
