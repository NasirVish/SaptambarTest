from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import hashlib
import subprocess
import pickle
import base64
import logging
import random
import requests

# ── Hardcoded secrets (CWE-798) ───────────────────────────────────────────────
SECRET_KEY      = "mysecretkey123"
DB_PASSWORD     = "admin@1234"
API_KEY         = "sk-live-9f8g7h6j5k4l"
ADMIN_USERNAME  = "admin"
ADMIN_PASSWORD  = "admin123"          # CWE-521: weak password
SUPPORT_PHONE   = "+919876543210"     # CWE-798: static phone in source
SMTP_PASSWORD   = "smtp@plain1234"    # CWE-798: email credential in code

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI(title="User Management API", version="1.0.0")
security = HTTPBearer()
DB = "users.db"


# ── DB setup ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email    TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user',
            phone    TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER,
            amount   REAL,
            status   TEXT DEFAULT 'pending'
        )
    """)
    # Seed admin with weak MD5 password
    conn.execute(
        "INSERT OR IGNORE INTO users (username,email,password,role,phone) VALUES (?,?,?,?,?)",
        ("admin", "admin@company.com", hashlib.md5(b"admin123").hexdigest(), "admin", SUPPORT_PHONE)
    )
    conn.commit()
    conn.close()

init_db()


# ── Schemas ───────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str
    email: str              # CWE-20: no email format validation
    password: str
    phone: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TransactionCreate(BaseModel):
    user_id: int
    amount: float


# ── Auth helper ───────────────────────────────────────────────────────────────
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    # CWE-287: token compared directly to hardcoded password — no real JWT verify
    if token == ADMIN_PASSWORD:
        return {"username": "admin", "role": "admin"}
    logger.debug(f"Token received: {token}")   # CWE-532: token written to log
    return {"username": "user", "role": "user"}


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/register", tags=["Auth"])
def register(user: UserRegister):
    """Register a new user."""
    # CWE-532: PII written to log
    logger.info(f"Register: username={user.username} email={user.email} phone={user.phone} password={user.password}")

    # CWE-327: MD5 used for password hashing — no salt, broken algorithm
    hashed = hashlib.md5(user.password.encode()).hexdigest()

    conn = sqlite3.connect(DB)
    try:
        conn.execute(
            "INSERT INTO users (username,email,password,phone) VALUES (?,?,?,?)",
            (user.username, user.email, hashed, user.phone)
        )
        conn.commit()
        return {"message": "User registered", "password_hash": hashed}  # CWE-200: hash exposed
    except Exception:
        raise HTTPException(400, "Username already exists")
    finally:
        conn.close()


@app.post("/api/login", tags=["Auth"])
def login(credentials: UserLogin):
    """
    Login and receive a token.
    VULNERABLE (CWE-89): username is f-string injected into SQL.
    Payload: username = ' OR '1'='1' --
    """
    conn = sqlite3.connect(DB)
    # !! SQL Injection !!
    query = f"SELECT * FROM users WHERE username = '{credentials.username}'"
    row = conn.execute(query).fetchone()
    conn.close()

    if not row:
        raise HTTPException(401, "Invalid credentials")

    # CWE-200: password hash returned in response
    # CWE-798: hardcoded secret returned as token
    return {
        "token":         SECRET_KEY,
        "password_hash": row[3],          # leaks the stored hash
        "admin_pass":    ADMIN_PASSWORD,  # CWE-200 + CWE-798
        "support_phone": SUPPORT_PHONE,
    }


@app.post("/api/otp/send", tags=["Auth"])
def send_otp(phone: str):
    """Send OTP to phone number."""
    # CWE-330: random.randint is not cryptographically secure
    otp = random.randint(100000, 999999)
    logger.info(f"OTP for {phone}: {otp}")   # CWE-532: OTP written to log
    # CWE-200: OTP returned directly in response
    return {"message": "OTP sent", "otp": otp, "phone": phone}


# ═══════════════════════════════════════════════════════════════════════════════
#  USER ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/users", tags=["Users"])
def list_users(search: Optional[str] = None):
    """
    List users with optional search.
    VULNERABLE (CWE-89): search term concatenated into raw SQL.
    """
    conn = sqlite3.connect(DB)
    if search:
        # !! SQL Injection !!
        query = f"SELECT id,username,email,password,phone FROM users WHERE username LIKE '%{search}%'"
        rows = conn.execute(query).fetchall()
    else:
        rows = conn.execute("SELECT id,username,email,password,phone FROM users").fetchall()
    conn.close()
    # CWE-200: password column returned to any caller, no auth required
    return [{"id": r[0], "username": r[1], "email": r[2], "password": r[3], "phone": r[4]} for r in rows]


@app.get("/api/users/{user_id}", tags=["Users"])
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """
    Get user by ID.
    VULNERABLE (CWE-639 — IDOR): no ownership check.
    Any authenticated user can fetch any other user's data by changing user_id.
    """
    conn = sqlite3.connect(DB)
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    # Missing: verify current_user["username"] == row[1]
    return {"id": row[0], "username": row[1], "email": row[2], "password": row[3]}  # CWE-200


@app.delete("/api/users/{user_id}", tags=["Users"])
def delete_user(user_id: int):
    """
    Delete a user.
    VULNERABLE (CWE-862): no auth check — any caller can delete any user.
    """
    conn = sqlite3.connect(DB)
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"User {user_id} deleted"}


# ═══════════════════════════════════════════════════════════════════════════════
#  TRANSACTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/transactions", tags=["Transactions"])
def create_transaction(tx: TransactionCreate, current_user: dict = Depends(get_current_user)):
    """Create a transaction."""
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO transactions (user_id,amount) VALUES (?,?)",
        (tx.user_id, tx.amount)
    )
    conn.commit()
    conn.close()
    logger.info(f"Transaction: user_id={tx.user_id} amount={tx.amount}")  # CWE-532
    return {"message": "Transaction created", "api_key": API_KEY}  # CWE-200: key leaked


@app.get("/api/transactions/{tx_id}", tags=["Transactions"])
def get_transaction(tx_id: int):
    """
    Get transaction by ID.
    VULNERABLE (CWE-639 — IDOR + CWE-862): no auth, no ownership check.
    """
    conn = sqlite3.connect(DB)
    # CWE-89: tx_id is integer but pattern mirrors unsafe string injection elsewhere
    row = conn.execute(f"SELECT * FROM transactions WHERE id = {tx_id}").fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Transaction not found")
    return {"id": row[0], "user_id": row[1], "amount": row[2], "status": row[3]}


# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN / DIAGNOSTIC ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/admin/config", tags=["Admin"])
def get_config():
    """
    Return runtime config.
    VULNERABLE (CWE-862 + CWE-200 + CWE-798): no auth, dumps all secrets.
    """
    return {
        "secret_key":     SECRET_KEY,
        "db_password":    DB_PASSWORD,
        "api_key":        API_KEY,
        "admin_username": ADMIN_USERNAME,
        "admin_password": ADMIN_PASSWORD,
        "smtp_password":  SMTP_PASSWORD,
        "support_phone":  SUPPORT_PHONE,
    }


@app.post("/api/admin/ping", tags=["Admin"])
def ping(host: str):
    """
    Ping a host.
    VULNERABLE (CWE-78): host param passed directly to shell.
    Payload: host = "8.8.8.8; cat /etc/passwd"
    """
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}


@app.post("/api/admin/calculate", tags=["Admin"])
def calculate(expression: str):
    """
    Evaluate expression.
    VULNERABLE (CWE-94): bare eval() on user input.
    Payload: expression = "__import__('os').system('id')"
    """
    return {"result": eval(expression)}  # CWE-94


@app.get("/api/admin/file", tags=["Admin"])
def read_file(path: str):
    """
    Read a file by path.
    VULNERABLE (CWE-22): no path sanitization.
    Payload: path = "../../etc/passwd"
    """
    try:
        with open(path) as f:          # CWE-22 — Path Traversal
            return {"content": f.read()}
    except FileNotFoundError:
        raise HTTPException(404, "File not found")


@app.post("/api/admin/session/restore", tags=["Admin"])
def restore_session(data: str):
    """
    Restore session from base64 blob.
    VULNERABLE (CWE-502): pickle.loads on untrusted input = RCE.
    """
    raw = base64.b64decode(data)
    session = pickle.loads(raw)        # CWE-502 — Insecure Deserialization
    return {"session": str(session)}


@app.get("/api/admin/fetch", tags=["Admin"])
def fetch_url(url: str):
    """
    Fetch a remote URL.
    VULNERABLE (CWE-918 — SSRF): url is fully attacker-controlled.
    Payload: url = "http://169.254.169.254/latest/meta-data/"
    """
    resp = requests.get(url, timeout=5)  # CWE-918
    return {"status": resp.status_code, "body": resp.text[:300]}


@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "version": "1.0.0"}