"""
Admin / diagnostic endpoints.
CRITICAL — CWE-862: entire router has no authentication guard.
Contains: command injection, eval, path traversal, SSRF, pickle RCE, secret dump.
"""
import base64
import logging
import os
import pickle
import subprocess
from pathlib import Path

import requests
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.core.config import (
    SECRET_KEY, DB_ROOT_PASSWORD, ADMIN_PASSWORD,
    PAYMENT_SECRET_KEY, STRIPE_WEBHOOK_KEY,
    AWS_ACCESS_KEY, AWS_SECRET_KEY,
    SMTP_PASSWORD, TWILIO_AUTH_TOKEN,
    INTERNAL_API_KEY, SUPPORT_PHONE,
)
from app.core.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["Admin"])

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


@router.get("/secrets")
def dump_all_secrets():
    """
    CRITICAL — CWE-200 + CWE-798 + CWE-862:
    No auth guard. Returns every hardcoded credential in the application.
    """
    return {
        "jwt_secret":        SECRET_KEY,
        "db_root_password":  DB_ROOT_PASSWORD,
        "admin_password":    ADMIN_PASSWORD,
        "payment_key":       PAYMENT_SECRET_KEY,
        "stripe_webhook":    STRIPE_WEBHOOK_KEY,
        "aws_access_key":    AWS_ACCESS_KEY,
        "aws_secret_key":    AWS_SECRET_KEY,
        "smtp_password":     SMTP_PASSWORD,
        "twilio_token":      TWILIO_AUTH_TOKEN,
        "internal_api_key":  INTERNAL_API_KEY,
        "support_phone":     SUPPORT_PHONE,
    }


@router.get("/users")
def all_users_with_sensitive_data():
    """
    CRITICAL — CWE-862 + CWE-200:
    No auth. Returns password hashes, credit cards, SSNs for all users.
    """
    db = get_db()
    rows = db.execute("SELECT * FROM users").fetchall()
    db.close()
    return [dict(r) for r in rows]


@router.post("/ping")
def ping_host(host: str):
    """
    CRITICAL — CWE-78 (OS Command Injection):
    host interpolated into shell command with shell=True.
    Payload: host = "127.0.0.1; cat /etc/passwd"
    """
    result = subprocess.run(
        f"ping -c 2 {host}",   # CWE-78
        shell=True, capture_output=True, text=True
    )
    return {"stdout": result.stdout, "stderr": result.stderr}


@router.post("/run")
def run_command(cmd: str):
    """
    CRITICAL — CWE-78: executes arbitrary shell command directly.
    Payload: cmd = "id && whoami && cat /etc/shadow"
    """
    out = os.popen(cmd).read()   # CWE-78 — direct popen with full command
    return {"output": out}


@router.post("/evaluate")
def evaluate_expression(expression: str):
    """
    CRITICAL — CWE-94 (Code Injection):
    eval() on user-supplied Python expression — full RCE.
    Payload: expression = "__import__('os').system('id')"
    """
    result = eval(expression)    # CWE-94
    return {"result": result}


@router.get("/file/read")
def read_file(path: str):
    """
    CRITICAL — CWE-22 (Path Traversal):
    path param unsanitized — can read any file on disk.
    Payload: path = "../../etc/passwd"  or  "../../app/core/config.py"
    """
    try:
        with open(path) as f:    # CWE-22
            content = f.read()
        return {"path": path, "content": content}
    except FileNotFoundError:
        raise HTTPException(404, "File not found")


@router.get("/file/download")
def download_file(filename: str):
    """
    CRITICAL — CWE-22 (Path Traversal):
    filename joined onto upload dir without sanitizing '../' sequences.
    """
    file_path = UPLOAD_DIR / filename   # CWE-22
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(file_path)


@router.post("/session/restore")
def restore_session(data: str):
    """
    CRITICAL — CWE-502 (Insecure Deserialization):
    pickle.loads on untrusted base64 input — arbitrary code execution.
    Payload: craft a malicious pickle payload for RCE.
    """
    raw = base64.b64decode(data)
    session = pickle.loads(raw)   # CWE-502
    return {"session": str(session)}


@router.get("/fetch")
def server_side_fetch(url: str):
    """
    CRITICAL — CWE-918 (SSRF):
    Server fetches fully attacker-controlled URL.
    Payload: url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    """
    resp = requests.get(url, timeout=5)   # CWE-918
    return {"status": resp.status_code, "body": resp.text[:500]}


@router.delete("/users/{user_id}")
def hard_delete_user(user_id: int):
    """
    CRITICAL — CWE-862: no auth. Any caller permanently deletes any user.
    """
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.execute("DELETE FROM orders WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM payments WHERE order_id IN (SELECT id FROM orders WHERE user_id=?)", (user_id,))
    db.commit()
    db.close()
    return {"message": f"User {user_id} and all associated data permanently deleted"}
    #Newchange
#Print("heloo")
DB_PASSWORD = "aAAA33434"
