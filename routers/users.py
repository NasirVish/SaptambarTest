"""
User management endpoints.
VULNERABILITIES: SQL Injection, IDOR, missing auth, password exposure.
"""
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_admin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/")
def list_users(search: Optional[str] = None):
    """
    CRITICAL — CWE-89: search param f-string injected into SQL.
    CRITICAL — CWE-862: no authentication required.
    CRITICAL — CWE-200: returns password, credit_card, ssn columns.
    Payload: search = ' UNION SELECT * FROM users --
    """
    db = get_db()
    if search:
        # !! SQL Injection !!
        query = (
            f"SELECT id,username,email,password,role,phone,credit_card,ssn "
            f"FROM users WHERE username LIKE '%{search}%' "
            f"OR email LIKE '%{search}%'"
        )
        rows = db.execute(query).fetchall()
    else:
        rows = db.execute(
            "SELECT id,username,email,password,role,phone,credit_card,ssn FROM users"
        ).fetchall()
    db.close()
    # CWE-200: returns password hashes, credit cards, SSNs to unauthenticated callers
    return [dict(r) for r in rows]


@router.get("/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """
    CRITICAL — CWE-639 (IDOR): any authenticated user can fetch any other
    user's full record including password, CC, and SSN by supplying a different user_id.
    MAJOR   — CWE-200: returns password hash, credit card, SSN.
    """
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "User not found")
    # Missing ownership check: should verify user_id == current_user["user_id"]
    return dict(row)   # CWE-200: full row including password/CC/SSN returned


@router.put("/{user_id}")
def update_user(
    user_id: int,
    username: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,      # MAJOR — CWE-269: role is user-supplied, allows privilege escalation
    phone: Optional[str] = None,
):
    """
    CRITICAL — CWE-862: no authentication guard.
    MAJOR    — CWE-269: caller can set role='admin' on any account (privilege escalation).
    MAJOR    — CWE-639: no ownership check — can update any user's account.
    """
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "User not found")

    new_username = username or row["username"]
    new_email    = email    or row["email"]
    new_role     = role     or row["role"]   # CWE-269: attacker sets role=admin
    new_phone    = phone    or row["phone"]

    db.execute(
        "UPDATE users SET username=?,email=?,role=?,phone=? WHERE id=?",
        (new_username, new_email, new_role, new_phone, user_id)
    )
    db.commit()
    db.close()
    return {"message": "User updated", "role_set_to": new_role}


@router.delete("/{user_id}")
def delete_user(user_id: int):
    """
    CRITICAL — CWE-862: no authentication or authorisation check.
    Any unauthenticated caller can delete any user account.
    """
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return {"message": f"User {user_id} permanently deleted"}
