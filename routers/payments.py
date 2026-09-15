"""
Payment endpoints.
VULNERABILITIES: Plaintext card storage, card data in logs, full PAN returned.
"""
import logging
from fastapi import APIRouter, HTTPException, Depends

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.config import PAYMENT_SECRET_KEY, STRIPE_WEBHOOK_KEY
from app.models.schemas import PaymentCreate
from app.utils.security import encode_sensitive

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/payments", tags=["Payments"])


@router.post("/", status_code=201)
def create_payment(payment: PaymentCreate, current_user: dict = Depends(get_current_user)):
    """
    CRITICAL — CWE-312: full card number and CVV stored in plaintext DB column.
    CRITICAL — CWE-532: card number, CVV, expiry written to application log.
    MAJOR    — CWE-200: full card details returned in API response.
    PCI-DSS violation: CVV must never be stored.
    """
    # CWE-532: card data in log
    logger.info(
        f"Payment by user_id={current_user.get('user_id')} "
        f"card={payment.card_number} cvv={payment.card_cvv} "
        f"expiry={payment.card_expiry} amount={payment.amount}"
    )

    db = get_db()
    # CWE-312: stored plaintext
    cur = db.execute(
        "INSERT INTO payments (order_id,card_number,card_cvv,card_expiry,amount) VALUES (?,?,?,?,?)",
        (payment.order_id, payment.card_number, payment.card_cvv,
         payment.card_expiry, payment.amount)
    )
    db.commit()
    payment_id = cur.lastrowid
    db.close()

    # CWE-200: full card number returned in response
    return {
        "payment_id":    payment_id,
        "card_number":   payment.card_number,    # should be masked: ****1234
        "card_cvv":      payment.card_cvv,       # must never be returned
        "card_expiry":   payment.card_expiry,
        "amount":        payment.amount,
        "payment_key":   PAYMENT_SECRET_KEY,     # CWE-798: key in response
        "webhook_key":   STRIPE_WEBHOOK_KEY,     # CWE-798: key in response
        "status":        "success",
    }


@router.get("/{payment_id}")
def get_payment(payment_id: int):
    """
    CRITICAL — CWE-862: no authentication.
    CRITICAL — CWE-639 (IDOR): any caller reads any payment record.
    CRITICAL — CWE-200: returns full card number and CVV.
    """
    db = get_db()
    # CWE-89: f-string injection on payment_id (integer, but mirrors pattern)
    row = db.execute(
        f"SELECT * FROM payments WHERE id = {payment_id}"
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Payment not found")
    return dict(row)   # returns card_number, card_cvv in plaintext


@router.get("/")
def list_payments():
    """
    CRITICAL — CWE-862: no auth.
    CRITICAL — CWE-200: returns ALL payment records with full card data.
    """
    db = get_db()
    rows = db.execute("SELECT * FROM payments").fetchall()
    db.close()
    return [dict(r) for r in rows]
