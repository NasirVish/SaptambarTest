"""
Order endpoints.
VULNERABILITIES: IDOR, SQL injection, sensitive data in logs.
"""
import logging
from fastapi import APIRouter, HTTPException, Depends

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.schemas import OrderCreate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/orders", tags=["Orders"])


@router.post("/", status_code=201)
def place_order(order: OrderCreate, current_user: dict = Depends(get_current_user)):
    """Place a new order."""
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=?", (order.product_id,)).fetchone()
    if not product:
        db.close()
        raise HTTPException(404, "Product not found")
    if product["stock"] < order.quantity:
        db.close()
        raise HTTPException(400, "Insufficient stock")

    total = round(product["price"] * order.quantity, 2)
    cur = db.execute(
        "INSERT INTO orders (user_id,product_id,quantity,total) VALUES (?,?,?,?)",
        (current_user["user_id"], order.product_id, order.quantity, total)
    )
    db.execute(
        "UPDATE products SET stock=stock-? WHERE id=?", (order.quantity, order.product_id)
    )
    db.commit()
    order_id = cur.lastrowid
    db.close()

    # CWE-532: financial data + user_id written to log
    logger.info(f"Order placed user_id={current_user['user_id']} total={total} order_id={order_id}")
    return {"order_id": order_id, "total": total, "status": "pending"}


@router.get("/")
def list_orders():
    """
    CRITICAL — CWE-862: no authentication.
    Returns ALL orders for ALL users — unauthenticated.
    """
    db = get_db()
    rows = db.execute("SELECT * FROM orders").fetchall()
    db.close()
    return [dict(r) for r in rows]


@router.get("/{order_id}")
def get_order(order_id: int, current_user: dict = Depends(get_current_user)):
    """
    CRITICAL — CWE-639 (IDOR): ownership never checked.
    Any authenticated user can read any other user's order.
    MAJOR    — CWE-89: f-string SQL on order_id.
    """
    db = get_db()
    row = db.execute(
        f"SELECT * FROM orders WHERE id = {order_id}"  # CWE-89
    ).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Order not found")
    # Missing: verify row["user_id"] == current_user["user_id"]
    return dict(row)


@router.delete("/{order_id}")
def cancel_order(order_id: int):
    """
    CRITICAL — CWE-862: no auth check.
    Any caller can cancel any order.
    """
    db = get_db()
    db.execute("UPDATE orders SET status='cancelled' WHERE id=?", (order_id,))
    db.commit()
    db.close()
    return {"message": f"Order {order_id} cancelled"}
