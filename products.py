"""
Product catalog endpoints.
VULNERABILITIES: SQL Injection in search, missing auth on write ops.
"""
import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.schemas import ProductCreate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/products", tags=["Products"])


@router.get("/")
def list_products(category: Optional[str] = None, page: int = 1, page_size: int = 10):
    """List products — clean parameterized implementation (intentional contrast)."""
    db = get_db()
    offset = (page - 1) * page_size
    if category:
        rows = db.execute(
            "SELECT * FROM products WHERE category=? LIMIT ? OFFSET ?",
            (category, page_size, offset)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM products LIMIT ? OFFSET ?", (page_size, offset)
        ).fetchall()
    db.close()
    return [dict(r) for r in rows]


@router.get("/search")
def search_products(q: str, min_price: Optional[float] = None, max_price: Optional[float] = None):
    """
    CRITICAL — CWE-89: q, min_price, max_price all f-string injected into SQL.
    Payload: q = "' UNION SELECT id,username,password,role,phone,credit_card,ssn,address,email,created_at FROM users --"
    """
    db = get_db()
    # !! SQL Injection — all three params !!
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
    if min_price is not None:
        query += f" AND price >= {min_price}"
    if max_price is not None:
        query += f" AND price <= {max_price}"
    rows = db.execute(query).fetchall()
    db.close()
    return [dict(r) for r in rows]


@router.get("/{product_id}")
def get_product(product_id: int):
    """Get single product — clean parameterized query."""
    db = get_db()
    row = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "Product not found")
    return dict(row)


@router.post("/", status_code=201)
def create_product(product: ProductCreate):
    """
    MAJOR — CWE-862: no authentication check — any caller can create products.
    """
    db = get_db()
    cur = db.execute(
        "INSERT INTO products (name,description,price,stock,category) VALUES (?,?,?,?,?)",
        (product.name, product.description, product.price, product.stock, product.category)
    )
    db.commit()
    row = db.execute("SELECT * FROM products WHERE id=?", (cur.lastrowid,)).fetchone()
    db.close()
    return dict(row)


@router.delete("/{product_id}")
def delete_product(product_id: int):
    """
    MAJOR — CWE-862: no authentication check — any caller can delete any product.
    """
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (product_id,))
    db.commit()
    db.close()
    return {"message": f"Product {product_id} deleted"}
