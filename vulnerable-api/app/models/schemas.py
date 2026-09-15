"""Pydantic schemas for request / response bodies."""
from typing import Optional
from pydantic import BaseModel


class UserRegister(BaseModel):
    username: str
    email: str          # CWE-20: plain str, no EmailStr / format validation
    password: str       # CWE-521: no strength enforcement
    phone: Optional[str] = None
    address: Optional[str] = None
    credit_card: Optional[str] = None   # stored in plaintext — CWE-312
    ssn: Optional[str] = None           # PII stored in plaintext — CWE-312


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    phone: Optional[str] = None
    credit_card: Optional[str] = None  # CWE-200: CC returned in response
    ssn: Optional[str] = None          # CWE-200: SSN returned in response


class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    stock: int = 0
    category: Optional[str] = None


class OrderCreate(BaseModel):
    product_id: int
    quantity: int = 1


class PaymentCreate(BaseModel):
    order_id: int
    card_number: str    # CWE-312: full card number accepted + stored plaintext
    card_cvv: str       # CWE-312: CVV accepted + stored — PCI-DSS violation
    card_expiry: str
    amount: float


class MessageCreate(BaseModel):
    receiver_id: int
    content: str        # CWE-79: stored raw, returned unescaped (stored XSS)
