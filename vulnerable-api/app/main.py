"""
Vulnerable Demo API — main application entry point.
DO NOT DEPLOY PUBLICLY.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import init_db
from app.routers import auth, users, products, orders, payments, messages, admin

app = FastAPI(
    title="Vulnerable Demo API",
    description="Intentionally vulnerable API for SAST and security agent testing.",
    version="1.0.0",
)

# MAJOR — CWE-942: wildcard CORS + credentials=True
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # CWE-942
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,     prefix="/api/v1")
app.include_router(users.router,    prefix="/api/v1")
app.include_router(products.router, prefix="/api/v1")
app.include_router(orders.router,   prefix="/api/v1")
app.include_router(payments.router, prefix="/api/v1")
app.include_router(messages.router, prefix="/api/v1")
app.include_router(admin.router,    prefix="/api/v1")


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health", tags=["System"])
def health():
    """Liveness probe."""
    return {"status": "ok", "version": "1.0.0"}
