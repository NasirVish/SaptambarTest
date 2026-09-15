# Vulnerable Demo API

Intentionally vulnerable FastAPI project for testing SAST and
security scanning agents (Vidura, Snyk, Bandit, etc.).

> ⚠️ DO NOT DEPLOY. Contains 40+ real security vulnerabilities.

## Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python run.py
# API → http://localhost:8000
# Docs → http://localhost:8000/docs
```

## Seeded accounts

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | alice123  | user  |

## Endpoint Map

| Method | Path | Auth | Key Vulnerabilities |
|--------|------|------|---------------------|
| POST | `/api/v1/auth/register` | None | MD5 hash, PII in log, hash in response |
| POST | `/api/v1/auth/login` | None | SQL Injection, password/secrets in response |
| POST | `/api/v1/auth/otp/send` | None | Weak RNG, OTP in response + log |
| POST | `/api/v1/auth/forgot-password` | None | Predictable token, admin pass in response |
| GET  | `/api/v1/auth/me` | Bearer | Returns raw password hash + CC + SSN |
| PUT  | `/api/v1/auth/change-password` | Bearer | Passwords logged, no strength check |
| GET  | `/api/v1/users/` | None | SQL Injection, no auth, returns CC/SSN |
| GET  | `/api/v1/users/{id}` | Bearer | IDOR, returns password/CC/SSN |
| PUT  | `/api/v1/users/{id}` | None | No auth, privilege escalation via role= |
| DELETE | `/api/v1/users/{id}` | None | No auth, deletes any user |
| GET  | `/api/v1/products/search` | None | SQL Injection (q, min/max_price) |
| POST | `/api/v1/products/` | None | No auth |
| POST | `/api/v1/orders/` | Bearer | Financial data in log |
| GET  | `/api/v1/orders/` | None | No auth, all users' orders |
| GET  | `/api/v1/orders/{id}` | Bearer | IDOR + SQL Injection |
| DELETE | `/api/v1/orders/{id}` | None | No auth |
| POST | `/api/v1/payments/` | Bearer | Card + CVV stored plaintext, in log + response |
| GET  | `/api/v1/payments/{id}` | None | No auth, IDOR, returns full card |
| GET  | `/api/v1/payments/` | None | No auth, all card data |
| POST | `/api/v1/messages/` | Bearer | Stored XSS |
| GET  | `/api/v1/messages/` | Bearer | SQL Injection, returns all messages |
| GET  | `/api/v1/messages/{id}` | Bearer | IDOR |
| GET  | `/api/v1/admin/secrets` | ⚠️ None | Dumps ALL secrets |
| GET  | `/api/v1/admin/users` | ⚠️ None | All users + CC/SSN |
| POST | `/api/v1/admin/ping` | ⚠️ None | OS Command Injection |
| POST | `/api/v1/admin/run` | ⚠️ None | Direct shell exec (popen) |
| POST | `/api/v1/admin/evaluate` | ⚠️ None | eval() — full RCE |
| GET  | `/api/v1/admin/file/read` | ⚠️ None | Path Traversal |
| GET  | `/api/v1/admin/file/download` | ⚠️ None | Path Traversal |
| POST | `/api/v1/admin/session/restore` | ⚠️ None | pickle RCE |
| GET  | `/api/v1/admin/fetch` | ⚠️ None | SSRF |
| DELETE | `/api/v1/admin/users/{id}` | ⚠️ None | No auth, hard delete |
| GET  | `/health` | None | Health check |

See `VULNERABILITIES.md` for the full annotated list.
