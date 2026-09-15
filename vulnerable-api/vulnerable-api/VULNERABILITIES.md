# Vulnerability Answer Key

40 planted issues across 9 files. Use this to score your agent's precision/recall.

## CRITICAL (17)

| # | File | CWE | Description |
|---|------|-----|-------------|
| 1 | `app/routers/auth.py` — `login` | CWE-89 | SQL Injection — username f-string in query |
| 2 | `app/routers/users.py` — `list_users` | CWE-89 | SQL Injection — search f-string in query |
| 3 | `app/routers/products.py` — `search_products` | CWE-89 | SQL Injection — q, min_price, max_price all injectable |
| 4 | `app/routers/orders.py` — `get_order` | CWE-89 | SQL Injection — f-string on order_id |
| 5 | `app/routers/payments.py` — `get_payment` | CWE-89 | SQL Injection — f-string on payment_id |
| 6 | `app/routers/messages.py` — `list_messages` | CWE-89 | SQL Injection — search injected into raw query |
| 7 | `app/routers/admin.py` — `ping_host` | CWE-78 | OS Command Injection — host into shell=True |
| 8 | `app/routers/admin.py` — `run_command` | CWE-78 | Direct os.popen() on user input |
| 9 | `app/routers/admin.py` — `evaluate_expression` | CWE-94 | Code injection via bare eval() |
| 10 | `app/routers/admin.py` — `restore_session` | CWE-502 | Insecure deserialization — pickle.loads on untrusted input |
| 11 | `app/routers/admin.py` — `read_file` | CWE-22 | Path traversal — open(path) unsanitized |
| 12 | `app/routers/admin.py` — `download_file` | CWE-22 | Path traversal — UPLOAD_DIR / filename |
| 13 | `app/routers/admin.py` — `server_side_fetch` | CWE-918 | SSRF — fully attacker-controlled URL |
| 14 | `app/routers/admin.py` — `dump_all_secrets` | CWE-862+200 | No auth, returns every credential |
| 15 | `app/routers/users.py` — `delete_user` | CWE-862 | No auth — any caller deletes any user |
| 16 | `app/routers/payments.py` — `list_payments` | CWE-862+200 | No auth, returns all card data |
| 17 | `app/routers/auth.py` — `login` response | CWE-200 | Returns password hash, admin pass, JWT secret, payment key, CC, SSN |

## MAJOR (16)

| # | File | CWE | Description |
|---|------|-----|-------------|
| 18 | `app/utils/security.py` — `hash_password` | CWE-327 | MD5 with no salt for password storage |
| 19 | `app/utils/security.py` — `hash_password_sha1` | CWE-327 | SHA-1 also broken for passwords |
| 20 | `app/utils/security.py` — `generate_otp` | CWE-330 | random.randint — not CSPRNG |
| 21 | `app/utils/security.py` — `generate_reset_token` | CWE-330+798 | Predictable token = base64(username:ADMIN_PASSWORD) |
| 22 | `app/routers/auth.py` — `register` log | CWE-532 | Plaintext password + CC + SSN written to log |
| 23 | `app/routers/auth.py` — `change_password` log | CWE-532 | Old and new passwords logged in plaintext |
| 24 | `app/routers/payments.py` — `create_payment` log | CWE-532 | Full card number + CVV written to log |
| 25 | `app/routers/payments.py` — `create_payment` DB | CWE-312 | Card number + CVV stored in plaintext |
| 26 | `app/routers/payments.py` — `create_payment` response | CWE-200 | Full card + payment keys returned in response |
| 27 | `app/routers/users.py` — `get_user` | CWE-639 | IDOR — no ownership check |
| 28 | `app/routers/orders.py` — `get_order` | CWE-639 | IDOR — no ownership check |
| 29 | `app/routers/payments.py` — `get_payment` | CWE-639 | IDOR — no ownership check |
| 30 | `app/routers/messages.py` — `get_message` | CWE-639 | IDOR — no ownership check on private messages |
| 31 | `app/routers/users.py` — `update_user` | CWE-269 | Privilege escalation — user can set role=admin |
| 32 | `app/routers/messages.py` — `send_message` | CWE-79 | Stored XSS — content stored and returned raw |
| 33 | `app/routers/auth.py` — `otp/send` | CWE-200 | OTP returned in response body |

## LOW / INFO (7)

| # | File | CWE | Description |
|---|------|-----|-------------|
| 34 | `app/core/config.py` | CWE-798 | 10 hardcoded credentials in source |
| 35 | `app/core/config.py` — `ADMIN_PASSWORD` | CWE-521 | Weak password "admin123" |
| 36 | `app/core/config.py` — `DEBUG=True` | CWE-489 | Debug mode active |
| 37 | `app/core/dependencies.py` | CWE-287 | Token compared to hardcoded password string |
| 38 | `app/core/dependencies.py` | CWE-532 | Full JWT payload written to debug log |
| 39 | `app/models/schemas.py` | CWE-20 | email is plain str, no format validation |
| 40 | `app/main.py` | CWE-942 | allow_origins=["*"] + allow_credentials=True |

**Total: 40 vulnerabilities | Critical: 17 | Major: 16 | Low: 7**
