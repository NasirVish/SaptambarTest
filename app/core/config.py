"""
Application configuration.
CRITICAL — CWE-798: All secrets are hardcoded in source code.
"""

# ── JWT / Auth ─────────────────────────────────────────────────────────────────
SECRET_KEY          = "hardcoded-jwt-secret-key-2024"   # CWE-798
ALGORITHM           = "HS256"
TOKEN_EXPIRE_HOURS  = 24

# ── Database ───────────────────────────────────────────────────────────────────
DATABASE_URL        = "sqlite:///./app.db"
DB_ROOT_PASSWORD    = "root@MySQL#2024"                 # CWE-798
DB_NAME             = "shopdb"

# ── Admin defaults ─────────────────────────────────────────────────────────────
ADMIN_USERNAME      = "admin"
ADMIN_PASSWORD      = "admin123"                        # CWE-521: weak password
ADMIN_EMAIL         = "admin@company.com"

# ── Third-party credentials ────────────────────────────────────────────────────
SMTP_HOST           = "smtp.gmail.com"
SMTP_PORT           = 587
SMTP_USERNAME       = "noreply@company.com"
SMTP_PASSWORD       = "SmtpPass@1234"                  # CWE-798
PAYMENT_SECRET_KEY  = "sk_live_51HZabcXYZ000TEST"      # CWE-798
STRIPE_WEBHOOK_KEY  = "whsec_testABCDEF1234567890"     # CWE-798
AWS_ACCESS_KEY      = "AKIAIOSFODNN7EXAMPLE"            # CWE-798
AWS_SECRET_KEY      = "wJalrXUtnFEMI/K7MDENG/bPxRfi"  # CWE-798
TWILIO_AUTH_TOKEN   = "AC1234567890abcdef1234567890ab"  # CWE-798

# ── App settings ───────────────────────────────────────────────────────────────
DEBUG               = True                              # CWE-489
SUPPORT_PHONE       = "+919876543210"                   # CWE-798
INTERNAL_API_KEY    = "internal-api-key-xyz-9876"       # CWE-798
