"""
Database initialisation and connection.
"""
import sqlite3
from pathlib import Path
from app.core.config import DB_ROOT_PASSWORD  # noqa – shows credential import pattern

DB_PATH = Path(__file__).resolve().parent.parent.parent / "app.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password      TEXT NOT NULL,
            role          TEXT DEFAULT 'user',
            phone         TEXT,
            address       TEXT,
            credit_card   TEXT,
            ssn           TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS products (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            description   TEXT,
            price         REAL NOT NULL,
            stock         INTEGER DEFAULT 0,
            category      TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            product_id    INTEGER NOT NULL,
            quantity      INTEGER DEFAULT 1,
            total         REAL NOT NULL,
            status        TEXT DEFAULT 'pending',
            created_at    TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS payments (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id      INTEGER NOT NULL,
            card_number   TEXT,
            card_cvv      TEXT,
            card_expiry   TEXT,
            amount        REAL,
            status        TEXT DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS messages (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id     INTEGER,
            receiver_id   INTEGER,
            content       TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        );
    """)

    from app.utils.security import hash_password
    conn.execute(
        "INSERT OR IGNORE INTO users (username,email,password,role,phone,credit_card,ssn) VALUES (?,?,?,?,?,?,?)",
        ("admin","admin@company.com", hash_password("admin123"), "admin",
         "+919876543210", "4111111111111111", "123-45-6789")
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username,email,password,role,phone,credit_card,ssn) VALUES (?,?,?,?,?,?,?)",
        ("alice","alice@example.com", hash_password("alice123"), "user",
         "+911234567890", "4222222222222222", "987-65-4321")
    )
    conn.executemany(
        "INSERT OR IGNORE INTO products (name,description,price,stock,category) VALUES (?,?,?,?,?)",
        [
            ("Laptop","High performance laptop",75000.0,10,"Electronics"),
            ("Phone","Latest smartphone",25000.0,50,"Electronics"),
            ("Book","Python programming guide",599.0,100,"Books"),
        ]
    )
    conn.commit()
    conn.close()
