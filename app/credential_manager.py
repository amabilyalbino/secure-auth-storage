import hashlib
import hmac
import secrets
import psycopg2
import re
from app.config import PEPPER, HASH_NAME, ITERATIONS, DB_NAME, DB_USER, DB_PASSWORD, DB_HOST

def hash_password(password: str, salt: bytes) -> bytes:
    password_peppered = password.encode() + PEPPER
    return hashlib.pbkdf2_hmac(HASH_NAME, password_peppered, salt, ITERATIONS)

def get_connection():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=5432
    )

def setup_db_table():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt TEXT NOT NULL,
                    hashed_password TEXT NOT NULL
                );
            """)
            conn.commit()

def store_credentials(username: str, password: str) -> None:
    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        raise ValueError("Username can only contain letters, digits, and underscores.")
    
    if not password or not password.strip():
        raise ValueError("Password cannot be empty.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.match(r"^[a-zA-Z0-9_]+$", password):
        raise ValueError("Password can only contain letters, digits, and underscores.")

    salt = secrets.token_bytes(16)
    hashed = hash_password(password, salt)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, salt, hashed_password) VALUES (%s, %s, %s)",
                (username, salt.hex(), hashed.hex())
            )
            conn.commit()

def verify_credentials(username: str, password: str) -> bool:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT salt, hashed_password FROM users WHERE username = %s",
                (username,)
            )
            row = cur.fetchone()
            
            if row is None:
                return False
            salt_hex, hashed_stored = row
            salt = bytes.fromhex(salt_hex)
            hashed_input = hash_password(password, salt).hex()
            return hmac.compare_digest(hashed_input, hashed_stored)

def user_exists(username: str) -> bool:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM users WHERE username = %s",
                (username,)
            )
            return cur.fetchone() is not None