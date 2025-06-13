from logger import configure_logging
import logging
import secrets
import re

from db import select_db, insert_db
from password import hash_password, verify_password

configure_logging()
logger = logging.getLogger(__name__)

def is_valid_username(username: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_]+$", username))

def is_valid_password(password: str) -> bool:
    return len(password) >= 8

def user_exists(username: str) -> bool:
    result = select_db("SELECT COUNT(*) FROM users WHERE username = %s", (username,), "user_exists")
    return result[0][0] > 0 

def store_credentials(username: str, password: str) -> None:
    if not username.strip():
        raise ValueError("Username cannot be empty.")
    if not is_valid_username(username):
        raise ValueError("Username can only contain letters, digits, and underscores.")

    if not password.strip():
        raise ValueError("Password cannot be empty.")
    if not is_valid_password(password):
        raise ValueError("Password must be at least 8 characters long.")

    salt = secrets.token_bytes(16)
    hashed = hash_password(password, salt)

    insert_db("INSERT INTO users (username, salt, hashed_password) VALUES (%s, %s, %s)", 
              (username, salt.hex(), hashed.hex(),), "store_credentials")

    logger.info(f"User '{username}' registered successfully.")

def verify_credentials(username: str, password: str) -> bool:
    result = select_db(
        "SELECT salt, hashed_password FROM users WHERE username = %s",
        (username,),
        "verify_credentials"
    )

    if not result:
        logger.warning(f"Login attempt for non-existent user: '{username}'")
        return False

    salt, stored_hash = bytes.fromhex(result[0][0]), result[0][1]
    return verify_password(password, salt, stored_hash)