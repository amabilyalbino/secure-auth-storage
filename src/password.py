import hashlib
import logging
from settings import PEPPER, HASH_NAME, ITERATIONS

logger = logging.getLogger(__name__)

def hash_password(password: str, salt: bytes) -> bytes:
    try:
        password_peppered = password.encode() + PEPPER
        return hashlib.pbkdf2_hmac(HASH_NAME, password_peppered, salt, ITERATIONS)
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise

def verify_password(password: str, salt: bytes, expected_hash: str) -> bool:
    try:
        hashed = hash_password(password, salt)
        return hashed.hex() == expected_hash
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False
