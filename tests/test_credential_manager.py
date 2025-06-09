import sys
import os
import pytest
import secrets
import string
import uuid
import hashlib

# Ensure Python can find app/ folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.credential_manager import (
    hash_password,
    verify_credentials,
    store_credentials,
    user_exists,
    get_connection,
    setup_db_table,
)
from app.config import PEPPER, HASH_NAME, ITERATIONS


# ---------- FIXTURE ----------

@pytest.fixture
def new_user():
    """Fixture to create and delete a test user automatically."""
    username = 'user_' + ''.join(secrets.choice(string.ascii_letters) for _ in range(8))
    password = 'ValidPass123_'

    yield username, password

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()


# ---------- UNIT TESTS ----------

def test_hash_password_consistency():
    password = "mypassword123"
    salt = secrets.token_bytes(16)
    hash1 = hash_password(password, salt)
    hash2 = hash_password(password, salt)
    assert hash1 == hash2

def test_hash_password_uniqueness():
    password = "mypassword123"
    salt1 = secrets.token_bytes(16)
    salt2 = secrets.token_bytes(16)
    hash1 = hash_password(password, salt1)
    hash2 = hash_password(password, salt2)
    assert hash1 != hash2

# ---------- INTEGRATION TESTS ----------

def test_store_and_verify_credentials(new_user):
    username, password = new_user

    store_credentials(username, password)

    assert user_exists(username) is True
    assert verify_credentials(username, password) is True
    assert verify_credentials(username, "WrongPassword") is False

def test_init_db_creates_users_table():
    setup_db_table()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'users';
            """)
            table_exists = cur.fetchone() is not None

    assert table_exists is True

# ---------- SECURITY & EDGE CASES ----------

def test_store_with_empty_username():
    with pytest.raises(ValueError):
        store_credentials("", "ValidPass123_")

def test_store_with_empty_password():
    with pytest.raises(ValueError):
        store_credentials("validuser", "")

def test_verify_nonexistent_user():
    assert verify_credentials("nonexistent_user_xyz", "somepassword") is False

@pytest.mark.parametrize("username", [
    "'; DROP TABLE users; --",
    "' OR 1=1 --",
    "<script>alert(1)</script>",
])
def test_store_credentials_rejects_unsafe_usernames(username):
    with pytest.raises(ValueError):
        store_credentials(username, "ValidPass123_")

# ---------- PASSWORD VALIDATION TESTS ----------

def test_store_with_valid_password():
    username = "validuser_" + uuid.uuid4().hex[:6]
    password = "ValidPass123_"
    try:
        store_credentials(username, password)
    except Exception:
        pytest.fail("store_credentials() raised an Exception for a valid password")

def test_store_with_invalid_password_special_chars():
    username = "invaliduser_" + uuid.uuid4().hex[:6]
    password = "Invalid123!"
    with pytest.raises(ValueError, match="Password can only contain letters, digits, and underscores."):
        store_credentials(username, password)

def test_store_with_invalid_password_too_short():
    username = "shortpassuser_" + uuid.uuid4().hex[:6]
    password = "123"
    with pytest.raises(ValueError, match="Password must be at least 8 characters long."):
        store_credentials(username, password)

def test_store_with_invalid_password_spaces():
    username = "spaceuser_" + uuid.uuid4().hex[:6]
    password = "My Pass 123"
    with pytest.raises(ValueError, match="Password can only contain letters, digits, and underscores."):
        store_credentials(username, password)

# ---------- ADVANCED SECURITY CHECKS ----------

def test_hash_length_and_iterations():
    password = "SecurePassword123"
    salt = secrets.token_bytes(16)
    hashed = hash_password(password, salt)

    assert isinstance(hashed, bytes)
    assert len(hashed) >= 32  # sha256 = 32 bytes
    assert ITERATIONS >= 100_000

def test_hash_changes_with_pepper(monkeypatch):
    password = "PepperTest123"
    salt = secrets.token_bytes(16)

    # First hash with current PEPPER
    hash1 = hash_password(password, salt)

    # Change PEPPER env temporarily
    monkeypatch.setenv("PEPPER", "DIFFERENT_PEPPER")
    from importlib import reload
    import app.config as new_config
    reload(new_config)

    # Manually rebuild the hash with new pepper
    password_peppered = password.encode() + new_config.PEPPER
    hash2 = hashlib.pbkdf2_hmac(HASH_NAME, password_peppered, salt, ITERATIONS)

    assert hash1 != hash2
