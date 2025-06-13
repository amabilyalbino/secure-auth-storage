import pytest
from auth import store_credentials, verify_credentials, user_exists
from db import setup_user_table, get_connection
import psycopg2
import secrets

# Setup

def setup_module(module):
    setup_user_table()
    # Clean test users before each test run
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username LIKE 'test_user_%'")
            conn.commit()

# Tests auth

def test_user_registration_and_login():
    username = f"test_user_{secrets.token_hex(4)}"
    password = "secureTestPass123"

    assert not user_exists(username)

    store_credentials(username, password)

    assert user_exists(username)
    assert verify_credentials(username, password)

def test_duplicate_username():
    username = f"test_user_{secrets.token_hex(4)}"
    password = "secureTestPass456"

    store_credentials(username, password)
    with pytest.raises(psycopg2.IntegrityError):
        store_credentials(username, password)

def test_invalid_password_too_short():
    username = f"test_user_{secrets.token_hex(4)}"
    short_password = "123"

    with pytest.raises(ValueError):
        store_credentials(username, short_password)

def test_invalid_username():
    invalid_username = "invalid!user"
    password = "SomeSecurePass123"

    with pytest.raises(ValueError):
        store_credentials(invalid_username, password)