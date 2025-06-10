import pytest
from db import get_connection, initialize_users_table
import psycopg2

# --- Tests ---

def test_database_connection():
    try:
        conn = get_connection()
        assert conn is not None
        assert conn.closed == 0  # connection is open
    finally:
        conn.close()
        assert conn.closed == 1

def test_initialize_users_table_creates_table():
    try:
        initialize_users_table()
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")
                columns = [col[0] for col in cur.fetchall()]
        assert "username" in columns
        assert "salt" in columns
        assert "hashed_password" in columns
    except psycopg2.Error as e:
        pytest.fail(f"Unexpected database error: {e}")