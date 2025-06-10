# tests/test_main.py – now uses real DB, no mocking

import pytest
from main import register_user, login_user, menu
from auth import user_exists
from db import get_connection
from getpass import getpass
import builtins
import io
import sys

@pytest.fixture(scope="module", autouse=True)
def cleanup_test_users():
    yield
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username LIKE 'test_user_cli_%'")
            conn.commit()

def test_register_and_login_success(monkeypatch):
    username = "test_user_cli_success"
    password = "StrongCliPassword123"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()

    monkeypatch.setattr(builtins, "input", lambda _: username)
    monkeypatch.setattr("main.getpass", lambda _: password)

    register_user()
    assert user_exists(username)

    monkeypatch.setattr(builtins, "input", lambda _: username)
    monkeypatch.setattr("main.getpass", lambda _: password)

    login_user()

def test_register_duplicate_user(monkeypatch):
    username = "test_user_cli_duplicate"
    password = "StrongCliPassword123"

    if not user_exists(username):
        monkeypatch.setattr(builtins, "input", lambda _: username)
        monkeypatch.setattr("main.getpass", lambda _: password)
        register_user()

    monkeypatch.setattr(builtins, "input", lambda _: username)
    monkeypatch.setattr("main.getpass", lambda _: password)
    register_user()

def test_menu_invalid_and_exit(monkeypatch, capsys):
    inputs = iter(["x", "3"])  # x = invalid option, 3 = exit
    monkeypatch.setattr(builtins, "input", lambda _: next(inputs))

    captured_output = io.StringIO()
    sys.stdout = captured_output
    menu()
    sys.stdout = sys.__stdout__

    out = captured_output.getvalue()
    assert "Invalid choice" in out
    assert "Goodbye!" in out
