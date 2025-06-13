import pytest
import secrets
from password import hash_password, verify_password

# --- Fixtures ---
@pytest.fixture
def sample_password():
    return "StrongPassword123"

@pytest.fixture
def sample_salt():
    return secrets.token_bytes(16)

# Hash test
def test_hash_password_returns_bytes(sample_password, sample_salt):
    hashed = hash_password(sample_password, sample_salt)
    assert isinstance(hashed, bytes)
    assert len(hashed) > 0

def test_verify_password_success(sample_password, sample_salt):
    hashed = hash_password(sample_password, sample_salt)
    assert verify_password(sample_password, sample_salt, hashed.hex())

def test_verify_password_failure_wrong_input(sample_password, sample_salt):
    hashed = hash_password(sample_password, sample_salt)
    wrong_password = "WrongPassword456"
    assert not verify_password(wrong_password, sample_salt, hashed.hex())

def test_hash_password_error(monkeypatch):
    monkeypatch.setattr("hashlib.pbkdf2_hmac", lambda *_: (_ for _ in ()).throw(Exception("fake error")))
    with pytest.raises(Exception, match="fake error"):
        hash_password("somepass", b"somesalt")