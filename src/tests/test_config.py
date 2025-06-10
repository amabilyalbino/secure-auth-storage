import os
import pytest
from settings import require_env

# --- Tests ---

def test_require_env_returns_value(monkeypatch):
    monkeypatch.setenv("FAKE_VAR", "some_value")
    assert require_env("FAKE_VAR") == "some_value"

def test_require_env_raises_for_missing():
    with pytest.raises(ValueError) as exc_info:
        require_env("MISSING_VAR")
    assert "Missing required environment variable" in str(exc_info.value)
