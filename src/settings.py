from dotenv import load_dotenv
import os

load_dotenv()

def require_env(var_name: str) -> str:
    value = os.getenv(var_name)
    if not value:
        raise ValueError(f"Missing required environment variable: {var_name}")
    return value

# Cryptographic configuration
PEPPER = require_env("PEPPER").encode()
HASH_NAME = os.getenv("HASH_NAME", "sha256")
ITERATIONS = int(os.getenv("ITERATIONS", "150000"))

# Database configuration
DB_NAME = require_env("DB_NAME")
DB_USER = require_env("DB_USER")
DB_PASSWORD = require_env("DB_PASSWORD")
DB_HOST = require_env("DB_HOST")
