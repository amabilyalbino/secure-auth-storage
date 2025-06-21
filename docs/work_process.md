# Implementation
This section describes the full implementation process of the Secure Auth Storage CLI.

- Setup and Envi
    - 1.1. 
- [My work process](docs/work_process.md)

## Designed Password Security Strategy

- **PBKDF2** → as the main password hashing function
- **SHA-256** as the internal algorithm inside PBKDF2.
- Unique **salt** per user to make hashes different → generated using Python’s `secrets.token_bytes(16)` for cryptographic randomness
-  A secret string called **pepper** is a value that must be created manually *(like a password or token)*, or it can be generated using the same secrets module used to generate the salt.
- Number of **iterations** defined → `150000`

> [!NOTE]
>
> **PBKDF2** is a cryptographic algorithm that uses **SHA-256** in multiple rounds to derive a secure hash. It combines the password + salt + pepper, and runs 150,000 iterations before producing the final output.

## Install Dependencies

To start building the project, I first added the required libraries to the `requirements.txt` file. 

- <b><ins>External packages</ins></b>
  
  - `python-dotenv` → to load environment variables from a .env file.
  - `psycopg2-binary` → to connect to the PostgreSQL database

- <b><ins>Built-in Python modules<ins></b>

  - `hashlib` — for password hashing with PBKDF2
  - `secrets` — to generate cryptographically secure salts (and optionally the pepper)
  - `os` — to read environment variables
  - `hmac` — for secure hash comparisons
  - `getpass` — to safely receive password input in the CLI without echoing it

## Project Setup and Constants

### 1. CLI Structure
---
I started by creating a file called `main.py` inside the `src/` folder. In this file, I built a simple menu-driven CLI interface that allows the user to:

- Register a new account
- Log in to an existing account
- Exit the program

I used basic `input()` prompts for interaction, and kept the `main.py` file focused on user flow only.
All the core logic — such as *(validation, hashing, credential storage, and verification)* — was delegated to other modules:

  → `auth.py`

  → `password.py`

  → `db.py`

  → `settings.py`

### 2. Environment Variables and Constants
---

To manage environment variables and constants, I created a separate file called `settings.py`.

This file handles loading and validating environment variables that are used across the project from a `.env` file.

```python
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
```
- `require_env()` → checks that required variables (like `PEPPER`, `DB_NAME`, etc.) actually exist.

- `PEPPER` is read and encoded to bytes for hashing.

#### 2.1. Setup the `.env` file
----
The `.env` file sits at the root of the project and defines sensitive values like the PEPPER, database credentials, and hashing configuration.

> **Example `.env` file:**

```python
PEPPER="SECRET_KEY"
ITERATIONS = 150000
HASH_NAME = "sha256"

PYTHONPATH=src

DB_NAME=login_system
DB_USER=auth_user
DB_PASSWORD=mysecurepassword
DB_HOST=localhost
```

## Credential Handling  Hashing, Storing, and Validation

This section explains how I implemented the secure processing of user credentials, including how passwords are hashed, stored in the database, and later verified during login.

### Hashing Function
---
→ **Defined in:** `password.py`

This function is the core of the secure password workflow. Hashes a user password using PBKDF2 with SHA-256, pepper, salt and multiple iterations.

```python
def hash_password(password: str, salt: bytes) -> bytes:
	try:
		password_peppered = password.encode() + PEPPER
		return hashlib.pbkdf2_hmac(HASH_NAME, password_peppered, salt, ITERATIONS)
	except Exception as e:
		logger.error(f"Error hashing password: {e}")
		raise
```
❶ - **Receives:**

  - `password`: a user-provided password as a string
  - `salt:` randomly string generated

➋ - **Process:**
  - Converts the password to bytes using `.encode()`

  - Appends the secret `PEPPER` (loaded from `.env`) to the password

  - Passes the combined `password + pepper` into `hashlib.pbkdf2_hmac()`, along with:

    - `HASH_NAME`: the hashing algorithm `sha256`
    
    - `salt`

    - `150000` iterations 

➌ - **Returns:**

    - A derived password hash in raw bytes format.