# Implementation
This section describes the full implementation process of the Secure Auth Storage CLI.

- [Designed Password Security Strategy](#designed-password-security-strategy)

- [Install dependencies](#install-dependencies)

- [Project Setup and Constants](#project-setup-and-constants)

  - [CLI Structure](#1-cli-structure)
  - [Environment Variables and Constants](#2-environment-variables-and-constants)

    - [Setup the `.env` file](#21-setup-the-env-file)
- [Credential Handling: Hashing, Storing, and Validation](#credential-handling-hashing-storing-and-validation)

  - [Hashing Function](#hashing-function)
  - [Store Credentials](#store-credentials)
  - [Verify Credentials](#verify-credentials)
  - [Verify Password]() 

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

## Credential Handling: Hashing, Storing, and Validation

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

### Store Credentials
--- 

→ **Defined in:** `auth.py`

This function is responsible for orchestrating the process of credential storage. 

It validates inputs, generates the salt, calls `hash_password()` function to perform the hashing and store the output in the database.

```python
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

	insert_db(
		"INSERT INTO users (username, salt, hashed_password) VALUES (%s, %s, %s)",
		(
			username,
			salt.hex(),
			hashed.hex(),
		),
		"store_credentials",
	)

	logger.info(f"User '{username}' registered successfully.")
```

❶ - **Receives:**

  - `username`: a string input provided by the user.
  - `password`: a user-provided password as a string.

➋ - **Process:**

  - ***Validates the input:***

    - Checks if username and password are not empty (after stripping whitespace).

    - Ensures the username only contains letters, digits, or underscores using `is_valid_username()`.

    - Ensures the password meets a minimum security requirement using `is_valid_password()`.

  - ***Generates a salt:***

    - Uses `secrets.token_bytes(16)` to create a 16-byte random salt for this user.

  - ***Hashes the password (Call `hash_password()`)***

  - ***Stores credentials in the database:***

    - Converts both `salt` value and `hashed` output to hexadecimal (`salt.hex()`, `hashed.hex()`) before storing (so they can be stored as text).

    - Calls `insert_db()` to insert the values into the `users` table.

➌ - **Returns:**

- Return (`None`)

### Verify Credentials
---
→ **Defined in:** `auth.py`

This function is responsible for validating a user's login attempt by retrieving the stored credentials from the database and comparing the provided password with the stored hash.

```python
def verify_credentials(username: str, password: str) -> bool:
	result = select_db(
		"SELECT salt, hashed_password FROM users WHERE username = %s",
		(username,),
		"verify_credentials",
	)

	if not result:
		logger.warning(f"Login attempt for non-existent user: '{username}'")
		return False

	salt, stored_hash = bytes.fromhex(result[0][0]), result[0][1]
	return verify_password(password, salt, stored_hash)
  ```

  ❶ - **Receives:**

  - `username`: a string input provided by the user.
  - `password`: a user-provided password as a string.

➋ - **Process:**

  - ***Database Query:***

    - Uses the `select_db()` function to fetch the stored `salt` and `hashed_password` for the given `username`.

  - ***User check:***

    - If the `username` is not found, it logs a warning and returns `False`.

  - ***Password Verification:***
  
    - Calls `verify_password()` to compare the stored hash with a fresh hash generated.

➌ - **Returns:**

- `True` if the hashes match (successful login)

- `False` otherwise (invalid credentials).

### Verify Password
---
→ **Defined in:** `password.py`

Handles comparison between a freshly hashed password and a stored hash.

```python
def verify_password(password: str, salt: bytes, expected_hash: str) -> bool:

	try:
		hashed = hash_password(password, salt)
		return hashed.hex() == expected_hash

	except Exception as e:
		logger.error(f"Error verifying password: {e}")
		return False
```
❶ - **Receives:**

  - `password`: a user-provided password as a string.

  - `salt`: The salt string, originally generated and stored when the user registered. It is used to recreate the original hash.

  - `expected_hash`: The previously stored hash from the database (in hex format) that the newly generated hash will be compared against.

➋ - **Process:**

- ***Hashing the input:***

  - Calls `hash_password()`

- ***Comparison:***

  - Converts the freshly generated hash into a hexadecimal string using `.hex()`.
  
  - Checks if it is exactly the same as the `expected_hash` stored in the database, using **equality operator** `hashed.hex() == expected_hash`.

➌ - **Returns:**

- `True`  if the generated hash matches the expected hash, indicating that the password is correct.

- `False` if the hashes don't match or any error occurs during the process.

### Database
---
→ **Defined in:** `db.py`

This file manages everything related to talking to the database. It connects to the PostgreSQL database, runs queries, inserts data, and creates the table where user information is stored.

```python
def get_connection():
	try:
		return psycopg2.connect(
			dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=5432
		)
	except psycopg2.OperationalError as e:
		logger.error(f"Failed to connect to database: {e}")
		raise


def select_db(query: str, vars, func_name: str):
	try:
		with get_connection() as conn:
			with conn.cursor() as cur:
				cur.execute(query, vars)
				return cur.fetchall()
	except psycopg2.Error as e:
		logger.error(f"Database error during {func_name}: {e}")
		raise


def insert_db(query: str, vars, func_name: str):
	try:
		with get_connection() as conn:
			with conn.cursor() as cur:
				cur.execute(query, vars)
				conn.commit()

	except psycopg2.Error as e:
		logger.error(f"Database error during {func_name}: {e}")
		raise


def setup_user_table():
	insert_db(
		"CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hashed_password TEXT NOT NULL);",
		(),
		"setup_user_table",
	)
	logger.info("Users table initialized.")
```
- `get_connection()`: connects to the PostgreSQL database using the credentials from  `.env` file.

- `select_db(query, vars, func_name)`: runs a `SELECT` query and returns the result. Used to get data from the database.

- `insert_db(query, vars, func_name)`: runs an `INSERT`, `CREATE`, or `UPDATE` query. Used to add or update data in the database.

- `setup_user_table()`: creates the users table if it doesn’t already exist. This is called when the app starts to make sure the database is ready.

