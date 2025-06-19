# Overview

This project is a Python CLI-based authentication system for storing and validating user credentials using **hashing, salting, and peppering**.

> [!WARNING]
> This project was built for **learning purposes only** — to explore and understand secure password handling with **hash, salt, and pepper** using Python. - **Not for production**

# Learning Motivation

It started when I had to build a simple CLI-based login system for a assessment. The credentials (username and password) had to be stored in a plain `.txt` file — which didn’t feel right in terms of security.

So I took that opportunity to learn how to store credentials more securely in Python. That’s when I found out about **hashing, salting, and peppering**. I decided to apply those concepts directly into that simple login system, turning it into a practical way.

# How to run

This project uses Docker to run a PostgreSQL database. You do **not** need to install PostgreSQL manually — the database will run inside a container defined by the `docker-compose.yml` file (which is already included in this repository).

## 1. Clone the repository and setup environment:

First, **clone the repository** and then in your terminal, run the following:

```bash
cd secure-auth-storage
```
```bash
cp .env.example .env
```
This will:

- Move you into the project folder

- Create your own `.env` configuration file based on the example provided.

> [!IMPORTANT] 
> Don't forget to update the `.env` file with your custom secrets if needed (like the PEPPER and DB credentials).

## 2. Start the PostgreSQL database:
   
```bash
docker-compose up -d
```

This command will launch a PostgreSQL database container in the background, using the configuration defined in the `docker-compose.yml` file.

## 3. Run the CLI app:

```bash
export PYTHONPATH=src
```
```bash
python3 src/main.py
```

# 🗂 Project Structure


```css
SECURE-AUTH-STORAGE
- src/
    - main.py -> CLI entry point / user interface
    - auth.py -> Handles authentication logic and validation
    - db.py -> DataBase setup
    - password.py -> Password hashing and verification
    - settings.py -> Loads environment variables 
    - logger.py -> setting up logging behaviour 

    - tests/
- .env
- requirements.txt
- docker-compose.yml
- README.md
```
## 📖 Documentation

If you're curious about how hashing, salting, peppering, and iteration work in practice, or want to see how I learned and applied these concepts, the docs below walk through each concept and how i applied them in this project.

- [Concepts of Secure Data Storage](docs/concepts.md)
- [Secure Storage Workflow](docs/storage-workflow.md)
- [My work process](docs/work-process.md)


> [!IMPORTANT]  
> The documentation in this project reflects my **learning process** and **thought process** while figuring out how to build secure password storage in Python. It’s not a formal technical reference, it’s a guided breakdown of how I understood each concept and applied it in practice.
