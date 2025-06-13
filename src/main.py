from getpass import getpass
from auth import store_credentials, verify_credentials, user_exists
from db import setup_user_table
from logger import configure_logging
import logging

configure_logging()
logger = logging.getLogger(__name__)

def menu():
	while True:
		print("\n--- Secure Login System ---")
		print("1. Register")
		print("2. Login")
		print("3. Exit")
		choice = input("Choose an option: ").strip()

		if choice == "1":
			register_user()
		elif choice == "2":
			login_user()
		elif choice == "3":
			print("Goodbye!")
			break
		else:
			print("Invalid choice. Please try again.")

def register_user():
	username = input("New username: ").strip()

	if user_exists(username):
		print("Username already exists. Please choose another.")
		return

	while True:
		password = getpass("New password (min 8 characters): ").strip()
		try:
			store_credentials(username, password)
			print("User registered successfully!")
			break
		except ValueError as e:
			print(f"Error: {e}")
		except Exception as e:
			logger.error(f"Unexpected error during registration: {e}")
			break

def login_user():
	username = input("Username: ").strip()
	password = getpass("Password: ").strip()

	try:
		if verify_credentials(username, password):
			print("Login successful!")
		else:
			print("Invalid username or password.")
	except Exception as e:
		logger.error(f"Unexpected error during login: {e}")

if __name__ == "__main__":
	try:
		setup_user_table()
	except Exception as e:
		logger.critical("Failed to initialize database. Exiting.")
		exit(1)

	menu()
