from app.credential_manager import store_credentials, user_exists, verify_credentials, setup_db_table
from getpass import getpass

def menu():
    while True:
        print("\n--- Secure Login System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            username = input("New username: ")

            if user_exists(username): 
                print("Username already exists. Please be more creative. Thanks!")
                continue

            while True: 
                password = getpass("New password (min 8 characters): ")
                if len(password) < 8:
                    print("Password is too short. Please use at least 8 characters.")
                else:
                    break

            try:
                store_credentials(username, password)
                print("User registered securely")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "2":
            username = input("Username: ")
            password = getpass("Password: ")

            if verify_credentials(username, password):
                print(f"\nLogin successful! Welcome, {username}!")

                while True: 
                    print("\n=== Logged In Menu ===")
                    print("1. Logout")
                    logged_choice = input("Choose an option: ")
                    if logged_choice == "1":
                        print("You have been logged out.\n")
                        break
                    else:
                        print("This option doesn't exist. Try again.")
            else:
                print("Invalid credentials.")

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    setup_db_table()
    menu()
