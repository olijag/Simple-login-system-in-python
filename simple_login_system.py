import ast
import logging
import bcrypt
import base64
import getpass

# Configure logging to display time, log level, and message
logging.basicConfig(level=logging.INFO, format='%(asctime)s  - %(levelname)s - %(message)s')

# Function to check if a user account already exists in the database
def check_if_account_exists(name):
    with open("database.txt", "r") as database_file:  # Open database file in read mode
        for line in database_file:
            line = line.strip()  # Remove leading/trailing whitespace
            if not line:  # Skip empty lines
                continue

            # Attempt to convert each line from string to dictionary
            try:
                account_dict = ast.literal_eval(line)
                # Check if the current dictionary's username matches the input
                if account_dict.get("username") == name:
                    return True  # User exists
            except ValueError as ve:
                logging.error(f"Error reading the line: {line}. Exception: {ve}")
            except SyntaxError as se:
                logging.error(f"Error reading the line: {line}. Exception: {se}")
    return False  # User does not exist

# Function to verify login credentials
def check_login_credentials(name, password: str):
    with open("database.txt", "r") as database_file:
        for line in database_file:
            try:
                account_dict = ast.literal_eval(line.strip())
                if account_dict.get("username") == name:
                    stored_password = account_dict.get("password")
                    # Decode stored password from base64 to bytes for comparison
                    stored_password_bytes = base64.b64decode(stored_password)
                    given_password_bytes = password.encode('utf-8')
                    # Compare given password with the stored hash
                    if bcrypt.checkpw(given_password_bytes, stored_password_bytes):
                        return True  # Password matches
            except ValueError as ve:
                logging.error(f"Error parsing account data, exception: {ve}")
            except SyntaxError as se:
                logging.error(f"Error parsing account data, exception: {se}")
    return False  # Password does not match

# Function to register a new account
def register_new_account():
    print("== Register new account ==")

    while True:
        name = input("Username: ")
        # Check for existing account with the same username
        if check_if_account_exists(name):
            print("\nAccount with given username already exists. Please try with a different name")
        else:
            break

    password = getpass.getpass(prompt="Password: ")  # Securely input password

    # Hash the password
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    # Encode the hash for storage
    hashed_str = base64.b64encode(hashed_password).decode('utf-8')

    # Save the new account to the database
    with open("database.txt", "a") as database_file:
        database_file.write(str({"username": name, "password": hashed_str}) + '\n')
    
    print("Account successfully created")

# Function for user login
def login():
    print("== Login into existing account ==")
    name = input("Username: ")
    password = getpass.getpass(prompt="Password: ")  # Securely input password

    # Verify account existence and credentials
    if not check_if_account_exists(name) or not check_login_credentials(name, password):
        print("\nAccount with given username doesn't exist or the password is wrong. Please try again.")
    else:
        print("Successfully logged in")

# Main function to start the application
options = {1: login, 2: register_new_account}

def init():
    print("== Simple Login System ==")
    print("1. Login to existing account")
    print("2. Register new account")

    while True:
        selected_option = input("Select: ")
        # Try-except block to catch and handle cases where input cannot be converted to an integer. 
        try: 
            selected_option = int(selected_option)
            if selected_option in options:
                options[selected_option]()  # Execute selected function
                break
            else:
                print("\nError: Invalid option selected\n")
        except ValueError:
            print("\nError: Invalid option selected. Please enter a number (1 or 2)\n")


# Entry point of the script
if __name__ == "__main__":
    init()