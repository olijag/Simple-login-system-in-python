# Simple Login System

This Python script provides a basic command-line interface for a login system, allowing users to register new accounts with a username and password, and then log in using their credentials. The system uses password hashing for security, ensuring that passwords are not stored in plain text.

## Features
User Registration: New users can register by choosing a unique username and a password. The password is hashed before it is stored, enhancing security.
User Login: Registered users can log in by entering their username and password. The system verifies the hashed password, granting access only if the credentials match.
Password Hashing: Uses the bcrypt library for secure password hashing.
Secure Password Input: Passwords are entered securely, hiding input from shoulder surfers.


The script requires the following Python libraries:

**ast:** For safely evaluating strings containing Python expressions from a simple database file.
**logging:** For logging errors and system messages.
**bcrypt:** For hashing and verifying passwords.
**base64:** For encoding and decoding hashed passwords as strings for storage.
**getpass:** For secure password input that doesn't echo characters on the terminal.


## File Storage
User credentials (usernames and hashed passwords) are stored in a plain text file named database.txt. 
Each line in the file represents a user account in the form of a Python dictionary literal, e.g., {'username': 'john_doe', 'password': 'hashed_password'}.
