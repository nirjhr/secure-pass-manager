# Secure Password Manager

A secure password manager that uses SQLite for storage and strong encryption for password protection.

## Features

- User registration and authentication
- Secure password storage using Fernet encryption
- SQLite database backend
- Command-line interface
- List, add, retrieve, and delete passwords
- Master password protection

## Installation

```bash
pip install secure-password-manager
```

## Usage

```python
from secure_password_manager import PasswordManager

# Create a new password manager instance
pm = PasswordManager()

# Register a new user
pm.register_user("username", "master_password")

# Authenticate and get user ID
user_id = pm.authenticate_user("username", "master_password")

# Store a password
pm.store_password(user_id, "github.com", "githubuser", "password123")

# Retrieve a password
username, password = pm.get_password(user_id, "github.com")
```

## Command Line Interface

You can also use the password manager from the command line:

```bash
password-manager
```

## Security

- Passwords are encrypted using Fernet (symmetric encryption)
- Master password is hashed using PBKDF2 with SHA256
- Secure random salt generation
- SQLite database for persistent storage

## License

MIT License - see LICENSE file for details.