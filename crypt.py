import hashlib
import os
from typing import Optional, Tuple, List
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
from datetime import datetime
import getpass

class PasswordManager:
    def __init__(self, db_path: str = "passwords.db"):
        """Initialize the password manager with database connection"""
        self.db_path = db_path
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            # Create stored_passwords table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS stored_passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE (user_id, service_name)
                )
            ''')
            
            conn.commit()
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> tuple[str, bytes]:
        """Hash a password using PBKDF2 with a random salt"""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.b64encode(kdf.derive(password.encode()))
        return key.decode('utf-8'), salt
    
    def register_user(self, username: str, master_password: str) -> bool:
        """Register a new user with a master password"""
        try:
            hashed_password, salt = self.hash_password(master_password)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                    (username, hashed_password, salt)
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # Username already exists
    
    def authenticate_user(self, username: str, password: str) -> Optional[int]:
        """Authenticate a user and return user_id if successful"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, password_hash, salt FROM users WHERE username = ?',
                (username,)
            )
            result = cursor.fetchone()
            
            if result:
                user_id, stored_hash, salt = result
                hashed_password, _ = self.hash_password(password, salt)
                
                if stored_hash == hashed_password:
                    # Update last login timestamp
                    cursor.execute(
                        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                        (user_id,)
                    )
                    conn.commit()
                    return user_id
            return None
    
    def store_password(self, user_id: int, service_name: str, username: str, password: str) -> bool:
        """Store an encrypted password for a service"""
        encrypted_password = self.cipher_suite.encrypt(password.encode())
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO stored_passwords 
                    (user_id, service_name, username, encrypted_password, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (user_id, service_name, username, encrypted_password))
                conn.commit()
            return True
        except sqlite3.Error:
            return False
    
    def get_password(self, user_id: int, service_name: str) -> Optional[Tuple[str, str]]:
        """Retrieve a stored password for a service"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT username, encrypted_password FROM stored_passwords WHERE user_id = ? AND service_name = ?',
                (user_id, service_name)
            )
            result = cursor.fetchone()
            
            if result:
                username, encrypted_password = result
                decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
                return username, decrypted_password
            return None
    
    def list_services(self, user_id: int) -> List[Tuple[str, str, str]]:
        """List all stored services for a user"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT service_name, username, created_at 
                   FROM stored_passwords 
                   WHERE user_id = ?
                   ORDER BY service_name''',
                (user_id,)
            )
            return cursor.fetchall()
    
    def delete_password(self, user_id: int, service_name: str) -> bool:
        """Delete a stored password for a service"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'DELETE FROM stored_passwords WHERE user_id = ? AND service_name = ?',
                    (user_id, service_name)
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False

def main():
    """Main function demonstrating the password manager usage"""
    pm = PasswordManager()
    
    while True:
        print("\nPassword Manager")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            username = input("Enter username: ")
            password = getpass.getpass("Enter master password: ")
            
            if pm.register_user(username, password):
                print("Registration successful!")
            else:
                print("Username already exists!")
                
        elif choice == "2":
            username = input("Enter username: ")
            password = getpass.getpass("Enter master password: ")
            
            user_id = pm.authenticate_user(username, password)
            if user_id:
                while True:
                    print("\nPassword Management")
                    print("1. Store password")
                    print("2. Get password")
                    print("3. List services")
                    print("4. Delete password")
                    print("5. Logout")
                    
                    subchoice = input("Choose an option: ")
                    
                    if subchoice == "1":
                        service = input("Enter service name: ")
                        service_username = input("Enter username for service: ")
                        service_password = getpass.getpass("Enter password for service: ")
                        
                        if pm.store_password(user_id, service, service_username, service_password):
                            print("Password stored successfully!")
                        else:
                            print("Error storing password!")
                            
                    elif subchoice == "2":
                        service = input("Enter service name: ")
                        result = pm.get_password(user_id, service)
                        
                        if result:
                            username, password = result
                            print(f"Username: {username}")
                            print(f"Password: {password}")
                        else:
                            print("Service not found!")
                            
                    elif subchoice == "3":
                        services = pm.list_services(user_id)
                        if services:
                            print("\nStored Services:")
                            for service, username, created_at in services:
                                print(f"Service: {service}, Username: {username}, Created: {created_at}")
                        else:
                            print("No stored passwords!")
                            
                    elif subchoice == "4":
                        service = input("Enter service name: ")
                        if pm.delete_password(user_id, service):
                            print("Password deleted successfully!")
                        else:
                            print("Service not found!")
                            
                    elif subchoice == "5":
                        break
            else:
                print("Authentication failed!")
                
        elif choice == "3":
            break

if __name__ == "__main__":
    main()