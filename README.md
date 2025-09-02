 🔒 Password Manager & Secure Vault

A secure desktop password manager built with Python. It uses **AES-256 encryption** to safeguard your data, requiring only one master password for access. Your passwords are stored locally in a MySQL database, ensuring privacy and control.

 ✨ Features

- Military-Grade Encryption:** All data is secured with AES-256.
- Master Password:** One password to access your entire vault.
- Intuitive GUI:** User-friendly interface built with Tkinter.
- Password Generator:** Create strong, random passwords instantly.
- Clipboard Autoclear:** Copies passwords safely and clears clipboard after a delay.
- MySQL Integration:** Efficient and secure local storage.

 🛠️ Tech Stack

Python | Tkinter(GUI) | MySQL(Database) | Pandas(Data Handling) | PyCryptodome(AES-256 Encryption)

## 🚀 Getting Started

 Prerequisites
- Python 3.8+
- MySQL Server

 Installation
1.  Clone the repo and navigate into it:
    ```bash
    git clone https://github.com/your-username/password-manager.git
    cd password-manager
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Set up the MySQL database using the `schema.sql` file.
4.  Run the application:
    ```bash
    python main.py
    ```


---
💡Note: This is a local application. You are responsible for remembering your master password and keeping your database safe.

Developed by [Nirjhar Chatterjee](https://linkedin.com/in/nirjhar-chatterjee)**
