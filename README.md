# 🔐 Secure Vault — Password Manager with Encryption

A professional terminal-based password manager built with Python. All credentials are encrypted using **AES (Fernet)** and protected by a master password hashed with **scrypt**.

---

## 📋 Features

| Feature | Description |
|---|---|
| **Master Password Auth** | Login with a master password (hashed with scrypt, never stored in plaintext) |
| **AES Encryption** | All passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before saving |
| **PBKDF2 Key Derivation** | Encryption key is derived from your master password with 480,000 iterations |
| **Add Credentials** | Store service name, username, and password |
| **View Credentials** | View all stored credentials with masked or revealed passwords |
| **Search** | Case-insensitive search by service name or username |
| **Update** | Modify username or password for existing credentials |
| **Delete** | Remove credentials with confirmation |
| **Password Generator** | Generate cryptographically secure passwords with configurable options |
| **Strength Meter** | Visual password strength evaluation |
| **Colored CLI** | Polished terminal UI with ANSI colors and emoji icons |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or later
- pip (Python package manager)

### Installation

```bash
# 1. Navigate to the project directory
cd "TEST 5 PASSWORD"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python main.py
```

### First Run

On first launch, the app will prompt you to create a **master password**. This password must meet the following requirements:

- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character (!@#$%^&*...)

> ⚠️ **Important**: If you forget your master password, there is no way to recover your stored credentials. The encryption is one-way.

---

## 🗂️ Project Structure

```
TEST 5 PASSWORD/
├── main.py              # Entry point: CLI menu and app loop
├── user.py              # User class: master password setup & login
├── vault.py             # Vault class: AES encryption/decryption engine
├── manager.py           # PasswordManager class: CRUD operations
├── generator.py         # Password generator with strength evaluation
├── requirements.txt     # External dependency: cryptography
├── README.md            # This file
└── data/                # Created at runtime (auto-generated)
    ├── master.key       # Scrypt hash of master password (salt + hash)
    └── vault.enc        # AES-encrypted credentials (salt + Fernet token)
```

---

## 🧩 Python Concepts Used

| Concept | Where |
|---|---|
| **OOP (Classes)** | `User`, `Vault`, `PasswordManager`, `PasswordGenerator` |
| **File Handling** | JSON read/write in `vault.py` and `user.py` |
| **Encryption** | Fernet (AES) in `vault.py`, scrypt in `user.py` |
| **Modules** | `os`, `json`, `hashlib`, `base64`, `secrets`, `getpass`, `cryptography` |
| **Authentication** | Master password login with attempt limiting |
| **CRUD Operations** | Add, View, Search, Update, Delete credentials |
| **Password Generation** | Cryptographically secure generation with `secrets` |

---

## 🔒 Security Design

| Layer | Mechanism |
|---|---|
| Master password storage | `hashlib.scrypt` (N=16384, r=8, p=1) with 16-byte random salt |
| Vault encryption key | Derived via `PBKDF2HMAC` (SHA-256, 480,000 iterations) |
| Vault encryption | `Fernet` — AES-128-CBC with HMAC-SHA256 (authenticated encryption) |
| Password generation | `secrets` module (OS-level CSPRNG) |
| Input masking | `getpass` module hides terminal input |

---

## 📸 Usage

```
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║   🔐  S E C U R E   V A U L T                   ║
    ║       Password Manager v1.0                      ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝

  ──────────────────────────────────────────────
    MAIN MENU
  ──────────────────────────────────────────────

    1.  ➕  Add New Credential
    2.  📋  View All Credentials
    3.  🔍  Search Credentials
    4.  ✏️   Update a Credential
    5.  🗑️   Delete a Credential
    6.  🎲  Generate a Password
    7.  🔄  Change Master Password
    0.  🚪  Exit
```

---

## 📄 License

This project is for educational purposes. Feel free to use and modify.
