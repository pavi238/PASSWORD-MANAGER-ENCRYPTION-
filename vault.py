"""
vault.py — Encryption Engine
=============================
Handles all cryptographic operations for the Password Manager.
Uses Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption
and PBKDF2HMAC for key derivation from the master password.
"""

import os
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Directory where encrypted data files are stored
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
VAULT_FILE = os.path.join(DATA_DIR, "vault.enc")


class Vault:
    """
    Encryption vault that handles encrypting/decrypting credential data.

    The vault uses a two-layer security model:
    1. A random 16-byte salt is generated per encryption operation.
    2. PBKDF2HMAC derives a 256-bit key from (master_password + salt).
    3. Fernet encrypts the plaintext JSON with the derived key.
    4. The salt and encrypted token are stored together in a JSON file.
    """

    ITERATIONS = 480_000  # PBKDF2 iteration count (OWASP recommendation)

    def __init__(self):
        """Initialize the vault and ensure the data directory exists."""
        os.makedirs(DATA_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Core Cryptographic Methods
    # ------------------------------------------------------------------ #

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive a Fernet-compatible key from a password and salt
        using PBKDF2HMAC with SHA-256.

        Args:
            password: The master password string.
            salt: A 16-byte random salt.

        Returns:
            A 32-byte URL-safe base64-encoded key suitable for Fernet.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=Vault.ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt(self, plaintext: str, password: str) -> tuple[bytes, bytes]:
        """
        Encrypt a plaintext string using a password-derived key.

        Args:
            plaintext: The string to encrypt (typically JSON).
            password: The master password.

        Returns:
            A tuple of (encrypted_token, salt).
        """
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        token = fernet.encrypt(plaintext.encode())
        return token, salt

    def decrypt(self, token: bytes, password: str, salt: bytes) -> str:
        """
        Decrypt an encrypted token using a password-derived key.

        Args:
            token: The encrypted Fernet token.
            password: The master password.
            salt: The salt that was used during encryption.

        Returns:
            The decrypted plaintext string.

        Raises:
            InvalidToken: If the password is wrong or data is corrupted.
        """
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        plaintext = fernet.decrypt(token)
        return plaintext.decode()

    # ------------------------------------------------------------------ #
    #  File I/O Methods
    # ------------------------------------------------------------------ #

    def save(self, entries: list[dict], password: str) -> None:
        """
        Encrypt the credential entries and write them to the vault file.

        The file format is JSON:
        {
            "salt": "<base64-encoded salt>",
            "token": "<base64-encoded encrypted token>"
        }

        Args:
            entries: List of credential dictionaries.
            password: The master password for encryption.
        """
        plaintext = json.dumps(entries, indent=2)
        token, salt = self.encrypt(plaintext, password)

        vault_data = {
            "salt": base64.b64encode(salt).decode(),
            "token": token.decode(),
        }

        with open(VAULT_FILE, "w") as f:
            json.dump(vault_data, f, indent=2)

    def load(self, password: str) -> list[dict]:
        """
        Read the vault file, decrypt it, and return the credential entries.

        Args:
            password: The master password for decryption.

        Returns:
            A list of credential dictionaries. Returns an empty list if
            the vault file does not exist.

        Raises:
            InvalidToken: If the master password is incorrect.
        """
        if not os.path.exists(VAULT_FILE):
            return []

        with open(VAULT_FILE, "r") as f:
            vault_data = json.load(f)

        salt = base64.b64decode(vault_data["salt"])
        token = vault_data["token"].encode()

        plaintext = self.decrypt(token, password, salt)
        entries = json.loads(plaintext)
        return entries

    def vault_exists(self) -> bool:
        """Check whether a vault file already exists on disk."""
        return os.path.exists(VAULT_FILE)
