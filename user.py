"""
user.py — User Authentication
==============================
Handles master password setup, validation, and login verification.
Uses hashlib.scrypt for secure password hashing with a random salt.
"""

import os
import json
import hashlib
import getpass
import re

# Path to the master key file
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MASTER_KEY_FILE = os.path.join(DATA_DIR, "master.key")


class User:
    """
    Manages the master password lifecycle:
    - First-time setup with strength validation
    - Login verification with attempt limiting
    - Master password change
    """

    # Scrypt parameters (CPU/memory cost, block size, parallelization)
    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1
    SCRYPT_DKLEN = 64

    MAX_LOGIN_ATTEMPTS = 3

    def __init__(self):
        """Initialize user module and ensure data directory exists."""
        os.makedirs(DATA_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Password Strength Validation
    # ------------------------------------------------------------------ #

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, list[str]]:
        """
        Validate that a master password meets minimum security requirements.

        Requirements:
        - At least 8 characters long
        - Contains at least one uppercase letter
        - Contains at least one lowercase letter
        - Contains at least one digit
        - Contains at least one special character

        Args:
            password: The password string to validate.

        Returns:
            A tuple of (is_valid, list_of_issues).
        """
        issues = []

        if len(password) < 8:
            issues.append("Must be at least 8 characters long")
        if not re.search(r"[A-Z]", password):
            issues.append("Must contain at least one uppercase letter (A-Z)")
        if not re.search(r"[a-z]", password):
            issues.append("Must contain at least one lowercase letter (a-z)")
        if not re.search(r"\d", password):
            issues.append("Must contain at least one digit (0-9)")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", password):
            issues.append("Must contain at least one special character (!@#$%^&*...)")

        return (len(issues) == 0, issues)

    # ------------------------------------------------------------------ #
    #  Hashing
    # ------------------------------------------------------------------ #

    def _hash_password(self, password: str, salt: bytes) -> str:
        """
        Hash a password using scrypt with the given salt.

        Args:
            password: The plaintext password.
            salt: A random salt (16 bytes).

        Returns:
            The hex-encoded hash string.
        """
        hashed = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
            dklen=self.SCRYPT_DKLEN,
        )
        return hashed.hex()

    # ------------------------------------------------------------------ #
    #  Setup & Login
    # ------------------------------------------------------------------ #

    def is_setup_complete(self) -> bool:
        """Check if a master password has been configured."""
        return os.path.exists(MASTER_KEY_FILE)

    def setup_master_password(self) -> bool:
        """
        Interactive first-time master password setup.

        Prompts the user to create and confirm a master password.
        Validates password strength before saving.

        Returns:
            True if setup was successful, False otherwise.
        """
        from main import Colors  # Import here to avoid circular import at module level

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  🔐  MASTER PASSWORD SETUP")
        print(f"{'═' * 50}{Colors.RESET}\n")
        print(f"{Colors.DIM}  Your master password protects all stored credentials.")
        print(f"  Choose a strong password you can remember.{Colors.RESET}\n")

        while True:
            password = getpass.getpass(f"  {Colors.YELLOW}Enter master password: {Colors.RESET}")

            # Validate strength
            is_valid, issues = self.validate_password_strength(password)
            if not is_valid:
                print(f"\n  {Colors.RED}⚠  Password does not meet requirements:{Colors.RESET}")
                for issue in issues:
                    print(f"     {Colors.RED}• {issue}{Colors.RESET}")
                print()
                continue

            # Confirm password
            confirm = getpass.getpass(f"  {Colors.YELLOW}Confirm master password: {Colors.RESET}")
            if password != confirm:
                print(f"\n  {Colors.RED}⚠  Passwords do not match. Try again.{Colors.RESET}\n")
                continue

            # Save hashed password
            salt = os.urandom(16)
            hashed = self._hash_password(password, salt)

            key_data = {
                "salt": salt.hex(),
                "hash": hashed,
            }

            with open(MASTER_KEY_FILE, "w") as f:
                json.dump(key_data, f, indent=2)

            print(f"\n  {Colors.GREEN}✅  Master password set successfully!{Colors.RESET}")
            return True

    def verify_password(self, password: str) -> bool:
        """
        Verify a password against the stored master password hash.

        Args:
            password: The password to verify.

        Returns:
            True if the password matches, False otherwise.
        """
        if not self.is_setup_complete():
            return False

        with open(MASTER_KEY_FILE, "r") as f:
            key_data = json.load(f)

        salt = bytes.fromhex(key_data["salt"])
        stored_hash = key_data["hash"]
        computed_hash = self._hash_password(password, salt)

        return computed_hash == stored_hash

    def login(self) -> tuple[bool, str]:
        """
        Interactive login prompt with attempt limiting.

        Returns:
            A tuple of (success: bool, password: str).
            If login fails, password will be an empty string.
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  🔑  LOGIN")
        print(f"{'═' * 50}{Colors.RESET}\n")

        for attempt in range(1, self.MAX_LOGIN_ATTEMPTS + 1):
            remaining = self.MAX_LOGIN_ATTEMPTS - attempt
            password = getpass.getpass(
                f"  {Colors.YELLOW}Enter master password ({attempt}/{self.MAX_LOGIN_ATTEMPTS}): {Colors.RESET}"
            )

            if self.verify_password(password):
                print(f"\n  {Colors.GREEN}✅  Login successful!{Colors.RESET}")
                return True, password

            if remaining > 0:
                print(f"  {Colors.RED}✗  Incorrect password. {remaining} attempt(s) remaining.{Colors.RESET}\n")
            else:
                print(f"\n  {Colors.RED}🔒  Too many failed attempts. Access denied.{Colors.RESET}")

        return False, ""

    def change_master_password(self, current_password: str, vault) -> tuple[bool, str]:
        """
        Change the master password. Re-encrypts the vault with the new password.

        Args:
            current_password: The current valid master password.
            vault: The Vault instance (to re-encrypt stored data).

        Returns:
            A tuple of (success: bool, new_password: str).
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  🔄  CHANGE MASTER PASSWORD")
        print(f"{'═' * 50}{Colors.RESET}\n")

        # Verify current password
        verify = getpass.getpass(f"  {Colors.YELLOW}Enter current master password: {Colors.RESET}")
        if not self.verify_password(verify):
            print(f"\n  {Colors.RED}✗  Current password is incorrect.{Colors.RESET}")
            return False, current_password

        # Get new password
        while True:
            new_password = getpass.getpass(f"  {Colors.YELLOW}Enter new master password: {Colors.RESET}")

            is_valid, issues = self.validate_password_strength(new_password)
            if not is_valid:
                print(f"\n  {Colors.RED}⚠  Password does not meet requirements:{Colors.RESET}")
                for issue in issues:
                    print(f"     {Colors.RED}• {issue}{Colors.RESET}")
                print()
                continue

            confirm = getpass.getpass(f"  {Colors.YELLOW}Confirm new master password: {Colors.RESET}")
            if new_password != confirm:
                print(f"\n  {Colors.RED}⚠  Passwords do not match. Try again.{Colors.RESET}\n")
                continue

            break

        # Re-encrypt vault with new password
        try:
            entries = vault.load(current_password)
            vault.save(entries, new_password)
        except Exception as e:
            print(f"\n  {Colors.RED}✗  Failed to re-encrypt vault: {e}{Colors.RESET}")
            return False, current_password

        # Save new master password hash
        salt = os.urandom(16)
        hashed = self._hash_password(new_password, salt)

        key_data = {
            "salt": salt.hex(),
            "hash": hashed,
        }

        with open(MASTER_KEY_FILE, "w") as f:
            json.dump(key_data, f, indent=2)

        print(f"\n  {Colors.GREEN}✅  Master password changed successfully!{Colors.RESET}")
        return True, new_password
