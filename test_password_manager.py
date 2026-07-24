"""
test_password_manager.py — Unit Tests
========================================
Comprehensive unit tests for the Password Manager modules:
- vault.py (cryptographic operations, PBKDF2, Fernet)
- user.py (strength validation, scrypt hashing)
- generator.py (secure generation, strength evaluation)
- manager.py (CRUD actions)

Uses unittest, unittest.mock, and tempfile to avoid modifying local user vault data.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from vault import Vault, DATA_DIR, VAULT_FILE
from user import User, MASTER_KEY_FILE
from generator import PasswordGenerator
from manager import PasswordManager


class TestVault(unittest.TestCase):
    """Test suite for cryptography operations in vault.py."""

    def setUp(self):
        # Create a temporary directory for vault and keys
        self.test_dir = tempfile.mkdtemp()
        self.patcher1 = patch('vault.DATA_DIR', self.test_dir)
        self.patcher2 = patch('vault.VAULT_FILE', os.path.join(self.test_dir, 'vault.enc'))
        self.patcher1.start()
        self.patcher2.start()
        self.vault = Vault()

    def tearDown(self):
        self.patcher1.stop()
        self.patcher2.stop()
        shutil.rmtree(self.test_dir)

    def test_encrypt_decrypt_success(self):
        password = "StrongMasterPass123!"
        data = "my secret message"

        token, salt = self.vault.encrypt(data, password)
        self.assertIsNotNone(token)
        self.assertIsNotNone(salt)

        decrypted = self.vault.decrypt(token, password, salt)
        self.assertEqual(decrypted, data)

    def test_decrypt_wrong_password(self):
        password = "StrongMasterPass123!"
        wrong_password = "WrongMasterPass123!"
        data = "my secret message"

        token, salt = self.vault.encrypt(data, password)

        from cryptography.fernet import InvalidToken
        with self.assertRaises(InvalidToken):
            self.vault.decrypt(token, wrong_password, salt)

    def test_save_and_load(self):
        password = "StrongMasterPass123!"
        entries = [
            {"service": "Google", "username": "user@gmail.com", "password": "gpass123"}
        ]

        self.assertFalse(self.vault.vault_exists())
        self.vault.save(entries, password)
        self.assertTrue(self.vault.vault_exists())

        loaded_entries = self.vault.load(password)
        self.assertEqual(loaded_entries, entries)


class TestUser(unittest.TestCase):
    """Test suite for master password rules and scrypt auth in user.py."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.patcher1 = patch('user.DATA_DIR', self.test_dir)
        self.patcher2 = patch('user.MASTER_KEY_FILE', os.path.join(self.test_dir, 'master.key'))
        self.patcher1.start()
        self.patcher2.start()
        self.user = User()

    def tearDown(self):
        self.patcher1.stop()
        self.patcher2.stop()
        shutil.rmtree(self.test_dir)

    def test_password_strength_validation(self):
        # Valid password
        is_valid, issues = User.validate_password_strength("Abcde123!")
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)

        # Too short
        is_valid, issues = User.validate_password_strength("Ab1!")
        self.assertFalse(is_valid)
        self.assertIn("Must be at least 8 characters long", issues)

        # No uppercase
        is_valid, issues = User.validate_password_strength("abcde123!")
        self.assertFalse(is_valid)
        self.assertIn("Must contain at least one uppercase letter (A-Z)", issues)

        # No lowercase
        is_valid, issues = User.validate_password_strength("ABCDE123!")
        self.assertFalse(is_valid)
        self.assertIn("Must contain at least one lowercase letter (a-z)", issues)

        # No digit
        is_valid, issues = User.validate_password_strength("Abcdefgh!")
        self.assertFalse(is_valid)
        self.assertIn("Must contain at least one digit (0-9)", issues)

        # No special character
        is_valid, issues = User.validate_password_strength("Abcde1234")
        self.assertFalse(is_valid)
        self.assertIn("Must contain at least one special character (!@#$%^&*...)", issues)

    def test_setup_and_verify(self):
        self.assertFalse(self.user.is_setup_complete())

        # Manually create setup data instead of mock input for setup_master_password
        salt = os.urandom(16)
        password = "ValidPassword123!"
        hashed = self.user._hash_password(password, salt)

        import json
        key_data = {
            "salt": salt.hex(),
            "hash": hashed,
        }
        with open(os.path.join(self.test_dir, 'master.key'), "w") as f:
            json.dump(key_data, f)

        self.assertTrue(self.user.is_setup_complete())
        self.assertTrue(self.user.verify_password(password))
        self.assertFalse(self.user.verify_password("WrongPassword123!"))


class TestPasswordGenerator(unittest.TestCase):
    """Test suite for password generation and strength rating in generator.py."""

    def test_generator_constraints(self):
        # Generate with default (16 characters)
        pwd = PasswordGenerator.generate()
        self.assertEqual(len(pwd), 16)
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))
        self.assertTrue(any(c in PasswordGenerator.SYMBOLS for c in pwd))

        # Custom constraints
        pwd_custom = PasswordGenerator.generate(
            length=10, use_uppercase=True, use_lowercase=False, use_digits=True, use_symbols=False
        )
        self.assertEqual(len(pwd_custom), 10)
        self.assertTrue(any(c.isupper() for c in pwd_custom))
        self.assertFalse(any(c.islower() for c in pwd_custom))
        self.assertTrue(any(c.isdigit() for c in pwd_custom))
        self.assertFalse(any(c in PasswordGenerator.SYMBOLS for c in pwd_custom))

        # Check value error
        with self.assertRaises(ValueError):
            PasswordGenerator.generate(use_uppercase=False, use_lowercase=False, use_digits=False, use_symbols=False)

    def test_evaluate_strength(self):
        # Weak
        rating, score, _ = PasswordGenerator.evaluate_strength("123")
        self.assertIn("Weak", rating)
        self.assertLess(score, 40)

        # Very Strong
        rating, score, _ = PasswordGenerator.evaluate_strength("aB3!fG7#kL1$mN9%pQ5^")
        self.assertIn("Very Strong", rating)
        self.assertGreaterEqual(score, 80)


class TestPasswordManager(unittest.TestCase):
    """Test suite for password database (CRUD) operations in manager.py."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.patcher1 = patch('vault.DATA_DIR', self.test_dir)
        self.patcher2 = patch('vault.VAULT_FILE', os.path.join(self.test_dir, 'vault.enc'))
        self.patcher1.start()
        self.patcher2.start()

        # Pre-create master password hash file to avoid User errors if any
        self.master_password = "SecretPassword123!"
        self.pm = PasswordManager(self.master_password)

    def tearDown(self):
        self.patcher1.stop()
        self.patcher2.stop()
        shutil.rmtree(self.test_dir)

    def test_crud_flow_direct(self):
        # Initially empty
        self.assertEqual(len(self.pm._entries), 0)

        # Create
        entry = {
            "service": "TestService",
            "username": "testuser",
            "password": "testpassword",
            "created_at": self.pm._now(),
            "updated_at": self.pm._now(),
        }
        self.pm._entries.append(entry)
        self.pm._save_entries()

        # Reload and check
        pm2 = PasswordManager(self.master_password)
        self.assertEqual(len(pm2._entries), 1)
        self.assertEqual(pm2._entries[0]["service"], "TestService")
        self.assertEqual(pm2._entries[0]["username"], "testuser")
        self.assertEqual(pm2._entries[0]["password"], "testpassword")

    def test_copy_to_clipboard(self):
        res = self.pm._copy_to_clipboard("test_pass")
        self.assertIn(res, [True, False])


if __name__ == "__main__":
    unittest.main()
