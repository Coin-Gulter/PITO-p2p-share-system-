# p2pshare/shared/security_manager.py

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
from pathlib import Path
import base64
import logging

logger = logging.getLogger(__name__)

# Constants for key derivation and encryption
SALT_SIZE = 16
ITERATIONS = 100000 # Number of PBKDF2 iterations, higher is more secure but slower
KEY_LENGTH = 32     # For AES-256 (32 bytes)
IV_LENGTH = 16      # For AES-CBC (16 bytes)
SECURITY_FILE_NAME = "security_info.json"

class SecurityManager:
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.security_file_path = self.config_dir / SECURITY_FILE_NAME
        self._encryption_key = None # Store the derived key in memory

    def _generate_salt(self) -> bytes:
        """Generates a random salt for PBKDF2."""
        return os.urandom(SALT_SIZE)

    def _derive_key(self, password: str, salt: bytes, iterations: int) -> bytes:
        """Derives a cryptographic key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def _hash_password_for_storage(self, password: str, salt: bytes, iterations: int) -> str:
        """Hashes the password for storage comparison (not for encryption directly)."""
        hashed_bytes = self._derive_key(password, salt, iterations) # Use the same KDF process
        return base64.b64encode(hashed_bytes).decode('utf-8')

    def initialize_security(self, password: str):
        """
        Initializes security for the first time, generates salt, derives key,
        and saves security info.
        """
        if self.security_file_path.exists():
            logger.warning("Security already initialized. Overwriting.")

        salt = self._generate_salt()
        iterations = ITERATIONS # Use predefined iterations
        
        # Derive the key for the current session
        self._encryption_key = self._derive_key(password, salt, iterations)
        
        # Hash a representation of the password for verification later, NOT the actual key
        # Using the same KDF parameters ensures consistency
        stored_password_hash = self._hash_password_for_storage(password, salt, iterations)

        security_info = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "iterations": iterations,
            "password_hash": stored_password_hash # This is the hash, not the key
        }

        try:
            with open(self.security_file_path, 'w') as f:
                json.dump(security_info, f)
            logger.info(f"Security initialized and info saved to {self.security_file_path}")
            return True
        except IOError as e:
            logger.error(f"Failed to save security info to {self.security_file_path}: {e}")
            self._encryption_key = None # Clear key if save fails
            return False

    def load_security(self, password: str) -> bool:
        """
        Loads security information and derives the encryption key based on the provided password.
        Returns True if password is correct and key is derived, False otherwise.
        """
        if not self.security_file_path.exists():
            logger.error("Security file not found. Security not initialized.")
            return False

        try:
            with open(self.security_file_path, 'r') as f:
                security_info = json.load(f)

            salt = base64.b64decode(security_info["salt"])
            iterations = security_info["iterations"]
            stored_password_hash = security_info["password_hash"]

            # Derive key from provided password
            derived_key = self._derive_key(password, salt, iterations)
            current_password_hash = base64.b64encode(derived_key).decode('utf-8')

            if current_password_hash == stored_password_hash:
                self._encryption_key = derived_key
                logger.info("Security loaded successfully. Encryption key derived.")
                return True
            else:
                logger.warning("Incorrect password provided for security.")
                self._encryption_key = None
                return False
        except (IOError, KeyError, json.JSONDecodeError) as e:
            logger.error(f"Error loading security info from {self.security_file_path}: {e}")
            self._encryption_key = None
            return False
    
    def get_encryption_key(self) -> bytes | None:
        """Returns the derived encryption key if loaded, otherwise None."""
        if self._encryption_key is None:
            logger.warning("Encryption key not loaded. Files cannot be processed securely.")
        return self._encryption_key

    def get_stored_hash_b64(self) -> str | None:
        """Returns the base64 encoded stored password hash for display."""
        if not self.security_file_path.exists():
            return None
        try:
            with open(self.security_file_path, 'r') as f:
                security_info = json.load(f)
                return security_info.get("password_hash")
        except (IOError, KeyError, json.JSONDecodeError) as e:
            logger.error(f"Error reading password hash from security file: {e}")
            return None

    def change_password(self, old_password: str, new_password: str) -> bool:
        """Changes the security password and updates the security file."""
        if not self.load_security(old_password): # Verify old password
            logger.warning("Failed to change password: old password incorrect.")
            return False
        
        # Initialize with new password (this will generate new salt and update info)
        return self.initialize_security(new_password)

    def is_initialized(self) -> bool:
        """Checks if the security file exists."""
        return self.security_file_path.exists()

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypts data using AES-CBC. Prepends IV to ciphertext."""
        if self._encryption_key is None:
            raise ValueError("Encryption key not loaded. Cannot encrypt data.")

        iv = os.urandom(IV_LENGTH)
        cipher = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the data to be a multiple of the block size (16 bytes for AES)
        padder = modes.CBC.padding_algorithm.pkcs7.padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext # Prepend IV for decryption

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypts data using AES-CBC. Expects IV prepended to ciphertext."""
        if self._encryption_key is None:
            raise ValueError("Encryption key not loaded. Cannot decrypt data.")
        if len(encrypted_data) < IV_LENGTH:
            raise ValueError("Encrypted data too short to contain IV.")

        iv = encrypted_data[:IV_LENGTH]
        ciphertext = encrypted_data[IV_LENGTH:]

        cipher = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad the data
        unpadder = modes.CBC.padding_algorithm.pkcs7.unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return data

