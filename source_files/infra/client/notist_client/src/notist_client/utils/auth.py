from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import base64


class AuthManager:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password with a random salt using PBKDF2."""
        if not password:
            raise ValueError("Password cannot be empty.")
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        hashed_password = kdf.derive(password.encode())
        # Combine salt and hashed password for storage
        return base64.b64encode(salt + hashed_password).decode("utf-8")

    @staticmethod
    def verify_password(stored_hashed_pw: str, input_password: str) -> bool:
        """Verify an input password against a stored hashed password."""
        try:
            if not input_password:
                raise ValueError("Password cannot be empty.")
            decoded_data = base64.b64decode(stored_hashed_pw)
            salt = decoded_data[:16]  # Extract the salt
            stored_hash = decoded_data[16:]  # Extract the stored hash

            kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )

            # Verify if the input password generates the same hash
            kdf.verify(input_password.encode(), stored_hash)
            return True
        except Exception:
            raise ValueError("Password verification failed.")
