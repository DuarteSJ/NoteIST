from typing import Dict, Any
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os


class SecureHandler:
    """Handles secure operations like signing and verifying data."""

    @staticmethod
    def sign_request(request_data: Dict[str, Any], private_key) -> str:
        """Signs request data with a private key."""
        try:
            serialized_data = json.dumps(
                request_data, separators=(",", ":"), sort_keys=True
            )
            signature = private_key.sign(
                serialized_data.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            raise Exception(f"Error signing request: {e}")

    @staticmethod
    def create_unsigned_payload(
        req_type: str, username: str, request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates an unsigned request payload."""
        return {
            "type": req_type,
            "username": username,
            "data": request_data,
        }

    @staticmethod
    def create_signed_payload(
        req_type: str, username: str, request_data: Dict[str, Any], signature: str
    ) -> Dict[str, Any]:
        """Creates a signed request payload."""
        return {
            "type": req_type,
            "username": username,
            "signature": signature,
            "data": request_data,
        }

    @staticmethod
    def encrypt_string(plaintext: str, key) -> str:
        """
        Encrypts a string using a derived master key from the password.

        Args:
            plaintext: The string to encrypt.
            password: The password to derive the master key.

        Returns:
            str: The encrypted string (base64 encoded).
        """
        # Generate a random 16-byte IV (Initialization Vector)
        iv = os.urandom(16)

        # Pad the plaintext to make it a multiple of block size (16 bytes for AES)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        # Create AES cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and encrypted data, then encode as base64
        encrypted_string = base64.b64encode(iv + encrypted_data).decode("utf-8")

        return encrypted_string

    @staticmethod
    def decrypt_string(encrypted_string: str, key) -> str:
        """
        Decrypts a string using a derived master key from the password.

        Args:
            encrypted_string: The base64 encoded string to decrypt.
            password: The password to derive the master key.

        Returns:
            str: The decrypted string.
        """

        # Decode the base64 encoded encrypted string
        encrypted_data = base64.b64decode(encrypted_string)

        # Extract the IV (first 16 bytes) and the encrypted data
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

        # Create AES cipher object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode("utf-8")
