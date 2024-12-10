import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode


class SecureNotesLibrary:
    def __init__(self):
        self.backend = default_backend()

    def _derive_key(self, password, salt, length=32):
        """Derives a cryptographic key from the password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
            backend=self.backend,
        )
        return kdf.derive(password.encode())

    def _encrypt(self, plaintext, key):
        """Encrypts data using AES-CBC with PKCS7 padding."""
        iv = os.urandom(16)  # 128-bit IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Add PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext

    def _decrypt(self, iv, ciphertext, key):
        """Decrypts data using AES-CBC and removes padding."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

    def protect(self, input_file, key, output_file, config_file):
        """Encrypts the file, generates a file hash, and saves config."""
        # Read the input file
        with open(input_file, "rb") as f:
            data = f.read()

        # Generate the file hash
        file_hash = hashlib.sha256(data).digest()

        # Encrypt the file
        salt = os.urandom(16)  # Generate salt for key derivation
        derived_key = self._derive_key(key, salt)
        iv, ciphertext = self._encrypt(data, derived_key)

        # Save the encrypted file
        with open(output_file, "wb") as f:
            f.write(salt + iv + ciphertext)

        # Save the file hash in the config file
        config_data = {"file_hash": urlsafe_b64encode(file_hash).decode()}
        with open(config_file, "w") as f:
            json.dump(config_data, f)

    def check(self, input_file, config_file):
        """Checks the integrity of an unprotected file using its hash."""
        # Read the unprotected file
        with open(input_file, "rb") as f:
            data = f.read()

        # Compute the hash of the unprotected file
        file_hash = hashlib.sha256(data).digest()

        # Read the stored hash from the config file
        with open(config_file, "r") as f:
            config_data = json.load(f)

        # Validate the file hash
        if urlsafe_b64encode(file_hash).decode() != config_data["file_hash"]:
            raise ValueError("File integrity check failed: hash mismatch.")

        print("File integrity verified successfully.")

    def unprotect(self, input_file, key, output_file):
        """Decrypts the file."""
        # Read the encrypted file
        with open(input_file, "rb") as f:
            data = f.read()

        # Extract salt, iv, and ciphertext
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        # Derive the key
        derived_key = self._derive_key(key, salt)

        # Decrypt the data
        plaintext = self._decrypt(iv, ciphertext, derived_key)

        # Save the decrypted file
        with open(output_file, "wb") as f:
            f.write(plaintext)


lib = SecureNotesLibrary()
# lib.protect("test.json", "your-password", "notes.enc", "config.json")
# lib.unprotect("notes.enc", "your-password", "notes_decrypted.json")
lib.check("notes_decrypted.txt", "config.json")
