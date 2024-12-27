from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes as crypto_hashes


class KeyManager:
    """Handles cryptographic key operations including generation, storage, and loading."""

    @staticmethod
    def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generates a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

    @staticmethod
    def load_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        """Derives the public key from a private key."""
        return private_key.public_key()

    @staticmethod
    def encrypt_with_master_key(data: bytes, master_key: bytes) -> bytes:
        """Encrypt data (e.g., private key, symmetric key) using AES GCM and master key."""
        # Generate a salt and derive an AES key from the master key
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        encryption_key = kdf.derive(master_key)

        # Encrypt the data using AES GCM
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(salt), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Return salt + encrypted data + tag (for AES GCM)
        return salt + encrypted_data + encryptor.tag

    @staticmethod
    def decrypt_with_master_key(encrypted_data: bytes, master_key: bytes) -> bytes:
        """Decrypt data (e.g., private key, symmetric key) using AES GCM and master key."""
        salt = encrypted_data[:16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]

        # Derive the AES decryption key from the master key
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        decryption_key = kdf.derive(master_key)

        # Decrypt the data using AES GCM
        cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(salt, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def store_private_key(
        private_key: rsa.RSAPrivateKey, private_key_path: str, master_key: bytes
    ) -> None:
        """Stores the RSA private key in an encrypted format."""
        if not os.path.exists(os.path.dirname(private_key_path)):
            os.makedirs(os.path.dirname(private_key_path))

        # Convert the private key to PEM format (unencrypted)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),  # Unencrypted for initial conversion
        )

        # Encrypt the private key using the master key
        encrypted_private_key = KeyManager.encrypt_with_master_key(private_key_pem, master_key)

        with open(private_key_path, "wb") as key_file:
            key_file.write(encrypted_private_key)

        print(
            f"Private key stored at: {private_key_path}.\n"
            "Do not share, change, or edit this file's contents nor location "
            "or YOU WILL LOSE ACCESS TO YOUR ACCOUNT.\n"
        )

    @staticmethod
    def load_private_key(private_key_path: str, master_key: bytes) -> rsa.RSAPrivateKey:
        """Loads and decrypts an RSA private key from a file using the master key."""
        try:
            with open(private_key_path, "rb") as key_file:
                encrypted_private_key = key_file.read()

            # Decrypt the private key using the master key
            private_key_pem = KeyManager.decrypt_with_master_key(encrypted_private_key, master_key)

            # Deserialize the private key from PEM format
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
            print(f"private key: {private_key}")
            return private_key

        except Exception as e:
            raise Exception(f"Failed to load or decrypt the private key: {e}")

    @classmethod
    def generate_key_pair(
        cls, private_key_path: str, master_key: bytes
    ) -> rsa.RSAPublicKey:
        """Generates and stores a new key pair, returning the public key."""
        private_key = cls.generate_private_key()
        public_key = cls.load_public_key(private_key)
        cls.store_private_key(private_key, private_key_path, master_key)
        return public_key

    @staticmethod
    def get_public_key_json_serializable(public_key: rsa.RSAPublicKey) -> str:
        """Converts an RSA public key to a JSON-serializable format."""
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(public_key_bytes).decode("utf-8")

    @staticmethod
    def generate_symmetric_key() -> bytes:
        """Generates a new random 256-bit symmetric encryption key."""
        return os.urandom(32)

    @staticmethod
    def encrypt_symmetric_key(symmetric_key: bytes, master_key: bytes) -> bytes:
        """Encrypts the symmetric key using the master key."""
        return KeyManager.encrypt_with_master_key(symmetric_key, master_key)

    @staticmethod
    def decrypt_symmetric_key(encrypted_symmetric_key: bytes, master_key: bytes) -> bytes:
        """Decrypts the symmetric key using the master key."""
        return KeyManager.decrypt_with_master_key(encrypted_symmetric_key, master_key)

    @staticmethod
    def derive_master_key(password: str) -> bytes:
        """
        Derives a master key from a string password using PBKDF2.

        Args:
            password: String password to derive key from

        Returns:
            bytes: 32-byte derived key
        """
        salt = b"password"  # In production, this should be unique per user
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))
