from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import padding


class KeyManager:
    """Handles cryptographic key operations including generation, storage, and loading."""

    def __init__(self, password: str, username: str):
        self.master_key = self.derive_master_key(password, username)

    # -------------------------------------
    # Master Key Functions
    # -------------------------------------
    def derive_master_key(self, password: str, username: str) -> bytes:
        """
        Derives a master key from a string password using PBKDF2.
        """
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,
            salt=username.encode("utf-8"),
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt_with_master_key(self, data: bytes, salt: bytes) -> bytes:
        """Encrypt data using AES GCM and master key."""
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        encryption_key = kdf.derive(self.master_key)

        cipher = Cipher(
            algorithms.AES(encryption_key), modes.GCM(salt), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return encryptor.tag + encrypted_data

    def _decrypt_with_master_key(self, encrypted: bytes, salt: bytes) -> bytes:
        """Decrypt data encrypted with the master key using AES GCM."""
        tag = encrypted[:16]
        encrypted_data = encrypted[16:]

        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        encryption_key = kdf.derive(self.master_key)

        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(salt, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

    # -------------------------------------
    # RSA Key Pair Functions
    # -------------------------------------
    def _generate_private_key(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generates a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

    def _store_private_key(
        self, private_key: rsa.RSAPrivateKey, private_key_path: str
    ) -> None:
        """Stores the RSA private key in an encrypted format."""
        if not os.path.exists(os.path.dirname(private_key_path)):
            os.makedirs(os.path.dirname(private_key_path))

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        encrypted_private_key = self.encrypt_key_with_master_key(private_key_pem)

        with open(private_key_path, "wb") as key_file:
            key_file.write(encrypted_private_key)

    def load_public_key(self, private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        """Derives the public key from a private key."""
        return private_key.public_key()

    def load_private_key(self, private_key_path: str) -> rsa.RSAPrivateKey:
        """Loads and decrypts an RSA private key from a file."""
        try:
            with open(private_key_path, "rb") as key_file:
                encrypted_private_key = key_file.read()

            private_key_pem = self.decrypt_key_with_master_key(encrypted_private_key)

            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
            return private_key

        except Exception as e:
            raise Exception(f"Failed to load or decrypt the private key: {e}")

    def generate_key_pair(self, private_key_path: str) -> rsa.RSAPublicKey:
        """Generates and stores a new key pair, returning the public key."""
        private_key = self._generate_private_key()
        public_key = self.load_public_key(private_key)
        self._store_private_key(private_key, private_key_path)
        return public_key

    def encrypt_key_with_public_key(
        self, key: bytes, public_key: rsa.RSAPublicKey
    ) -> bytes:
        """Encrypts a key using an RSA public key."""
        return public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                algorithm=crypto_hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt_key_with_private_key(
        self, encrypted_key: bytes, private_key_path: str
    ) -> bytes:
        """Decrypts a key using an RSA private key."""
        private_key = self.load_private_key(private_key_path)
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                algorithm=crypto_hashes.SHA256(),
                label=None,
            ),
        )

    # -------------------------------------
    # Symmetric Key Functions
    # -------------------------------------
    def encrypt_key_with_master_key(self, key: bytes) -> bytes:
        """Encrypts a symmetric key using the master key."""
        salt = os.urandom(16)
        return salt + self._encrypt_with_master_key(key, salt)

    def decrypt_key_with_master_key(self, encrypted_key: bytes) -> bytes:
        """Decrypts a symmetric key encrypted with the master key."""
        salt = encrypted_key[:16]
        return self._decrypt_with_master_key(encrypted_key[16:], salt)
    
    def encrypt_data_with_master_key(self, data: str) -> bytes:
        """Encrypts data using the master key."""
        salt = os.urandom(16)
        return salt + self._encrypt_with_master_key(data.encode("utf-8"), salt)
    
    def decrypt_data_with_master_key(self, encrypted_data: bytes) -> str:
        """Decrypts data encrypted with the master key."""
        salt = encrypted_data[:16]
        return self._decrypt_with_master_key(encrypted_data[16:], salt).decode("utf-8")

    # -------------------------------------
    # Note Key Functions
    # -------------------------------------
    def generate_encrypted_note_key(self):
        """Generates and encrypts a note key using the master key."""
        return self.encrypt_key_with_master_key(os.urandom(32))

    def load_note_key(self, note_key_file: str):
        """Loads and decrypts a note key from a file."""
        try:
            with open(note_key_file, "rb") as key_file:
                encrypted_note_key = key_file.read()
            return self.decrypt_key_with_master_key(encrypted_note_key)
        except Exception as e:
            raise Exception(f"Failed to load or decrypt the note key: {e}")

    def store_note_key(self, note_key: bytes, note_key_path: str):
        """Encrypts and stores a note key in a file."""
        try:
            encrypted_note_key = self.encrypt_key_with_master_key(note_key)
            with open(note_key_path, "wb") as key_file:
                key_file.write(encrypted_note_key)
        except Exception as e:
            raise Exception(f"Failed to store the note key: {e}")

    # -------------------------------------
    # Public Key Serialization
    # -------------------------------------
    @staticmethod
    def get_public_key_json_serializable(public_key: rsa.RSAPublicKey) -> str:
        """Converts an RSA public key to a JSON-serializable format."""
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(public_key_bytes).decode("utf-8")

    @staticmethod
    def load_public_key_from_json_serializable(public_key: str) -> rsa.RSAPublicKey:
        """Loads an RSA public key from a JSON-serializable format."""
        public_key_bytes = base64.b64decode(public_key)
        return serialization.load_der_public_key(
            public_key_bytes, backend=default_backend()
        )
