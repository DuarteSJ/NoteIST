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

    def __init__(self, password: str, salt: bytes):
        self.master_key = self.derive_master_key(password)
        self.note_title_salt = salt

    def generate_private_key(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generates a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

    def load_public_key(self, private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        """Derives the public key from a private key."""
        return private_key.public_key()

    def encrypt_with_master_key(self, data: bytes, salt: bytes) -> bytes:
        """Encrypt data (e.g., private key, symmetric key) using AES GCM and master key."""
        # TODO: this function might be doing to much

        # Generate a salt and derive an AES key from the master key

        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )

        encryption_key = kdf.derive(self.master_key)

        # Encrypt the data using AES GCM
        cipher = Cipher(
            algorithms.AES(encryption_key), modes.GCM(salt), backend=default_backend()
        )

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        print("encryptor tag")
        print(encryptor.tag)

        # Return salt + encrypted data + tag (for AES GCM)
        return encryptor.tag + encrypted_data

    def decrypt_with_master_key(self, encrypted: bytes, salt: bytes) -> bytes:
        """Decrypt data encrypted with the master key using AES GCM."""
        # Extract the salt, encrypted data, and tag
        tag = encrypted[:16]
        encrypted_data = encrypted[16:]

        # Derive the encryption key using the salt and master key
        kdf = PBKDF2HMAC(
            algorithm=crypto_hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        encryption_key = kdf.derive(self.master_key)

        # Decrypt using AES GCM
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(salt, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

    def encrypt_note_title(self, title: str) -> bytes:
        """Encrypts the note title using the note key."""
        encrypted_title = self.encrypt_with_master_key(
            title.encode("utf-8"), self.note_title_salt
        )
        encrypted_title = base64.urlsafe_b64encode(encrypted_title).decode("utf-8")
        return encrypted_title

    def decrypt_note_title(self, title: bytes) -> str:
        """Decrypts the note title using the note key."""
        title = base64.urlsafe_b64decode(title.encode("utf-8"))
        return self.decrypt_with_master_key(title, self.note_title_salt).decode("utf-8")

    def encrypt_key_with_master_key(self, key: bytes) -> bytes:
        """Encrypts the note key using the master key."""
        salt = os.urandom(16)
        return salt + self.encrypt_with_master_key(key, salt)

    def decrypt_key_with_master_key(self, encrypted_key: bytes) -> bytes:
        salt = encrypted_key[:16]
        return self.decrypt_with_master_key(encrypted_key[16:], salt)

    def store_private_key(
        self,
        private_key: rsa.RSAPrivateKey,
        private_key_path: str,
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

        encrypted_private_key = self.encrypt_key_with_master_key(private_key_pem)

        with open(private_key_path, "wb") as key_file:
            key_file.write(encrypted_private_key)

        print(
            f"Private key stored at: {private_key_path}.\n"
            "Do not share, change, or edit this file's contents nor location "
            "or YOU WILL LOSE ACCESS TO YOUR ACCOUNT.\n"
        )

    def load_private_key(self, private_key_path: str) -> rsa.RSAPrivateKey:
        """Loads and decrypts an RSA private key from a file using the master key."""
        try:
            with open(private_key_path, "rb") as key_file:
                encrypted_private_key = key_file.read()

            # Decrypt the private key using the master key
            private_key_pem = self.decrypt_key_with_master_key(encrypted_private_key)

            # Deserialize the private key from PEM format
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
            print(f"private key: {private_key}")
            return private_key

        except Exception as e:
            raise Exception(f"Failed to load or decrypt the private key: {e}")

    def generate_key_pair(self, private_key_path: str) -> rsa.RSAPublicKey:
        """Generates and stores a new key pair, returning the public key."""
        private_key = self.generate_private_key()

        public_key = self.load_public_key(private_key)

        self.store_private_key(private_key, private_key_path)

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

    def generate_encrypted_note_key(cls):
        """Generates a new random 256-bit symmetric encryption key and encripts it with the master key."""
        return cls.encrypt_key_with_master_key(cls.generate_symmetric_key())

    def load_note_key(cls, noteKeyFile: str):
        """Loads and decrypts the note's secret key from a file using the master key."""
        try:
            with open(noteKeyFile, "rb") as key_file:
                encrypted_note_key = key_file.read()

            # Decrypt the secret key using the master key
            note_key = cls.decrypt_key_with_master_key(encrypted_note_key)
            return note_key

        except Exception as e:
            raise Exception(f"Failed to load or decrypt the note key: {e}")
        
    def store_note_key(cls, note_key: bytes, note_key_path: str):
        """Encrypts and stores the note's secret key in an encrypted format."""
        try:

            encrypted_note_key = cls.encrypt_key_with_master_key(note_key)

            with open(note_key_path, "wb") as key_file:
                key_file.write(encrypted_note_key)
        
        except Exception as e:
            raise Exception(f"Failed to store the note key: {e}")


    def derive_master_key(self, password: str) -> bytes:
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

    def encrypt_key_with_public_key(self, key: bytes, public_key: bytes) -> bytes:
        """Encrypts a key using an RSA public key."""
        return public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=crypto_hashes.SHA256()),
                algorithm=crypto_hashes.SHA256(),
                label=None,
            ),
        )
    
    def decrypt_key_with_private_key(self, encrypted_key: bytes, private_key_path: str) -> bytes:
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
    
    