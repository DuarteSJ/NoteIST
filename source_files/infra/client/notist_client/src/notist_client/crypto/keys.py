from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

class KeyManager:
    """Handles cryptographic key operations including generation, storage, and loading."""
    
    @staticmethod
    def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generates a new RSA private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def load_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        """Derives the public key from a private key."""
        return private_key.public_key()

    @staticmethod
    def store_private_key(private_key: rsa.RSAPrivateKey, private_key_path: str) -> None:
        """Stores the RSA private key in PEM format."""
        if not os.path.exists(os.path.dirname(private_key_path)):
            os.makedirs(os.path.dirname(private_key_path))

        with open(private_key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        print(
            f"Private key stored at: {private_key_path}.\n"
            "Do not share, change, or edit this file's contents nor location "
            "or YOU WILL LOSE ACCESS TO YOUR ACCOUNT.\n"
        )

    @staticmethod
    def load_private_key(private_key_path: str) -> rsa.RSAPrivateKey:
        """Loads an RSA private key from a file."""
        with open(private_key_path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

    @classmethod
    def generate_key_pair(cls, private_key_path: str) -> rsa.RSAPublicKey:
        """Generates and stores a new key pair, returning the public key."""
        private_key = cls.generate_private_key()
        public_key = cls.load_public_key(private_key)
        cls.store_private_key(private_key, private_key_path)
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