import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_private_key() -> rsa.RSAPrivateKey:
    """
    Generates a new RSA private key.

    Returns:
        rsa.RSAPrivateKey: The generated private key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    """
    Generates the corresponding RSA public key from a given private key.

    Args:
        private_key (rsa.RSAPrivateKey): The private key from which to derive the public key.

    Returns:
        rsa.RSAPublicKey: The generated public key.
    """
    public_key = private_key.public_key()
    return public_key

def store_private_key(private_key: rsa.RSAPrivateKey, private_key_path: str) -> None:
    """
    Stores the RSA private key in PEM format at the specified file path.

    Args:
        private_key (rsa.RSAPrivateKey): The private key to store.
        private_key_path (str): The file path to store the private key.
    """
    # Ensure the directory for the private key file exists
    if not os.path.exists(os.path.dirname(private_key_path)):
        os.makedirs(os.path.dirname(private_key_path))  # Create directory if it doesn't exist
    
    with open(private_key_path, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"Private key stored at: {private_key_path}")

def store_public_key(public_key: rsa.RSAPublicKey, public_key_path: str) -> None:
    """
    Stores the RSA public key in PEM format at the specified file path.

    Args:
        public_key (rsa.RSAPublicKey): The public key to store.
        public_key_path (str): The file path to store the public key.
    """
    # Ensure the directory for the public key file exists
    if not os.path.exists(os.path.dirname(public_key_path)):
        os.makedirs(os.path.dirname(public_key_path))  # Create directory if it doesn't exist
    
    with open(public_key_path, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print(f"Public key stored at: {public_key_path}")

def load_private_key(private_key_path: str) -> rsa.RSAPrivateKey:
    """
    Loads the RSA private key from the specified file path.

    Args:
        private_key_path (str): The file path to load the private key from.

    Returns:
        rsa.RSAPrivateKey: The loaded private key.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key

def load_public_key(public_key_path: str) -> rsa.RSAPublicKey:
    """
    Loads the RSA public key from the specified file path.

    Args:
        public_key_path (str): The file path to load the public key from.

    Returns:
        rsa.RSAPublicKey: The loaded public key.
    """
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key
