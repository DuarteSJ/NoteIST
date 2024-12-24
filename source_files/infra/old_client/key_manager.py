import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generates a new RSA private key.

    Returns:
        rsa.RSAPrivateKey: The generated private key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    return private_key


def load_public_key(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
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
        f"Private key stored at: {private_key_path}.\nDo not share, change, or edit this file's contents nor location or YOU WILL LOOSE ACCESS TO YOUR ACCOUNT.\n"
    )


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


def generate_key_pair(private_key_path: str) -> rsa.RSAPublicKey:
    """
    Generates a new RSA key pair and stores the private key at the specified file path, returning the public key.

    Args:
        private_key_path (str): The file path to store the private key.
    """
    private_key = generate_private_key()
    public_key = load_public_key(private_key)

    store_private_key(private_key, private_key_path)
    return public_key


def get_public_key_json_serializable(public_key: rsa.RSAPublicKey) -> str:
    """
    Converts the RSA public key into a JSON-serializable Base64-encoded string.

    Args:
        public_key (rsa.RSAPublicKey): The RSA public key to serialize.

    Returns:
        str: The Base64-encoded string representation of the public key.
    """
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # jesus fucking christ, this is a fucking mess of a code base and I'm not even sure if this is the right way to do it but it works so I'm not gonna touch it anymore
    # Encode the raw bytes to Base64 for JSON compatibility
    public_key_base64 = base64.b64encode(public_key_bytes).decode("utf-8")
    return public_key_base64
