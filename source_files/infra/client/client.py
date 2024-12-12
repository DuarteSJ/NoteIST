import socket
import ssl
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from exceptions import *


# Test data
test_request = {
    "operation": "create",
    "document": {"name": "Test Document", "content": "This is a test document."},
}

def load_private_key(private_key_path: str) -> rsa.RSAPrivateKey:
    """Load the client's private key from file"""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key

def encrypt_challenge_with_private_key(challenge: str, private_key: rsa.RSAPrivateKey) -> str:
    """Encrypt the challenge with the client's private key"""
    encrypted_challenge = private_key.encrypt(
        challenge.encode(),
        padding.PKCS1v15()
    )
    # Return the encrypted challenge as a base64 string to send over the network
    return base64.b64encode(encrypted_challenge).decode('utf-8')

def test_secure_server(host, port, cert_path, private_key_path):
    try:
        # Create a secure client socket
        context = ssl.create_default_context()

        # Load CA certificate to verify the server's certificate
        context.load_verify_locations(cafile=cert_path)  # CA cert to verify server

        # This is for server authentication only, not mutual TLS
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED  # We don't need client certificate

        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                print(f"Connected to server at {host}:{port}")

                # Receive the challenge from the server (assuming it's sent as a JSON response)
                server_response = secure_sock.recv(4096)
                response_data = json.loads(server_response.decode('utf-8'))

                if "challenge" in response_data:
                    challenge = response_data["challenge"]
                    print(f"Received challenge from server: {challenge}")

                    # Load the private key
                    private_key = load_private_key(private_key_path)

                    # Encrypt the challenge with the private key
                    encrypted_challenge = encrypt_challenge_with_private_key(challenge, private_key)

                    # Send the encrypted challenge back to the server
                    secure_sock.send(json.dumps({"challenge_response": encrypted_challenge}).encode("utf-8"))

                    # Receive the response from the server (session token or error)
                    server_response = secure_sock.recv(4096)
                    print(f"Server response: {server_response.decode('utf-8')}")
                else:
                    print("No challenge found in server response")

    except Exception as e:
        print(f"Test client error: {e}")


if __name__ == "__main__":
    test_secure_server("192.168.56.14", 5000, "/home/vagrant/setup/certs/ca.crt", "/home/vagrant/setup/certs/private_key.pem")
