import ssl
import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from typing import List
from app.models import (
    RequestModelType,
    ResponseModel,
)
from key_manager import load_private_key


class SecureRequestHandler:
    def __init__(self, username_file: str, host: str, port: int, cert_path: str):
        self.host = host
        self.port = port

        self.username = self._read_username_from_file(username_file)

        self.cert_path = cert_path

    def read_username_from_file(file_path: str) -> str:
        """Reads the username from a given file."""
        try:
            with open(file_path, "r") as file:
                username = file.read().strip()
                return username
        except FileNotFoundError:
            print(f"Error: The file at {file_path} does not exist.")
            return None
        except Exception as e:
            print(f"Error reading the file: {e}")
            return None

    def _sign_request(self, request_data: str, private_key):
        """Sign the request using the private key."""

        return private_key.sign(
            request_data.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )

    def _create_signed_payload(self, request_data: str, private_key_path: str) -> dict:
        """Generate the signed payload for the request."""

        private_key = load_private_key(private_key_path)
        signature = self._sign_request(request_data, private_key)

        payload = {
            "username": self.username,
            "signature": signature.hex(),
            "data": request_data,
        }

        return payload

    def _send_request(self, payload: dict) -> ResponseModel:
        """Send the request payload to the server and return the server's response."""

        try:
            # Establish SSL/TLS connection
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=self.cert_path)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            sock = socket.create_connection((self.host, self.port))
            secure_sock = context.wrap_socket(sock, server_hostname=self.host)

            secure_sock.send(json.dumps(payload).encode("utf-8"))

            data = secure_sock.recv(4096)  # TODO: size
            response_dict = json.loads(data.decode("utf-8"))

            # Return the response
            response = ResponseModel(**response_dict)
            secure_sock.close()
            return response

        except Exception as e:
            print(f"Request failed: {e}")
            return ResponseModel(status="error", message=str(e))

    def push_changes(self, private_key_path: str, changes: List[dict]) -> ResponseModel:
        """Create the signed payload and send the request to the server."""

        request_data = json.dumps(changes)
        payload = self._create_signed_payload(request_data, private_key_path)

        return self._send_request(payload)

    def pull_changes(self, private_key_path: str):
        # TODO: implement this
        ...
