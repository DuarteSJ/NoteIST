import ssl
import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from typing import List, Optional
from models import ResponseModel
from key_manager import load_private_key


class SecureRequestHandler:
    def __init__(self, username: str, host: str, port: int, cert_path: str):
        self.host = host
        self.port = port
        self.username = username
        self.cert_path = cert_path

        # if not self.username:
        #     raise ValueError(
        #         "Username could not be used. Ensure the username is valid."
        #     )

    def _sign_request(self, request_data: str, private_key):
        return private_key.sign(
            request_data.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )

    def _create_signed_payload(self, request_data: dict, private_key_path: str) -> dict:
        request_data_str = json.dumps(request_data)
        private_key = load_private_key(private_key_path)
        signature = self._sign_request(request_data_str, private_key)

        return {
            "username": self.username,
            "signature": signature.hex(),
            "data": request_data_str,
        }

    def _receive_data(self, secure_sock) -> str:
        data = b""
        while True:
            chunk = secure_sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8")

    def _send_request(self, payload: dict) -> ResponseModel:
        try:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=self.cert_path)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.host
                ) as secure_sock:
                    secure_sock.send(json.dumps(payload).encode("utf-8"))
                    response_data = self._receive_data(secure_sock)
                    response_dict = json.loads(response_data)

            return ResponseModel(**response_dict)

        except (socket.error, ssl.SSLError) as e:
            print(f"Socket/SSL error: {e}")
            raise
        except Exception as e:
            print(f"General request error: {e}")
            return ResponseModel(
                status="error", message=str(e), documents=None, document=None
            )

    def push_changes(self, private_key_path: str, changes: List[dict]) -> ResponseModel:
        payload = self._create_signed_payload(changes, private_key_path)
        return self._send_request(payload)

    def pull_changes(self, private_key_path: str) -> ResponseModel:
        request_data = {
            "type": "get_user_notes",
        }
        payload = self._create_signed_payload(request_data, private_key_path)
        return self._send_request(payload)

    def register_user(self, private_key_path: str, public_key: bytes) -> ResponseModel:
        pass
        # request_data = {
        #     "type": "register",
        #     "public_key": public_key,
        # }
        # payload = self._create_signed_payload(request_data, private_key_path)
        # return self._send_request(payload)
