import ssl
import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from typing import List
from models import ResponseModel, RequestType
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

    def _sign_request(self, request_data: list, private_key):
        try:
            serialized_data = json.dumps(
                request_data, separators=(",", ":"), sort_keys=True
            )
            print(f"Serialized data: {serialized_data}")
            return private_key.sign(
                serialized_data.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
            )
        except Exception as e:
            print(f"Error signing request: {e}")
            raise

    def _create_unsigned_payload(self, req_type: str, request_data: dict) -> dict:
        return {
            "type": req_type,
            "username": self.username,
            "data": request_data,
        }

    def _create_signed_payload(
        self, req_type, request_data: dict, private_key_path: str
    ) -> dict:
        print(f"Creating signed payload for {req_type}")
        private_key = load_private_key(private_key_path)
        print(f"Private key loaded: {private_key}")
        signature = self._sign_request(request_data, private_key)
        print(f"Signature: {signature}")

        return {
            "type": req_type,
            "username": self.username,
            "signature": signature.hex(),
            "data": request_data,
        }

    def _receive_data(self, secure_sock) -> str:
        chunks = []
        while True:
            chunk = secure_sock.recv(4096)
            if not chunk:  # Connection was closed
                break
            chunks.append(chunk)
            
            # Check if the socket has more data waiting
            # By checking the socket's receive buffer
            if len(chunk) < 4096:
                break
        
        return b''.join(chunks).decode('utf-8')

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
                    print(f" sending: {json.dumps(payload).encode('utf-8')}")
                    secure_sock.send(json.dumps(payload).encode("utf-8"))
                    response_data = self._receive_data(secure_sock)
                    response_dict = json.loads(response_data)
            print(f"Received response from server: {response_dict}")
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
        payload = self._create_signed_payload(
            RequestType.PUSH.value, changes, private_key_path
        )
        print(f"push payload: {payload}")
        return self._send_request(payload)

    def pull_changes(self, private_key_path: str) -> ResponseModel:
        print("pulling changes")
        payload = self._create_signed_payload(
            RequestType.PULL.value, [], private_key_path
        )
        print(f"pull payload: {payload}")
        return self._send_request(payload)

    def register_user(self, public_key: bytes) -> ResponseModel:
        request_data = {
            "public_key": public_key,
        }
        payload = self._create_unsigned_payload(
            RequestType.REGISTER.value, request_data
        )
        return self._send_request(payload)
