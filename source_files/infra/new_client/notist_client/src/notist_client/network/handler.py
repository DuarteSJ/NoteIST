import ssl
import socket
import json
from typing import Dict, Any, List
from ..crypto.secure import SecureHandler
from ..crypto.keys import KeyManager
from ..models.responses import Response
from ..models.actions import RequestType

class NetworkHandler:
    """Handles all network communication with the server."""
    
    def __init__(self, username: str, host: str, port: int, cert_path: str):
        self.username = username
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.secure_handler = SecureHandler()

    def _receive_data(self, secure_sock: ssl.SSLSocket) -> str:
        """Receives data from the secure socket."""
        return secure_sock.recv(4096).decode("utf-8")

    def _send_request(self, payload: Dict[str, Any]) -> Response:
        """Sends a request to the server and returns the response."""
        try:
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=self.cert_path)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((self.host, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as secure_sock:
                    secure_sock.send(json.dumps(payload).encode("utf-8"))
                    response_data = self._receive_data(secure_sock)
                    return Response(**json.loads(response_data))

        except (socket.error, ssl.SSLError) as e:
            raise Exception(f"Network error: {e}")
        except Exception as e:
            return Response(
                status="error",
                message=str(e),
                documents=None,
                document=None
            )

    def push_changes(self, private_key_path: str, changes: List[Dict[str, Any]]) -> Response:
        """Pushes changes to the server."""
        private_key = KeyManager.load_private_key(private_key_path)
        signature = self.secure_handler.sign_request(changes, private_key)
        
        payload = self.secure_handler.create_signed_payload(
            RequestType.PUSH.value,
            self.username,
            changes,
            signature
        )
        return self._send_request(payload)

    def pull_changes(self, private_key_path: str) -> Response:
        """Pulls changes from the server."""
        private_key = KeyManager.load_private_key(private_key_path)
        signature = self.secure_handler.sign_request([], private_key)
        
        payload = self.secure_handler.create_signed_payload(
            RequestType.PULL.value,
            self.username,
            [],
            signature
        )
        return self._send_request(payload)

    def register_user(self, public_key: str) -> Response:
        """Registers a new user with the server."""
        return
        payload = self.secure_handler.create_unsigned_payload(
            RequestType.REGISTER.value,
            self.username,
            {"public_key": public_key}
        )
        print(payload)
        return self._send_request(payload)
