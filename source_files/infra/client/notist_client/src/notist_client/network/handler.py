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

    def __init__(
        self,
        username: str,
        host: str,
        port: int,
        cert_path: str,
        key_manager: KeyManager,
    ):
        self.username = username
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_manager = key_manager
        self.secure_handler = SecureHandler()

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

        return b"".join(chunks).decode("utf-8")

    def _send_request(self, payload: Dict[str, Any]) -> Response:
        """Sends a request to the server and returns the response."""
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
                    return Response(**json.loads(response_data))

        except (socket.error, ssl.SSLError) as e:
            raise Exception(f"Network error: {e}")
        except Exception as e:
            return Response(
                status="error",
                message=str(e) + " this did not come from the server",
                documents=None,
                document=None,
            )

    def push_changes(
        self, private_key_path: str, note_changes: List[Dict[str, Any]], user_changes: List[Dict[str, Any]]
    ) -> Response:
        """Pushes changes to the server."""
        if not note_changes and not user_changes:
            return Response(
                status="success",
                message="No changes to push (this wasn't sent by server)",
                user_results=[],
                action_results=[],
            )
        changes = {"note_changes": note_changes, "user_changes": user_changes}
        private_key = self.key_manager.load_private_key(private_key_path)
        signature = self.secure_handler.sign_request(changes, private_key)

        payload = self.secure_handler.create_signed_payload(
            RequestType.PUSH.value, self.username, changes, signature
        )
        print(f"sending payload: {payload}")
        return self._send_request(payload)

    def pull_changes(self, private_key_path: str, hash_of_hmacs:str) -> Response:
        """Pulls changes from the server."""
        private_key = self.key_manager.load_private_key(private_key_path)

        #get notes  

        data = {"digest_of_hmacs":hash_of_hmacs}

        signature = self.secure_handler.sign_request(data, private_key)

        # TODO: Send the hmac of hashes through this
        # This is the server code:
        # sorted_docs = sorted(documents, key=lambda x: x['_id'])
        # hmac_str = ""
        # for doc in sorted_docs:
        #     hmac_str += doc.get("hmac")


        # digest_of_hmacs = hashes.Hash(hashes.SHA256())
        # digest_of_hmacs.update(hmac_str.encode("utf-8"))
        # digest_of_hmacs = digest_of_hmacs.finalize().hex()


        payload = self.secure_handler.create_signed_payload(
            RequestType.PULL.value, self.username, data, signature
        )
        return self._send_request(payload)

    def register_user(self, public_key: str) -> Response:
        """Registers a new user with theprivate_key server."""
        payload = self.secure_handler.create_unsigned_payload(
            RequestType.REGISTER.value, self.username, {"public_key": public_key}
        )
        print(payload)
        return self._send_request(payload)
