# This is not done, but can currently be used to generate random keys

import argparse
import sys
import os


KEY_FILE = os.path.join(os.path.expanduser("~"), ".config", "secure_document", "key")


def generate_key() -> bytes:
    """Generates a new random 256-bit encryption key."""
    key = os.urandom(32)  # 256-bit long
    return key


def store_key(key: bytes) -> None:
    """Stores the encryption key in a file."""

    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print(f"Key stored at: {KEY_FILE}")


def load_key() -> bytes:
    """Loads the encryption key from the predefined file, or prompts the user to generate one."""
    if not os.path.exists(KEY_FILE):
        user_input = (
            input("Key file not found. Do you want to generate a new key? (yes/no): ")
            .strip()
            .lower()
        )
        if user_input in ["yes", "y", "Yes"]:
            key = generate_key()
            store_key(key)
            print("New encryption key generated and stored.")
            return key
        else:
            raise FileNotFoundError(
                "Key file not found. Please generate a key using the 'generate-key' command."
            )

    with open(KEY_FILE, "rb") as f:
        return f.read()


def main() -> int:
    """Main entry point of the application."""
    parser = argparse.ArgumentParser(description="Secure Document Key Management")
    parser.add_argument(
        "command", choices=["generate-key", "load-key"], help="Manage encryption keys"
    )

    args = parser.parse_args()

    if args.command == "generate-key":
        key = generate_key()
        store_key(key)
        print("Generated new key and stored it.")
        return 0

    elif args.command == "load-key":
        try:
            key = load_key()
            print(f"Key successfully loaded: {key.hex()}")
            return 0
        except Exception as e:
            print(f"Error: {e}")
            return 1

    print("Invalid command.")
    return 1


if __name__ == "__main__":
    sys.exit(main())




# This might be usefull in the future
import ssl
import socket
import json
from infra.common.models import ResponseModel

class Server:
    def __init__(self, host: str, port: int, cert_path: str, key_path: str):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.server_socket = None

    def start_server(self):
        """Starts the server to listen for incoming requests."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}...")

        while True:
            client_socket, client_address = self.server_socket.accept()
            with client_socket:
                print(f"Connection established with {client_address}")

                # Wrap the connection with SSL/TLS encryption
                secure_sock = context.wrap_socket(client_socket, server_side=True)
                
                # Receive data from the client (the request is expected to be a list of dictionaries)
                data = secure_sock.recv(4096)
                if data:
                    try:
                        requests = json.loads(data.decode('utf-8'))
                        responses = []

                        # Process each request in the list
                        for request in requests:
                            response = self.process_request(request)
                            responses.append(response)

                        # Send back the combined response
                        response_data = json.dumps(responses).encode('utf-8')
                        secure_sock.send(response_data)
                    except Exception as e:
                        error_response = ResponseModel(status='error', message=str(e))
                        secure_sock.send(json.dumps([error_response.dict()]).encode('utf-8'))

    def process_request(self, request: dict) -> ResponseModel:
        """Process an individual request."""
        # Example of request processing
        if request['type'] == 'create_note':
            return self.create_note(request)
        elif request['type'] == 'get_note':
            return self.get_note(request)
        elif request['type'] == 'get_user_notes':
            return self.get_user_notes(request)
        elif request['type'] == 'edit_note':
            return self.edit_note(request)
        elif request['type'] == 'delete_note':
            return self.delete_note(request)
        else:
            return ResponseModel(status='error', message="Unknown request type")

    def create_note(self, request: dict) -> ResponseModel:
        """Create a note (mocked for example)."""
        return ResponseModel(status='success', message='Note created successfully')

    def get_note(self, request: dict) -> ResponseModel:
        """Get a note (mocked for example)."""
        return ResponseModel(status='success', message=f"Note {request['note_id']} retrieved successfully")

    def get_user_notes(self, request: dict) -> ResponseModel:
        """Get all notes for a user (mocked for example)."""
        return ResponseModel(status='success', message=f"Notes for {request['username']} retrieved successfully")

    def edit_note(self, request: dict) -> ResponseModel:
        """Edit an existing note (mocked for example)."""
        return ResponseModel(status='success', message=f"Note {request['note_id']} updated successfully")

    def delete_note(self, request: dict) -> ResponseModel:
        """Delete a note (mocked for example)."""
        return ResponseModel(status='success', message=f"Note {request['note_id']} deleted successfully")






#TODO:
    mudar user para ter password (password nao é guardada em lado nenhum, user tem de a saber):
        pv key e gerada a partir de random salt (guardado localmente) + psw
        - vantagens:
            - private key nao fica guardada localmente (loacal ataacks counter)

    mudar secure-document para encriptar so o content e o title, ou seja:
        - {
            id: 12
            title: "paiwcxdgnfasdgpf"
            content: "çosdfhnpoxds"
            Hmac: hmac(title+content)
            version: 2
        }