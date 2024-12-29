import socket
import ssl
import json
import logging
from pydantic import ValidationError
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from users import UsersService
from notes import NotesService
from cryptography.hazmat.primitives.hashes import SHA256
import base64


# Import the new Pydantic models
from models import (
    BaseRequestModel,
    RequestType,
    ResponseModel,
    RequestFactory,
    RegisterRequest,
    PullRequest,
    PushRequest,
    SignedRequestModel,
    ActionType,
)


class Server:
    def __init__(
        self,
        user_service: UsersService,
        notes_service: NotesService,
        host="0.0.0.0",
        port=5000,
        cert_path="/home/vagrant/certs/server/server.crt",
        key_path="/home/vagrant/certs/server/server.key",
    ):
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Socket and TLS setup
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.context.verify_mode = ssl.CERT_NONE

        # Inject services
        self.user_service = user_service
        self.notes_service = notes_service

    def handle_register_request(self, req: RegisterRequest) -> ResponseModel:
        """
        Handle the registration request.
        """

        key = req.data.get("public_key")
        if not key:
            return {"status": "error", "message": "Public key is required"}
        try:
            self.user_service.create_user(req.username, key)
            return {"status": "success", "message": "User created successfully"}

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return {"status": "error", "message": str(ve)}

        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return {"status": "error", "message": str(e)}

    def handle_pull_request(self, req: PullRequest) -> ResponseModel:
        """
        Handle the pull request.
        """
        try:
            if not self.verify_signature(req):
                return {"status": "error", "message": "Signature verification failed"}

            user = self.user_service.get_user(req.username)
            local_hmac = req.data.get("digest_of_hmacs")

            documents = self.notes_service.get_user_notes(user.get("id"))
            sorted_docs = sorted(documents, key=lambda x: x["id"])
            hmac_str = ""
            for doc in sorted_docs:
                hmac_str += doc.get("hmac")

            digest_of_hmacs = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest_of_hmacs.update(hmac_str.encode("utf-8"))
            digest_of_hmacs = digest_of_hmacs.finalize().hex()

            print(f"Server: {digest_of_hmacs}")
            print(f"Client: {local_hmac}")

            if digest_of_hmacs == local_hmac:
                return {
                    "status": "synced",
                    "message": "All files are up to date. Sync successful",
                }


            return {
                "status": "success",
                "message": "Documents retrieved successfully",
                "documents": documents,
            }

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return {"status": "error", "message": str(ve)}
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return {"status": "error", "message": str(e)}

    def handle_push_request(self, req: PushRequest) -> ResponseModel:
        """
        Handle the push request by processing a list of actions.

        Calls the appropriate handler method for each action type.
        """
        try:
            # Verify signature first
            if not self.verify_signature(req):
                return {"status": "error", "message": "Signature verification failed"}

            # user was found for signature verification
            user = self.user_service.get_user(req.username)

            # Prepare to collect results of actions
            action_results = []

            note_changes = req.data.get("note_changes")
            user_changes = req.data.get("user_changes")


            # Process each action
            for action in note_changes:
                print(action)
                handler_method = self._get_action_handler(action.get("type", ""))
                if handler_method:
                    try:
                        result = handler_method(action, user)
                        action_results.append(
                            {
                                "action": action.get("type"),
                                "status": "success",
                                "result": result,
                            }
                        )
                    except Exception as action_error:
                        action_results.append(
                            {
                                "action": action.get("type"),
                                "status": "error",
                                "message": str(action_error),
                            }
                        )
                else:
                    action_results.append(
                        {
                            "action": action.get("type"),
                            "status": "error",
                            "message": f'No handler found for action: {action.get("type")}',
                        }
                    )

            user_results = []

            for collab in user_changes:
                handler_method = self._get_action_handler(collab.get("type", ""))
                if handler_method:
                    try:
                        result = handler_method(collab, user)
                        user_results.append(
                            {
                                "collab": collab.get("type"),
                                "status": "success",
                                "result": result,
                            }
                        )
                    except Exception as collab_error:
                        user_results.append(
                            {
                                "collab": collab.get("type"),
                                "status": "error",
                                "message": str(collab_error),
                            }
                        )
                else:
                    user_results.append(
                        {
                            "collab": collab.get("type"),
                            "status": "error",
                            "message": f'No handler found for action: {collab.get("type")}',
                        }
                    )

            # Construct response
            return {
                "status": "success",
                "message": "Actions processed",
                "action_results": action_results,
                "user_results": user_results,
            }

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return {"status": "error", "message": str(ve)}
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return {"status": "error", "message": str(e)}

    def _get_action_handler(self, action: str):
        """
        Retrieve the appropriate handler method for a given action.

        :param action: The action type to handle
        :return: A method to handle the specific action
        """
        action_handlers = {
            ActionType.CREATE_NOTE.value: self._handle_create_note,
            ActionType.EDIT_NOTE.value: self._handle_edit_note,
            ActionType.DELETE_NOTE.value: self._handle_delete_note,
            ActionType.ADD_COLLABORATOR.value: self._handle_add_collaborator,
            ActionType.REMOVE_COLLABORATOR.value: self._handle_remove_collaborator,
        }

        return action_handlers.get(action)

    def _handle_create_note(
        self, action: Dict[str, Any], user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle creating a new note for the user.

        :param username: The username of the note creator
        :param user: User details
        :return: Details of the created note
        """
        data = action.get("data", {})
        note = data.get("note")
        if not note:
            raise ValueError("Missing note data")
        
        note_id = note.get("id")
        note_hmac = note.get("hmac")
        note_iv = note.get("iv")
        note_title = note.get("title")
        note_note = note.get("note")
        if (
            not note_id
            or not note_hmac
            or not note_iv
            or not note_title
            or not note_note
        ):
            raise ValueError("Missing required note fields")

        note = self.notes_service.get_note(note_id, user)
        if note:
            raise ValueError(
                f"Note with id {note_id} already exists. Try deleting this note and creating a new one"
            )

        note = self.notes_service.create_note(
            title=note_title,
            content=note_note,
            id=note_id,
            iv=note_iv,
            hmac=note_hmac,
            owner=user,
        )
        note_id = note.get("id")
        return {"status": "success", "message": f"Note {note_id} created", }

    def _handle_edit_note(
        self, action: Dict[str, Any], user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle editing an existing note.

        :param username: The username of the note editor
        :param user: User details
        :return: Details of the edited note
        """

        # recebe uma nota com id, title, content, hmac, iv e version.
        # checka a version do documento e a atual
        # se tiver havido um update da parte de um editor, aumenta a versão para a ultima que saiu.
        # se a versão for a mesma, chama o create_note

        sent_note = action.get("data", {}).get("note")

        if not sent_note:
            raise ValueError("Missing note data")

        owner = self.user_service.get_user(sent_note.get("owner").get("username"))
        owner_id = owner.get("id")

        server_note = self.notes_service.get_note(sent_note.get("id"), owner_id)
        if not server_note:
            raise ValueError("Note not found")

        perms = self.user_service.check_user_note_permissions(
            user.get("id"), server_note
        )

        if not perms.get("is_editor"):
            raise ValueError("User does not have permission to edit this note")

        note_id = sent_note.get("id")
        note_hmac = sent_note.get("hmac")
        note_iv = sent_note.get("iv")
        note_title = sent_note.get("title")
        note_note = sent_note.get("note")
        note_version = sent_note.get("version")

        if (
            not note_id
            or not note_hmac
            or not note_iv
            or not note_title
            or not note_note
            or not note_version
            or not owner_id
        ):
            raise ValueError("Missing required note fields")

        self.notes_service.edit_note(
            title=note_title,
            content=note_note,
            id=note_id,
            iv=note_iv,
            hmac=note_hmac,
            owner=owner,
            editor=user,
            version=note_version,
        )

        return {"status": "success", "message": f"Note {note_id} edited"}

    def _handle_delete_note(
        self, action: Dict[str, Any], user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle deleting a note.

        :param username: The username of the note deleter
        :param user: User details
        :return: Details of the deleted note
        """

        # sent_note = action.get('data', {}).get('note')
        # if not sent_note:
        #     raise ValueError("Missing note data")

        owner = user
        note_id = action.get("data", {}).get("note_id")
        if not note_id:
            raise ValueError("Missing note data")

        server_note = self.notes_service.get_note(note_id, owner)

        perms = self.user_service.check_user_note_permissions(
            user.get("id"), server_note
        )
        if not perms.get("is_owner"):
            raise ValueError("User does not have permission to delete this note")

        self.notes_service.delete_note(note_id, owner)

        for editor_id in server_note.get("editors", []):
            self.user_service.remove_editor_note(editor_id, note_id)
        for viewer_id in server_note.get("viewers", []):
            self.user_service.remove_viewer_note(viewer_id, note_id)

        return {"status":"success", "message": f"Note {note_id} deleted"}

    def _handle_add_collaborator(
        self, action: Dict[str, Any], user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle adding colaborators to a note.
        colaborators can be viewers or editors. (decided in the action data)
        {
            "type": "ADD_COLABORATOR",
            "data": {
                "note_id":
                "editorFlag": True/False,
                "collaborator_username":
            }
        }

        """
        note_id = action.get("data", {}).get("note_id")
        collaborator_username = action.get("data", {}).get("collaborator_username")
        editorFlag = action.get("data", {}).get("is_editor")

        if not note_id or not collaborator_username or editorFlag is None:
            raise ValueError("Missing required note fields")

        collaborator = self.user_service.get_user(collaborator_username)
        if not collaborator:
            raise ValueError(f"User {collaborator_username} not found")

        note = self.notes_service.get_note(note_id, user)
        if not note:
            raise ValueError(f"Note with id {note_id} not found")

        if editorFlag:
            self.notes_service.add_editor_to_note(
                note, user.get("id"), collaborator.get("id")
            )
            self.user_service.add_editor_note(collaborator, note_id)

        self.notes_service.add_viewer_to_note(
            note, user.get("id"), collaborator.get("id")
        )
        self.user_service.add_viewer_note(collaborator.get("id"), note_id)

        return {"status": "success", "message": f"Collaborator {collaborator_username} added"}

    def _handle_remove_collaborator(
        self, action: Dict[str, Any], user: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle removing colaborators from a note.
        colaborators can be viewers or editors. (decided in the action data)
        {
            "type": "REMOVE_COLLABORATOR",
            "data": {
                "note_id":
                "collaborator_username":
            }
        }
        """
        note_id = action.get("data", {}).get("note_id")
        collaborator_username = action.get("data", {}).get("collaborator_username")
        editorFlag = action.get("data", {}).get("editorFlag")

        if not note_id or not collaborator_username:
            raise ValueError("Missing required note fields")

        collaborator = self.user_service.get_user(collaborator_username)
        if not collaborator:
            raise ValueError(f"User {collaborator_username} not found")

        note = self.notes_service.get_note(note_id, user)
        if not note:
            raise ValueError(f"Note with id {note_id} not found")

        if editorFlag:
            self.notes_service.remove_editor_from_note(
                note, user.get("id"), collaborator.get("id")
            )
            self.user_service.remove_editor_note(collaborator.get("id"), note_id)

        self.notes_service.remove_viewer_from_note(
            note, user.get("id"), collaborator.get("id")
        )
        self.user_service.remove_viewer_note(collaborator.get("id"), note_id)

        return {"status": "success", "message": f"Collaborator {collaborator_username} removed"}

    def handle_request(self, request: BaseRequestModel) -> ResponseModel:
        """
        Handle different document operations by delegating to the appropriate service.
        """
        try:
            if request.type == RequestType.REGISTER:
                return self.handle_register_request(req=request)

            elif request.type == RequestType.PULL:
                return self.handle_pull_request(req=request)

            elif request.type == RequestType.PUSH:
                return self.handle_push_request(req=request)

            else:
                return ResponseModel(status="error", message="Unsupported operation")

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status="error", message=str(ve))
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status="error", message=str(e))

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

    def verify_signature(self, req: SignedRequestModel) -> bool:
        # Fetch public key from database
        username = req.username
        signature = req.signature.decode("utf-8")
        signature = bytes.fromhex(signature)
        data = req.data
        serialized_data = json.dumps(data, separators=(",", ":"), sort_keys=True)
        public_key_bytes = base64.b64decode(
            self.user_service.get_user(username)["public_key"]
        )

        try:
            # Load the public key
            public_key = load_der_public_key(public_key_bytes, default_backend())

            # Verify the signature
            public_key.verify(
                signature,  # signature should be raw bytes
                serialized_data.encode("utf-8"),  # data to verify should also be bytes
                padding.PKCS1v15(),
                SHA256(),
            )
            return True
        except Exception as e:
            logging.error(f"Signature verification failed: {e}")
            return False

    def start(self):
        """
        Start the secure TLS socket server
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(5)
            self.logger.info(f"Server listening on {self.host}:{self.port}")

            with self.context.wrap_socket(sock, server_side=True) as secure_sock:
                while True:
                    try:
                        client_socket, address = secure_sock.accept()
                        self.logger.info(f"Connection from {address}")

                        # Receive data
                        data = self._receive_data(client_socket)

                        request_dict = json.loads(data)

                        # Validate and create request using factory
                        request = RequestFactory.create_request(request_dict)

                        # Process request
                        response = self.handle_request(request)

                        # Send response
                        client_socket.send(json.dumps(response).encode("utf-8"))
                        client_socket.close()

                    except Exception as e:
                        self.logger.error(f"Server error: {e}")


if __name__ == "__main__":  #
    from users import get_users_service
    from notes import get_notes_service
    from db_manager import get_database_manager

    MONGO_HOST = "192.168.56.17"
    MONGO_PORT = "27017"
    DB_NAME = "secure_document_db"
    SERVER_CRT = "/home/vagrant/certs/server/server.pem"
    SERVER_KEY_PATH = "/home/vagrant/certs/server/server.pem"
    CA_CRT = "/home/vagrant/certs/ca.crt"

    try:
        with get_database_manager(
            MONGO_HOST, MONGO_PORT, DB_NAME, None, SERVER_CRT, CA_CRT
        ) as db_manager:
            user_service = get_users_service(db_manager)
            notes_service = get_notes_service(db_manager)
            server = Server(
                user_service=user_service,
                notes_service=notes_service,
                cert_path=SERVER_CRT,
                key_path=SERVER_KEY_PATH,
            )
            server.start()
    except Exception as e:
        logging.error(f"Error initializing the server: {e}")
        raise
