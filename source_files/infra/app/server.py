import socket
import ssl
import json
import logging
from pymongo import MongoClient
from pydantic import ValidationError
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from users import UsersService
from notes import NotesService
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
    ActionModel
)

class Server:
    def __init__(self, 
                 user_service: UsersService,
                 notes_service: NotesService,
                 host='0.0.0.0', 
                 port=5000, 
                 cert_path='/home/vagrant/setup/certs/server.crt', 
                 key_path='/home/vagrant/setup/certs/server.key',
                 mongo_uri='mongodb://192.168.56.17:27017',):
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # MongoDB connection for additional operations if needed
        self.client = MongoClient(mongo_uri)
        self.db = self.client['secure_document_db']
        self.collection = self.db['documents']
        
        # Check if connection
        if self.client:
            self.logger.info("Connected to MongoDB")
        else:
            self.logger.error("Failed to connect to MongoDB")       

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

        try:
            self.user_service.create_user(req.username, req.public_key)
            return ResponseModel(status='success', message='User registered')

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status='error', message=str(ve))
        
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status='error', message=str(e))

    def handle_pull_request(self, req: PullRequest) -> ResponseModel:
        """
        Handle the pull request.
        """
        try:
            if not self.verify_signature(req):
                return ResponseModel(status='error', message='Signature verification failed')
            
            user = self.user_service.get_user(req.username)
            digest_of_hmacs = user.get('digest_of_hmacs', None)
            if not digest_of_hmacs:
                # TODO: Decide what to do here if digest_of_hmacs is not set
                digest_of_hmacs = ""
            
            documents = self.notes_service.get_user_notes(username=req.username)

            return ResponseModel(
                status='success',
                message='Documents retrieved successfully',
                digest_of_hashes=digest_of_hmacs,
                documents=documents
            )
        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status='error', message=str(ve))
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status='error', message=str(e))

    def handle_push_request(self, req: PushRequest) -> ResponseModel:
        """
        Handle the push request by processing a list of actions.
        
        Calls the appropriate handler method for each action type.
        """
        try:
            # Verify signature first
            if not self.verify_signature(req):
                return ResponseModel(status='error', message='Signature verification failed')
            
            # user was found for signature verification
            user = self.user_service.get_user(req.username)
            
            # Prepare to collect results of actions
            action_results = []
            
            # Process each action
            for action in req.actions:
                if 'type' not in action:
                    continue
                handler_method = self._get_action_handler(action.type)
                if handler_method:
                    try:
                        result = handler_method(action, user)
                        action_results.append({
                            'action': action.value,
                            'status': 'success',
                            'result': result
                        })
                    except Exception as action_error:
                        action_results.append({
                            'action': action.value,
                            'status': 'error',
                            'message': str(action_error)
                        })
                else:
                    action_results.append({
                        'action': action.value,
                        'status': 'error',
                        'message': f'No handler found for action: {action.value}'
                    })
            
            # Get digest of HMACs (if applicable)
            digest_of_hmacs = user.get('digest_of_hmacs', '')
            
            # Retrieve user documents
            documents = self.notes_service.get_user_notes(username=req.username)
            
            # Construct response
            return ResponseModel(
                status='success',
                message='Actions processed successfully',
                digest_of_hashes=digest_of_hmacs,
                documents=documents,
                document={'action_results': action_results}
            )
        
        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status='error', message=str(ve))
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status='error', message=str(e))

    def _get_action_handler(self, action: ActionType):
        """
        Retrieve the appropriate handler method for a given action.
        
        :param action: The action type to handle
        :return: A method to handle the specific action
        """
        action_handlers = {
            ActionType.CREATE_NOTE: self._handle_create_note,
            ActionType.EDIT_NOTE: self._handle_edit_note,
            ActionType.DELETE_NOTE: self._handle_delete_note
            ActionType.ADD_COLABORATOR: self._handle_add_colaborator,
            ActionType.REMOVE_COLABORATOR: self._handle_remove_colaborator
        }
        
        return action_handlers.get(action)
   
    def _handle_create_note(self, action: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle creating a new note for the user.
        
        :param username: The username of the note creator
        :param user: User details
        :return: Details of the created note
        """
        # Criar nota:
        # verificar se id, owner_id existem. Se não criar nota
        
        note = action.get('data', {}).get('note')
        if not note:
            raise ValueError("Missing note data")
        
        note_id = note.get('_id')
        note_hmac = note.get('hmac')
        note_iv = note.get('iv')
        note_title = note.get('title')
        note_note = note.get('note')
        if not note_id or not note_hmac or not note_iv or not note_title or not note_note:
            raise ValueError("Missing required note fields")
        
        note = self.notes_service.get_note(note_id,user )
        if note:
            #TODO: WHAT TO DO HERE?
            raise ValueError(f"Note with id {note_id} already exists")
        
        note = self.notes_service.create_note(
            title=note_title,
            content=note_note,
            id=note_id,
            iv=note_iv,
            hmac=note_hmac,
            owner=user,
            note=note
        )

        return note
    
    #TODO: FIX THIS
    def _handle_edit_note(self, action: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
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

        note = action.get('data', {}).get('note')
        if not note:
            raise ValueError("Missing note data")
        
        perms = self.user_service.check_user_note_permissions(user.get("_id"), note)
        if not perms.get("is_editor"):
            raise ValueError("User does not have permission to edit this note")
        
        note_id = note.get('_id')
        note_hmac = note.get('hmac')
        note_iv = note.get('iv')
        note_title = note.get('title')
        note_note = note.get('note')
        note_version = note.get('version')

        _,last_note_version = self.notes_service.get_note_version(note_id)
        if note_version < last_note_version:
            note_version = last_note_version
        elif note_version > last_note_version:
            raise ValueError("Something went wrong with the note versioning (version is higher than the last one)")
        
        note = self.notes_service.create_note(
            title=note_title,
            content=note_note,
            id=note_id,
            iv=note_iv,
            hmac=note_hmac,
            owner=user,
            note=note,
            version=note_version
        )

        return note

    #TODO: FIX THIS
    def _handle_delete_note(self, username: str, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle deleting a note.
        
        :param username: The username of the note deleter
        :param user: User details
        :return: Details of the deleted note
        """
        # Implement note deletion logic
        # This is a placeholder - you'll need to add actual implementation
        note = self.notes_service.delete_note(username=username)
        return note

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
                return ResponseModel(status='error', message='Unsupported operation')

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status='error', message=str(ve))
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status='error', message=str(e))

    def _receive_data(self, secure_sock) -> str:
        data = b""
        while True:
            chunk = secure_sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8")
    
    def verify_signature(self, req: SignedRequestModel) -> bool:
        # Fetch public key from database
        username = req.username
        signature = req.signature
        data = req.data
        public_key_pem = self.user_service.get_user(username)["public_key"]
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        try:
            public_key.verify(
                bytes.fromhex(signature),
                data.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
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
                        client_socket.send(response.json().encode('utf-8'))
                        client_socket.close()

                    except Exception as e:
                        self.logger.error(f"Server error: {e}")

if __name__ == '__main__':#
    from users import get_users_service
    from notes import get_notes_service
    from db_manager import get_database_manager
    
    MONGO_HOST = 'localhost'
    MONGO_PORT = '27017'
    DB_NAME = 'secure_document_db'
    DB_USERNAME = 'admin'
    SERVER_CRT = '/home/vagrant/certs/server/server.pem'
    CA_CRT = '/home/vagrant/certs/ca.crt'

    try:
        with get_database_manager(MONGO_HOST,MONGO_PORT,DB_NAME,) as db_manager:
            user_service = get_users_service(db_manager)
            notes_service = get_notes_service(db_manager)
            server = Server(user_service=user_service, notes_service=notes_service)
            server.start()
    except Exception as e:
        logging.error(f"Error initializing the server: {e}")
        raise