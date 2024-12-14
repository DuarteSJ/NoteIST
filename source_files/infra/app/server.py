import socket
import ssl
import json
import logging
from pymongo import MongoClient
from pydantic import ValidationError
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from users import UsersService
from notes import NotesService
# Import the new Pydantic models
from models import (
    RequestType,
    ResponseModel,
    RequestModelType,
    RequestFactory,
    RegisterRequest,
    PullRequest,
    PushRequest,
    SignedRequestModel
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
                #TODO: oq se faz aqui?
                digest_of_hmacs = ""
                pass
            documents = self.notes_service.get_user_notes(username=req.username)

            return ResponseModel(status='success', message='Document retrieved', document=document)
        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status='error', message=str(ve))
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status='error', message=str(e))


    def handle_request(self, request: RequestModelType) -> ResponseModel:
        """
        Handle different document operations by delegating to the appropriate service.
        """
        try:
            if request.type == RequestType.REGISTER:
                # Assuming create_note now takes username and document
                user_id = self.handle_register_request(req=request)
                return ResponseModel(status='success', message='Document created', document={'_id': str(user_id)})

            elif request.type == RequestType.PULL:
                # Assuming get_note now takes username and note_id
                document = self.notes_service.get_note(
                    username=request.username, 
                    note_id=request.note_id
                )
                return ResponseModel(status='success', message='Document retrieved', document=document)

            elif request.type == RequestType.PUSH:
                # Retrieve all notes for the user
                documents = self.notes_service.get_user_notes(username=request.username)
                return ResponseModel(status='success', message='User notes retrieved', documents=documents)


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

if __name__ == '__main__':
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