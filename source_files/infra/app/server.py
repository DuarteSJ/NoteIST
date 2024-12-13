import socket
import ssl
import json
import logging
from pymongo import MongoClient
from pydantic import ValidationError
    
# Import the new Pydantic models
from models import (
    RequestModelType, 
    RequestFactory, 
    ResponseModel, 
    RequestType
)

class Server:
    def __init__(self, 
                 user_service,
                 notes_service,
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

    def handle_request(self, request: RequestModelType) -> ResponseModel:
        """
        Handle different document operations by delegating to the appropriate service.
        """
        try:
            if request.type == RequestType.CREATE_NOTE:
                # Assuming create_note now takes username and document
                note_id = self.notes_service.create_note(
                    username=request.username, 
                    document=request.document
                )
                return ResponseModel(status='success', message='Document created', document={'_id': str(note_id)})

            elif request.type == RequestType.GET_NOTE:
                # Assuming get_note now takes username and note_id
                document = self.notes_service.get_note(
                    username=request.username, 
                    note_id=request.note_id
                )
                return ResponseModel(status='success', message='Document retrieved', document=document)

            elif request.type == RequestType.GET_USER_NOTES:
                # Retrieve all notes for the user
                documents = self.notes_service.get_user_notes(username=request.username)
                return ResponseModel(status='success', message='User notes retrieved', documents=documents)

            elif request.type == RequestType.EDIT_NOTE:
                # Edit a specific note
                self.notes_service.edit_note(
                    username=request.username, 
                    note_id=request.note_id, 
                    document=request.document
                )
                return ResponseModel(status='success', message='Document updated')

            elif request.type == RequestType.DELETE_NOTE:
                # Delete a specific note
                self.notes_service.delete_note(
                    username=request.username, 
                    note_id=request.note_id
                )
                return ResponseModel(status='success', message='Document deleted')

            else:
                return ResponseModel(status='error', message='Unsupported operation')

        except ValidationError as ve:
            self.logger.error(f"Validation Error: {ve}")
            return ResponseModel(status='error', message=str(ve))
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return ResponseModel(status='error', message=str(e))

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
                        data = client_socket.recv(4096)
                        request_dict = json.loads(data.decode('utf-8'))

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
    
    MONGO_URI = 'mongodb://localhost:27017'
    DB_NAME = 'secure_document_db'
    
    try:
        with get_database_manager(MONGO_URI, DB_NAME) as db_manager:
            user_service = get_users_service(db_manager)
            notes_service = get_notes_service(db_manager)
            server = Server(user_service=user_service, notes_service=notes_service)
            server.start()
    except Exception as e:
        logging.error(f"Error initializing the server: {e}")
        raise