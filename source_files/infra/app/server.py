import socket
import ssl
import json
import logging
from pymongo import MongoClient
from pydantic import ValidationError
    
# Import the Pydantic models
from models import RequestModel, ResponseModel, RequestType

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

    def handle_request(self, request: RequestModel) -> ResponseModel:
        """
        Handle different document operations by delegating to the appropriate service.
        """
        try:
            if request.operation == RequestType.CREATE_NOTE:
                result = self.notes_service.create_note(request.document)
                return ResponseModel(status='success', message='Document created', document={'_id': str(result)})

            elif request.operation == RequestType.GET_NOTE:
                pass
                document = self.notes_service.get_note(request.document_id)

            elif request.operation == RequestType.GET_USER_NOTES:
                pass
                #result = self.notes_service.update_note_by_id(request.document_id, request.document)

            elif request.operation == RequestType.EDIT_NOTE:
                pass
                #result = self.notes_service.delete_note_by_id(request.document_id)

            elif request.operation == RequestType.DELETE_NOTE:
                pass
            

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

                        # Validate request
                        request = RequestModel(**request_dict)

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
            user_service = get_users_service()
            notes_service = get_notes_service(db_manager)
            server = Server(user_service=user_service, notes_service=notes_service)
            server.start()
    except Exception as e:
        logging.error(f"Error initializing the server: {e}")
        raise