import socket
import ssl
import json
import logging
from typing import Dict, Any
from pymongo import MongoClient
from bson import ObjectId
from pydantic import ValidationError

# Import the Pydantic models
from models import RequestModel, ResponseModel

class Server:
    def __init__(self, 
                 host='0.0.0.0', 
                 port=5000, 
                 cert_path='/home/vagrant/setup/certs/server.crt', 
                 key_path='/home/vagrant/setup/certs/server.key',
                 mongo_uri='mongodb://192.168.56.17:27017'):
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # MongoDB connection
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

        # Disable client certificate verification by setting CERT_NONE
        self.context.verify_mode = ssl.CERT_NONE  # No client certificate verification

        # Optionally, load CA certificate if needed for server certificate validation
        # self.context.load_verify_locations(cafile='/home/vagrant/setup/certs/ca.crt')  # Not required now

    def handle_request(self, request: RequestModel) -> ResponseModel:
        """
        Handle different document operations with Pydantic validation
        """
        try:
            # Implement the request handling logic here
            if request.operation == OperationType.CREATE:
                document = DocumentModel(**request.document)
                result = self.collection.insert_one(document.dict(by_alias=True))
                return ResponseModel(status='success', message='Document created', document={'_id': str(result.inserted_id)})
            elif request.operation == OperationType.READ:
                document = self.collection.find_one({'_id': ObjectId(request.document_id)})
                if document:
                    return ResponseModel(status='success', message='Document found', document=document)
                else:
                    return ResponseModel(status='error', message='Document not found')
            elif request.operation == OperationType.UPDATE:
                document = DocumentModel(**request.document)
                result = self.collection.update_one({'_id': ObjectId(request.document_id)}, {'$set': document.dict(by_alias=True)})
                if result.modified_count > 0:
                    return ResponseModel(status='success', message='Document updated')
                else:
                    return ResponseModel(status='error', message='Document not found')
            elif request.operation == OperationType.DELETE:
                result = self.collection.delete_one({'_id': ObjectId(request.document_id)})
                if result.deleted_count > 0:
                    return ResponseModel(status='success', message='Document deleted')
                else:
                    return ResponseModel(status='error', message='Document not found')
            
            pass
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
    server = Server()
    server.start()