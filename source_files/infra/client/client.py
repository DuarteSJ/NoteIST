import socket
import ssl
import json
import logging
from typing import Dict, Any

# Import the Pydantic models
from app.models import RequestModel, ResponseModel, DocumentModel, OperationType

class SecureDocumentClient:
    def __init__(self, 
                 host='localhost', 
                 port=5000, 
                 ca_cert_path='/path/to/ca.crt'):
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        self.host = host
        self.port = port
        
        # TLS context setup
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations(ca_cert_path)

    def send_request(self, request: RequestModel) -> ResponseModel:
        """
        Send a request to the secure document server
        """
        try:
            with socket.create_connection((self.host, self.port)) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.host) as secure_sock:
                    # Send request
                    secure_sock.send(request.json().encode('utf-8'))
                    
                    # Receive response
                    response_data = secure_sock.recv(4096)
                    response_dict = json.loads(response_data.decode('utf-8'))
                    
                    return ResponseModel(**response_dict)
        
        except Exception as e:
            self.logger.error(f"Client request error: {e}")
            return ResponseModel(status='error', message=str(e))

    def create_document(self, document: DocumentModel):
        """Create a new document"""
        request = RequestModel(operation=OperationType.CREATE, document=document)
        return self.send_request(request)

    # Add other CRUD methods (read_document, update_document, delete_document)