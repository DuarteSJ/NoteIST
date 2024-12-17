import logging
from typing import Optional, Dict, Any, List
from pymongo import MongoClient
from contextlib import contextmanager
from logging.handlers import TimedRotatingFileHandler
import ssl
import os


class DatabaseManager:
    """
    Handles low-level database interactions with MongoDB
    Focuses on basic CRUD operations without business logic
    """
    def __init__(self, 
                host: str = 'localhost', 
                port: int = 27017, 
                db_name: str = 'secure_document_db',
                username: Optional[str] = None,
                client_cert_path: Optional[str] = None,
                ca_cert_path: Optional[str] = None
            ):
        # Configure more verbose logging
        os.makedirs('logs', exist_ok=True)

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,  # Set to DEBUG for detailed logs
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),  # Logs to console
                TimedRotatingFileHandler(
                    'logs/mongodb_connection.log',  # File path inside the 'logs' folder
                    when='midnight',  # Rotate at midnight
                    interval=1,  # Interval for rotation (1 day)
                    backupCount=7,  # Optional: keep last 7 log files
                    encoding='utf-8'  # Optional: ensure proper encoding
                )
            ]
        )
        
        self.logger = logging.getLogger(__name__)

        try:
            # Prepare TLS/SSL options
            ssl_context = ssl.create_default_context(cafile=ca_cert_path)
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            # Prepare connection parameters with more detail
            connection_params = {
                'host': f'mongodb://{host}:{port}/{db_name}',
                'tls': True,
                'tlsCAFile': ca_cert_path,
                'tlsAllowInvalidHostnames': False,
            }

            # Add client certificate if provided
            if client_cert_path:
                connection_params.update({
                    'tlsCertificateKeyFile': client_cert_path,
                })

            # Log connection details before connecting
            #self.logger.info(f"Attempting to connect to MongoDB at {host}:{port}")
            #self.logger.debug(f"Connection Parameters: {connection_params}")

            # Establish connection
            self.client = MongoClient(**connection_params)
            self.db = self.client[db_name]

            # Verify connection with detailed logging
            server_info = self.client.server_info()
            self.logger.info("Successfully connected to MongoDB")
            #self.logger.debug(f"Server Information: {server_info}")

            # Additional connection details
            #self.logger.info(f"Connected to Database: {db_name}")
            #self.logger.info(f"Databases available: {self.client.list_database_names()}")

        
        except Exception as e:
            self.logger.error(f"Error initializing MongoDB connection: {e}", exc_info=True)
            raise

    def insert_document(self, collection_name: str, document: Dict[str, Any]) -> str:
        """
        Insert a document into a specified collection
        
        Args:
            collection_name (str): Name of the collection
            document (dict): Document to insert
        
        Returns:
            str: Inserted document's ID
        """
        try:
            collection = self.db[collection_name]
            result = collection.insert_one(document)
            self.logger.info(f"Inserted document in {collection_name} with ID: {result.inserted_id}")
            return str(result.inserted_id)
        except Exception as e:
            self.logger.error(f"Error inserting document in {collection_name}: {e}")
            raise

    def find_document(self, 
                      collection_name: str, 
                      query: Dict[str, Any], 
                      projection: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Find a single document matching the query
        
        Args:
            collection_name (str): Name of the collection
            query (dict): Query to find the document
            projection (dict, optional): Fields to return
        
        Returns:
            dict or None: Found document or None
        """
        try:
            collection = self.db[collection_name]
            document = collection.find_one(query, projection)
            
            if document:
                # Convert ObjectId to string if present
                if '_id' in document:
                    document['_id'] = str(document['_id'])
            
            return document
        except Exception as e:
            self.logger.error(f"Error finding document in {collection_name}: {e}")
            raise

    def find_documents(self, 
                       collection_name: str, 
                       query: Dict[str, Any], 
                       projection: Optional[Dict[str, Any]] = None,
                       limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Find multiple documents matching the query
        
        Args:
            collection_name (str): Name of the collection
            query (dict): Query to find documents
            projection (dict, optional): Fields to return
            limit (int, optional): Maximum number of documents to return
        
        Returns:
            list: List of found documents
        """
        try:
            collection = self.db[collection_name]
            cursor = collection.find(query, projection)
            
            if limit:
                cursor = cursor.limit(limit)
            
            documents = list(cursor)
            
            # Convert ObjectIds to strings
            for doc in documents:
                if '_id' in doc:
                    doc['_id'] = str(doc['_id'])
            
            return documents
        except Exception as e:
            self.logger.error(f"Error finding documents in {collection_name}: {e}")
            raise

    def update_document(self, 
                        collection_name: str, 
                        query: Dict[str, Any], 
                        update: Dict[str, Any], 
                        upsert: bool = False) -> Dict[str, Any]:
        """
        Update a document in the specified collection
        
        Args:
            collection_name (str): Name of the collection
            query (dict): Query to find the document
            update (dict): Update operations
            upsert (bool): Insert document if not found
        
        Returns:
            dict: Updated document
        """
        try:
            collection = self.db[collection_name]
            result = collection.find_one_and_update(
                query, 
                update, 
                return_document=True,
                upsert=upsert
            )
            
            if result:
                result['_id'] = str(result['_id'])
                self.logger.info(f"Updated document in {collection_name}")
                return result
            
            return {}
        except Exception as e:
            self.logger.error(f"Error updating document in {collection_name}: {e}")
            raise

    def delete_document(self, collection_name: str, query: Dict[str, Any]) -> int:
        """
        Delete document(s) matching the query
        
        Args:
            collection_name (str): Name of the collection
            query (dict): Query to find documents to delete
        
        Returns:
            int: Number of deleted documents
        """
        try:
            collection = self.db[collection_name]
            result = collection.delete_many(query)
            
            self.logger.info(f"Deleted {result.deleted_count} documents from {collection_name}")
            return result.deleted_count
        except Exception as e:
            self.logger.error(f"Error deleting documents from {collection_name}: {e}")
            raise

    def close_connection(self):
        """
        Close the MongoDB connection
        """
        if self.client:
            self.client.close()
            self.logger.info("MongoDB connection closed")

@contextmanager
def get_database_manager(
    host: str = '192.168.56.17', 
    port: int = 27017, 
    db_name: str = 'secure_document_db',
    username: Optional[str] = None,
    client_cert_path: Optional[str] = None,
    ca_cert_path: Optional[str] = None,
):
    
    manager = None
    try:
        manager = DatabaseManager(
            host=host, 
            port=port, 
            db_name=db_name,
            username=username,
            client_cert_path=client_cert_path,
            ca_cert_path=ca_cert_path
        )
        yield manager
    except Exception as e:
        logging.error(f"Error in database manager: {e}")
        raise
    finally:
        if manager:
            manager.close_connection()

