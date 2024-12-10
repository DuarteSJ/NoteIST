# app/database.py
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

class DatabaseConnection:
    """Manages MongoDB database connection"""
    _instance = None
    
    def __new__(cls, uri=None):
        if not cls._instance:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
            cls._instance.uri = uri or "mongodb://teamuser:teampassword@192.168.56.9:27017/teamdb"
            cls._instance.client = None
            cls._instance.db = None
            cls._instance.connect()
        return cls._instance
    
    def connect(self):
        """Establish connection to MongoDB"""
        try:
            self.client = MongoClient(self.uri)
            # Verify the connection
            self.client.admin.command('ismaster')
            self.db = self.client.teamdb
            print("Successfully connected to MongoDB")
        except ConnectionFailure as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise
    
    def get_collection(self, collection_name='documents'):
        """Get a specific collection"""
        return self.db[collection_name]
    
    def close(self):
        """Close the database connection"""
        if self.client:
            self.client.close()
            print("MongoDB connection closed")