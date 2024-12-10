# setup/dbOperations.py
from bson import ObjectId
from typing import List, Optional
from database import DatabaseConnection
from models import DocumentModel


class SaraPareceCRUD:
    """CRUD operations for documents"""

    def __init__(self, collection_name="notes"):
        # Vamos ter notes, users
        self.db_connection = DatabaseConnection()
        self.collection = self.db_connection.get_collection(collection_name)

    def create(self, document: DocumentModel) -> DocumentModel:
        """Create a new document"""
        # Convert to dictionary, excluding the ID if it's None
        print("create")
        document_dict = document.dict(exclude_unset=True)
        if "id" in document_dict:
            del document_dict["id"]

        # Insert the document
        result = self.collection.insert_one(document_dict)

        # Retrieve the full document to return
        created_document = self.collection.find_one({"_id": result.inserted_id})
        return DocumentModel(**created_document)

    def read_all(self) -> List[DocumentModel]:
        """Retrieve all documents"""
        documents = list(self.collection.find())
        return [DocumentModel(**doc) for doc in documents]

    def read_by_id(self, document_id: str) -> Optional[DocumentModel]:
        """Retrieve a single document by ID"""
        document = self.collection.find_one({"_id": ObjectId(document_id)})
        return DocumentModel(**document) if document else None

    def update(
        self, document_id: str, document: DocumentModel
    ) -> Optional[DocumentModel]:
        """Update an existing document"""
        # Convert to dictionary, excluding the ID
        update_data = document.dict(exclude_unset=True, exclude={"id"})

        # Perform the update
        result = self.collection.update_one(
            {"_id": ObjectId(document_id)}, {"$set": update_data}
        )

        # Check if document was updated
        if result.modified_count == 0:
            return None

        # Retrieve and return the updated document
        updated_document = self.collection.find_one({"_id": ObjectId(document_id)})
        return DocumentModel(**updated_document)

    def delete(self, document_id: str) -> bool:
        """Delete a document by ID"""
        result = self.collection.delete_one({"_id": ObjectId(document_id)})
        return result.deleted_count > 0
