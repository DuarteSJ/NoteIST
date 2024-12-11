import logging
from typing import Optional, Dict, Any, List
import datetime

from db_manager import DatabaseManager, get_database_manager
from models import NotesModel

class NotesService:
    """
    Handles business logic for note-specific operations
    Implements validation, permission checks, and note-specific processing
    """
    def __init__(self, database_manager: DatabaseManager):
        """
        Initialize NotesService with a DatabaseManager
        
        Args:
            database_manager (DatabaseManager): Database interaction layer
        """
        self.db_manager = database_manager
        self.logger = logging.getLogger(__name__)

    def create_note(self, 
                    title: str, 
                    content: str, 
                    owner_id: int, 
                    editors: Optional[List[int]] = None, 
                    viewers: Optional[List[int]] = None,
                    hmac: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new note with comprehensive validation
        
        Args:
            title (str): Note title
            content (str): Note content
            owner_id (int): ID of the note owner
            editors (list, optional): List of user IDs who can edit
            viewers (list, optional): List of user IDs who can view
            hmac (str, optional): HMAC for note integrity
        
        Returns:
            Dict containing the created note details
        """
        try:
            # Validate owner exists
            owner = self.db_manager.find_document('users', {'_id': owner_id})
            if not owner:
                raise ValueError(f"User with ID {owner_id} not found")

            # Prepare note data
            note_data = {
                "hmac": hmac or "",  # Optional HMAC
                "title": title,
                "content": content,
                "owner": owner_id,
                "editors": editors or [],
                "viewers": viewers or [],
                "date_created": datetime.datetime.utcnow(),
                "date_modified": datetime.datetime.utcnow(),
                "last_modified_by": owner_id,
                "version": 1
            }

            # Validate using Pydantic model
            note_model = NotesModel(**note_data)

            # Insert note
            note_id = self.db_manager.insert_document(
                'notes', 
                note_model.model_dump(by_alias=True)
            )
            
            # Update user's owned notes
            self.db_manager.update_document(
                'users',
                {'_id': owner_id},
                {'$push': {'owned_notes': note_id}}
            )

            # Log and return
            self.logger.info(f"Note created with ID: {note_id}")
            return {**note_data, "_id": note_id}
        
        except Exception as e:
            self.logger.error(f"Error creating note: {e}")
            raise

    def get_note(self, note_id: str, user_id: int) -> Dict[str, Any]:
        """
        Retrieve a note with permission checks
        
        Args:
            note_id (str): ID of the note to retrieve
            user_id (int): ID of the user requesting the note
        
        Returns:
            Dict containing note details if user has permission
        """
        try:
            # Find the note
            note = self.db_manager.find_document('notes', {'_id': note_id})
            
            if not note:
                raise ValueError("Note not found")
            
            # Check user permissions
            if (user_id != note['owner'] and 
                user_id not in note['editors'] and 
                user_id not in note['viewers']):
                raise PermissionError("User does not have permission to access this note")
            
            return note
        
        except Exception as e:
            self.logger.error(f"Error retrieving note: {e}")
            raise

    def update_note(self, 
                    note_id: str, 
                    user_id: int, 
                    title: Optional[str] = None, 
                    content: Optional[str] = None,
                    hmac: Optional[str] = None) -> Dict[str, Any]:
        """
        Update an existing note with permission checks
        
        Args:
            note_id (str): ID of the note to update
            user_id (int): ID of the user updating the note
            title (str, optional): New title for the note
            content (str, optional): New content for the note
            hmac (str, optional): New HMAC for note integrity
        
        Returns:
            Dict containing updated note details
        """
        try:
            # Find the existing note
            note = self.db_manager.find_document('notes', {'_id': note_id})
            
            if not note:
                raise ValueError("Note not found")
            
            # Check edit permissions
            if user_id not in note['editors'] and user_id != note['owner']:
                raise PermissionError("User does not have permission to edit this note")
            
            # Prepare update
            update_data = {
                "$set": {
                    "last_modified_by": user_id,
                    "date_modified": datetime.datetime.utcnow(),
                    "version": note.get('version', 1) + 1
                }
            }
            
            if title is not None:
                update_data["$set"]["title"] = title
            
            if content is not None:
                update_data["$set"]["content"] = content
            
            if hmac is not None:
                update_data["$set"]["hmac"] = hmac
            
            # Update note
            updated_note = self.db_manager.update_document(
                'notes', 
                {'_id': note_id}, 
                update_data
            )
            
            return updated_note
        
        except Exception as e:
            self.logger.error(f"Error updating note: {e}")
            raise

    def delete_note(self, note_id: str, user_id: int) -> Dict[str, Any]:
        """
        Delete a note with owner permission check
        
        Args:
            note_id (str): ID of the note to delete
            user_id (int): ID of the user deleting the note
        
        Returns:
            Dict with deletion status
        """
        try:
            # Find the existing note
            note = self.db_manager.find_document('notes', {'_id': note_id})
            
            if not note:
                raise ValueError("Note not found")
            
            # Check delete permissions (only owner can delete)
            if user_id != note['owner']:
                raise PermissionError("Only the note owner can delete this note")
            
            # Delete note
            delete_count = self.db_manager.delete_document('notes', {'_id': note_id})
            
            # Remove note from user's owned notes
            self.db_manager.update_document(
                'users',
                {'_id': user_id},
                {'$pull': {'owned_notes': note_id}}
            )
            
            if delete_count:
                return {
                    "status": "success", 
                    "message": "Note deleted successfully",
                    "note_id": note_id
                }
            
            raise ValueError("Note deletion failed")
        
        except Exception as e:
            self.logger.error(f"Error deleting note: {e}")
            raise

    def get_user_notes(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve all notes a user has access to
        
        Args:
            user_id (int): ID of the user
        
        Returns:
            List of notes the user can access
        """
        try:
            # Find notes where user is owner, editor, or viewer
            notes = self.db_manager.find_documents('notes', {
                "$or": [
                    {"owner": user_id},
                    {"editors": user_id},
                    {"viewers": user_id}
                ]
            })
            
            return notes
        
        except Exception as e:
            self.logger.error(f"Error retrieving user notes: {e}")
            raise

# Factory function for creating NotesService
def get_notes_service(mongo_uri='mongodb://localhost:27017', db_name='secure_document_db'):
    """
    Context manager for NotesService to ensure proper connection handling
    
    Usage:
    with get_notes_service() as notes_service:
        notes_service.create_note(...)
    """
    try:
        with get_database_manager(mongo_uri, db_name) as db_manager:
            notes_service = NotesService(db_manager)
            yield notes_service
    except Exception as e:
        logging.error(f"Error in notes service: {e}")
        raise