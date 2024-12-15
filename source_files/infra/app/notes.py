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
                id: int,
                iv: str,
                hmac: str,
                owner: Dict[str, Any],
                editors: Optional[List[int]] = None, 
                viewers: Optional[List[int]] = None) -> Dict[str, Any]:
        try:
            # Prepare note data
            owner_id = owner.get('id')
            note_data = {
                "_id": id,
                "iv": iv,
                "hmac": hmac,
                "title": title,
                "note": content,
                "date_created": datetime.datetime.now(datetime.timezone.utc),
                "date_modified": datetime.datetime.now(datetime.timezone.utc),
                "last_modified_by": owner_id,
                "version": 1,
                "owner": {
                        "id": owner_id,
                        "username": owner.get('username')
                        },
                "editors": [{"id": editor} for editor in (editors or [])],
                "viewers": [{"id": viewer} for viewer in (viewers or [])],
            }

            # Insert note
            note_id = self.db_manager.insert_document(
                'notes', 
                note_data
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

    def get_note(self, note_id: str, owner_id: int, version: int = None) -> Dict[str, Any]:
        """
        Retrieve a note with permission checks using unique identifiers
        
        Args:
            note_id (str): ID of the note to retrieve
            owner_id (int): ID of the note owner
            version (int, optional): Version of the note. Defaults to 1.
        
        Returns:
            Dict containing note details if user has permission
        """
        try:
            # Find the note using the unique combination of identifiers
            if version:
                note = self.db_manager.find_document('notes', {
                    '_id': note_id, 
                    'version': version,
                    'owner.id': owner_id
                })
            else:
                note = self.db_manager.find_document('notes', {
                    '_id': note_id, 
                    'owner.id': owner_id
                })
            
            if not note:
                return None
            
            #TODO: is this needed?
            # # Check user permissions
            # # Check if the requesting user is the owner, an editor, or a viewer
            # is_owner = owner_id == note['owner']['id']
            # is_editor = any(editor['id'] == owner_id for editor in note.get('editors', []))
            # is_viewer = any(viewer['id'] == owner_id for viewer in note.get('viewers', []))
            
            # if not (is_owner or is_editor or is_viewer):
            #     raise PermissionError("User does not have permission to access this note")
            
            return note
        
        except Exception as e:
            self.logger.error(f"Error retrieving note: {e}")
            raise

    def edit_note(self, 
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


def get_notes_service(db_manager):
    """
    Create a NotesService using the provided DatabaseManager
    
    Args:
        db_manager (DatabaseManager): An instance of the DatabaseManager
    
    Returns:
        NotesService: A NotesService instance
    """
    try:
        return NotesService(db_manager)
    except Exception as e:
        logging.error(f"Error in notes service: {e}")
        raise