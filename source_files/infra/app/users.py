import logging
from typing import Dict, Any
from db_manager import DatabaseManager
from models import UsersModel


class UsersService:
    """
    Handles user-related operations including authentication and management
    """

    def __init__(self, database_manager: DatabaseManager):
        """
        Initialize UsersService with a DatabaseManager

        Args:
            database_manager (DatabaseManager): Database interaction layer
        """
        self.db_manager = database_manager
        self.logger = logging.getLogger(__name__)

    def create_user(self, username: str, public_key) -> Dict[str, Any]:
        try:

            # Check if username already exists
            existing_user = self.db_manager.find_document(
                "users", {"username": username}
            )
            if existing_user:
                raise ValueError("Username already exists")

            from uuid import uuid4

            # Prepare user data
            user_data = {
                "id": str(uuid4()),
                "username": username,
                "public_key": public_key,
                "owned_notes": [],
                "editor_notes": [],
                "viewer_notes": [],
                "keys": {},
            }

            # Validate using Pydantic model
            user_model = UsersModel(**user_data)

            # Insert user
            user_id = self.db_manager.insert_document(
                "users", user_model.model_dump(by_alias=True)
            )

            # Log and return (exclude sensitive info)
            self.logger.info(f"User created with ID: {user_id}")
            return user_id

        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            raise

    def update_user_keys(self, user_id: str, note_id: str, key: str):
        """
        Update the keys for a user by adding a note_id and key to their keys dictionary.

        Args:
            user_id (str): The ID of the user
            note_id (str): The note ID to be added as a key
            key (str): The key to be added as the value
        """
        try:
            # Use $set with a dynamic field for the note_id key
            self.db_manager.update_document(
                "users",
                {"id": user_id},
                {"$set": {f"keys.{note_id}": key}}  # Dynamic key update
            )
        except Exception as e:
            self.logger.error(f"Error updating user keys: {e}")
            raise

    def get_user(self, identifier: str, by_username: bool = True) -> Dict[str, Any]:
        """
        Retrieve user details by username or user ID.

        Args:
            identifier (str): The username or user ID of the user.
            by_username (bool): Whether to search by username (default is True). If False, searches by user ID.

        Returns:
            Dict: A dictionary containing user details (excluding sensitive fields).
        """
        try:
            query = {"username": identifier} if by_username else {"id": identifier}

            user = self.db_manager.find_document("users", query)

            if not user:
                raise ValueError("User not found")

            # Exclude sensitive information
            return user

        except Exception as e:
            self.logger.error(f"Error retrieving user: {e}")
            raise

    def check_user_note_permissions(
        self, user_id: int, note: Dict[str, Any]
    ) -> Dict[str, bool]:
        """
        Check a user's permissions for a specific note

        Args:
            user_id (int): ID of the user to check permissions for
            note (Dict[str, Any]): The note document to check permissions against

        Returns:
            Dict[str, bool]: A dictionary containing permission flags
        """
        try:

            # Check if user is the owner
            is_owner = note.get("owner", {}).get("id") == user_id

            # Check if user is an editor
            is_editor = any(
                editor.get("id") == user_id for editor in note.get("editors", [])
            )

            # Check if user is a viewer
            is_viewer = any(
                viewer.get("id") == user_id for viewer in note.get("viewers", [])
            )

            return {
                "is_owner": is_owner,
                "is_editor": is_editor or is_owner,
                "is_viewer": is_viewer or is_editor or is_owner,
            }

        except Exception as e:
            self.logger.error(f"Error checking note permissions: {e}")
            raise

    def add_viewer_note(self, user: Dict[str, any], note_id: int) -> Dict[str, Any]:
        """
        Add a note to the list of notes the user can view

        Args:
            user_id (int): ID of the user
            note_id (int): ID of the note

        Returns:
            Dict[str, Any]: A dictionary containing the updated user document
        """
        # Get user document
        user_id = user.get("id")

        if note_id in user.get("viewer_notes"):
            raise ValueError("Note already exists in viewer notes")

        # Update user document
        self.db_manager.update_documents(
            "users", {"id": user_id}, {"$addToSet": {"viewer_notes": note_id}}
        )

    def remove_viewer_note(self, user: Dict[str, any], note_id: int) -> Dict[str, Any]:
        """
        Remove a note from the list of notes the user can view

        Args:
            user_id (int): ID of the user
            note_id (int): ID of the note

        Returns:
            Dict[str, Any]: A dictionary containing the updated user document
        """
        # Get user document

        user_id = user.get("id")

        if note_id not in user.get("viewer_notes"):
            raise ValueError(
                f"Note {note_id} does not exist in viewer ({user_id}) notes"
            )

        # Update user document
        self.db_manager.update_documents(
            "users", {"id": user_id}, {"$pull": {"viewer_notes": note_id}}
        )

    def add_editor_note(self, user: Dict[str, any], note_id: int) -> Dict[str, Any]:
        """
        Add a note to the list of notes the user can edit

        Args:
            user_id (int): ID of the user
            note_id (int): ID of the note

        Returns:
            Dict[str, Any]: A dictionary containing the updated user document
        """
        # Get user document

        user_id = user.get("id")

        if note_id in user.get("editor_notes"):
            raise ValueError("Note already exists in editor notes")

        # Update user document
        self.db_manager.update_documents(
            "users", {"id": user_id}, {"$addToSet": {"editor_notes": note_id}}
        )

    def remove_editor_note(self, user: Dict[str, any], note_id: int) -> Dict[str, Any]:
        """
        Remove a note from the list of notes the user can edit

        Args:
            user_id (int): ID of the user
            note_id (int): ID of the note

        Returns:
            Dict[str, Any]: A dictionary containing the updated user document
        """
        # Get user document
        user_id = user.get("id")

        if note_id not in user.get("editor_notes"):
            raise ValueError(
                f"Note {note_id} does not exist in editor ({user_id}) notes"
            )

        # Update user document
        self.db_manager.update_documents(
            "users", {"id": user_id}, {"$pull": {"editor_notes": note_id}}
        )


# Factory function for creating UsersService
def get_users_service(db_manager):
    """
    Create a UsersService using the provided DatabaseManager

    Args:
        db_manager (DatabaseManager): An instance of the DatabaseManager

    Returns:
        NotesService: A UsersService instance
    """
    try:
        return UsersService(db_manager)
    except Exception as e:
        logging.error(f"Error in notes service: {e}")
        raise
