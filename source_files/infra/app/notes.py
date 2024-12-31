import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from db_manager import DatabaseManager
from pymongo.errors import DuplicateKeyError


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

    def create_note(
        self,
        title: str,
        content: str,
        id: int,
        iv: str,
        hmac: str,
        owner: Dict[str, Any],
        editors: Optional[List[int]] = None,
        viewers: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        try:
            # Prepare note data
            owner_id = owner.get("id")

            note_data = {
                "id": id,
                "iv": iv,
                "hmac": hmac,
                "title": title,
                "note": content,
                "date_created": datetime.now(timezone.utc),
                "date_modified": datetime.now(timezone.utc),
                "last_modified_by": owner_id,
                "version": 1,
                "owner": {"id": owner_id, "username": owner.get("username")},
                "editors": [{"id": editor} for editor in (editors or [])],
                "viewers": [{"id": viewer} for viewer in (viewers or [])],
            }

            # Insert note
            self.db_manager.insert_document("notes", note_data)

            # Update user's owned notes
            self.db_manager.update_document(
                "users", {"id": owner_id}, {"$push": {"owned_notes": id}}
            )
            # Log and return
            self.logger.info(f"Note created with ID: {id}")
            return {**note_data, "id": id}

        except Exception as e:
            self.logger.error(f"Error creating note: {e}")
            raise

    def edit_note(
        self,
        title: str,
        content: str,
        id: int,
        iv: str,
        hmac: str,
        owner: Dict[str, Any],
        editor: Dict[str, Any],
        version: int,
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        retries = 0
        while retries < max_retries:
            try:
                # First, retrieve the existing note to get the current version and other details
                existing_note = self.get_note(id, owner.get("id"))
                last_server_version = existing_note.get("version")

                if not existing_note:
                    raise ValueError("Note no longer exists")

                if last_server_version < version:
                    version = last_server_version + 1
                elif last_server_version > version:
                    raise ValueError(
                        "Something went wrong with the versioning. Trying restarting the app."
                    )

                # Prepare note data for the new version
                note_data = {
                    "id": id,
                    "iv": iv,
                    "hmac": hmac,
                    "title": title,
                    "note": content,
                    "date_created": existing_note[
                        "date_created"
                    ],  # Keep original creation date
                    "date_modified": datetime.now(timezone.utc),
                    "last_modified_by": editor.get("id"),
                    "version": version,
                    "owner": existing_note["owner"],
                    "editors": existing_note.get("editors", []),
                    "viewers": existing_note.get("viewers", []),
                }

                # Insert the new version of the note
                note_id = self.db_manager.insert_document("notes", note_data)

                # Log and return
                self.logger.info(
                    f"Note edited with ID: {note_id}, new version: {version}"
                )
                return {**note_data, "id": note_id}

            except Exception as e:
                self.logger.error(f"Error editing note: {e}")
                raise
            except DuplicateKeyError:
                # Increment retry counter and try again
                retries += 1
                print(
                    f"DuplicateKeyError encountered, retrying... Attempt {retries}/{max_retries}"
                )
        raise ValueError("Failed to insert a new version after multiple retries")

    def get_all_versions_of_note(self, note_id: str, owner_id: str) -> Dict[str, Any]:
        """
        Retrieve the latest version of a note for a given note ID and owner

        Args:
            note_id (str): ID of the note to retrieve
            owner_id (int): ID of the note owner

        Returns:
            Dict containing the latest version of the note, or None if not found
        """
        try:

            # Find the latest version of the note
            result = self.db_manager.find_documents(
                "notes", {"id": note_id, "owner.id": owner_id}
            )

            if not result:
                return False

            if isinstance(result, dict):
                return result

            all_versions = list(result)
            return all_versions

        except Exception as e:
            self.logger.error(f"Error retrieving note: {e}")
            raise

    def get_note(self, note_id: str, owner_id: str) -> Dict[str, Any]:
        """
        Retrieve the latest version of a note for a given note ID and owner

        Args:
            note_id (str): ID of the note to retrieve
            owner_id (int): ID of the note owner

        Returns:
            Dict containing the latest version of the note, or None if not found
        """
        try:

            # Find the latest version of the note
            result = self.db_manager.find_documents(
                "notes", {"id": note_id, "owner.id": owner_id}
            )

            if not result:
                return False

            if isinstance(result, dict):
                return result

            all_versions = list(result)
            latest_note = max(all_versions, key=lambda x: int(x["version"]))
            return latest_note

        except Exception as e:
            self.logger.error(f"Error retrieving note: {e}")
            raise

    def delete_note(self, note_id: str, user_id: int) -> Dict[str, Any]:
        """
        Delete all notes with the given _id and owner[_id] equal to user_id.

        Args:
            note_id (str): ID of the notes to delete.
            user_id (int): ID of the user deleting the notes.

        Returns:
            Dict: Deletion status.
        """
        try:
            # Query to find notes with matching _id and owner._id
            query = {"id": note_id, "owner.id": user_id}

            # Find matching notes
            notes = self.db_manager.find_documents("notes", query)

            if not notes:
                raise ValueError("No notes found")

            # Delete the matching notes
            delete_count = self.db_manager.delete_documents("notes", query)

            # Update the user's owned notes list
            self.db_manager.update_document(
                "users", {"id": user_id}, {"$pull": {"owned_notes": note_id}}
            )

            if delete_count:
                return {
                    "status": "success",
                    "message": f"{delete_count} note(s) deleted successfully",
                    "note_id": note_id,
                }

            raise ValueError("Note deletion failed")

        except Exception as e:
            self.logger.error(f"Error deleting notes: {e}")
            raise

    def get_user_notes(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve all notes a user has access to

        Args:
            user_id (str): ID of the user

        Returns:
            List of notes the user can access
        """
        try:
            # Find notes where user is owner, editor, or viewer
            notes = self.db_manager.find_documents(
                "notes",
                {
                    "$or": [
                        {"owner.id": user_id},
                        {"editors.id": user_id},
                        {"viewers.id": user_id},
                    ]
                },
            )

            return notes

        except Exception as e:
            self.logger.error(f"Error retrieving user notes: {e}")
            raise

    def add_viewer_to_note(
        self, note: Dict[str, Any], owner_id: int, viewer: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add a viewer to a note

        Args:
            note_id (str): ID of the note
            owner_id (int): ID of the note owner
            user_id (int): ID of the user to add as a viewer

        Returns:
            Dict with status of the operation
        """

        # Check if the requesting user is the owner
        if owner_id != note["owner"]["id"]:
            raise PermissionError("Only the note owner can add viewers")
        user_id = viewer.get("id")
        note_id = note.get("id")
        # Check if the user is already a viewer
        if user_id in note.get("viewers", []):
            raise ValueError(
                f"User {user_id} is already a viewer for the note {note_id}"
            )

        # Add user as a viewer
        self.db_manager.update_documents(
            "notes",
            {"id": note_id},
            {"$push": {"viewers": {"id": user_id, "username": viewer.get("username")}}},
        )

    def remove_viewer_from_note(
        self, note: Dict[str, Any], owner_id: int, viewer_id: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Remove a viewer from a note

        Args:
            note (Dict[str, Any]): The note document
            owner_id (int): ID of the note owner
            user_id (int): ID of the user to remove as a viewer

        Returns:
            Dict with status of the operation
        """
        # Find the note ID
        note_id = note.get("id")

        # Check if the requesting user is the owner
        if owner_id != note["owner"]["id"]:
            raise PermissionError("Only the note owner can remove viewers")

        # Check if the user is a viewer
        viewer_exists = any(
            vie.get("id") == viewer_id for vie in note.get("viewers", [])
        )
        if not viewer_exists:
            raise ValueError("User is not a viewer")

        # Remove the viewer
        self.db_manager.update_documents(
            "notes",
            {"id": note_id},
            {
                "$pull": {"viewers": {"id": viewer_id}}
            },  # Remove dictionary matching user_id
        )

    def add_editor_to_note(
        self, note: Dict[str, Any], owner_id: int, editor: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Add an editor to a note

        Args:
            note_id (str): ID of the note
            owner_id (int): ID of the note owner
            user_id (int): ID of the user to add as an editor

        Returns:
            Dict with status of the operation
        """
        note_id = note.get("id")
        editor_id = editor.get("id")

        # Check if the requesting user is the owner
        if owner_id != note["owner"]["id"]:
            raise PermissionError("Only the note owner can add editors")

        # Check if the user is already an editor
        if editor_id in note.get("editors", []):
            raise ValueError("User is already an editor")

        # Add user as an editor
        self.db_manager.update_documents(
            "notes",
            {"id": note_id},
            {
                "$push": {
                    "editors": {"id": editor_id, "username": editor.get("username")}
                }
            },
        )

    def remove_editor_from_note(
        self, note: Dict[str, Any], owner_id: str, editor_id: str
    ) -> Dict[str, Any]:
        """
        Remove an editor from a note

        Args:
            note (Dict[str, Any]): The note document
            owner_id (int): ID of the note owner
            user_id (int): ID of the user to remove as an editor

        Returns:
            Dict with status of the operation
        """
        # Find the note ID
        note_id = note.get("id")

        # Check if the requesting user is the owner
        if owner_id != note["owner"]["id"]:
            raise PermissionError("Only the note owner can remove editors")

        # Check if the user is an editor
        editor_exists = any(ed["id"] == editor_id for ed in note.get("editors", []))
        if not editor_exists:
            raise ValueError("User is not an editor")

        # Remove the editor
        self.db_manager.update_documents(
            "notes",
            {"id": note_id},
            {
                "$pull": {"editors": {"id": editor_id}}
            },  # Remove dictionary matching user_id
        )


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
