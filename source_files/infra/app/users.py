import logging
from typing import Optional, Dict, Any, Tuple
import hashlib
import secrets
import re
from db_manager import DatabaseManager, get_database_manager
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

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate a secure hash for the password
        
        Args:
            password (str): User's password
            salt (str, optional): Existing salt or generate a new one
        
        Returns:
            tuple of (hashed_password, salt)
        """
        if not salt:
            salt = secrets.token_hex(16)  # 32 character salt
        
        # Use a strong hashing method
        salted_password = f"{salt}{password}"
        password_hash = hashlib.sha256(salted_password.encode()).hexdigest()
        
        return password_hash, salt

    def _validate_password(self, password: str) -> bool:
        """
        Validate password strength
        
        Args:
            password (str): Password to validate
        
        Returns:
            bool: Whether password meets requirements
        """
        # Check password complexity
        # if len(password) < 8:
        #     return False
        
        # At least one uppercase, one lowercase, one number
        # if not re.search(r'[A-Z]', password):
        #     return False
        # if not re.search(r'[a-z]', password):
        #     return False
        # if not re.search(r'\d', password):
        #     return False
        
        return True

    def create_user(self, 
                    username: str, 
                    public_key) -> Dict[str, Any]:
        try:
            
            # Check public key
            if not isinstance(public_key, bytes):
                raise ValueError("Public key must be in bytes format")

            # Check if username already exists
            existing_user = self.db_manager.find_document('users', {'username': username})
            if existing_user:
                raise ValueError("Username already exists")
            
            # Prepare user data
            user_data = {
                "username": username,
                "public_key": public_key,
                "hash_of_digest": "",
                "owned_notes": [],
                "editor_notes": [],
                "viewer_notes": []
            }
            
            # Validate using Pydantic model
            user_model = UsersModel(**user_data)
            
            # Insert user
            user_id = self.db_manager.insert_document(
                'users', 
                user_model.model_dump(by_alias=True)
            )
            
            # Log and return (exclude sensitive info)
            self.logger.info(f"User created with ID: {user_id}")
            return user_id
        
        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
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
            query = {'username': identifier} if by_username else {'_id': identifier}

            user = self.db_manager.find_document('users', query)

            if not user:
                raise ValueError("User not found")

            # Exclude sensitive information
            return {
                "_id": user['_id'],
                "username": user['username'],
                "public_key": user.get('public_key', None),
                "owned_notes": user.get('owned_notes', []),
                "editor_notes": user.get('editor_notes', []),
                "viewer_notes": user.get('viewer_notes', [])
            }

        except Exception as e:
            self.logger.error(f"Error retrieving user: {e}")
            raise

    def delete_user(self, user_id: str, password: str) -> Dict[str, Any]:
        """
        Delete a user account after password verification

        Args:
            user_id (str): ID of the user to delete
            password (str): User's current password

        Returns:
            Dict with deletion status
        """
        try:
            # Find user
            user = self.db_manager.find_document('users', {'_id': user_id})

            if not user:
                raise ValueError("User not found")

            # Verify password
            stored_hash = user['password']
            salt = user['hash_of_digest']

            input_hash, _ = self._hash_password(password, salt)

            if input_hash != stored_hash:
                raise ValueError("Password verification failed")

            # Delete user document
            self.db_manager.delete_document('users', {'_id': user_id})

            # Log and return success message
            self.logger.info(f"User with ID {user_id} successfully deleted")
            return {
                "status": "success",
                "message": "User account deleted successfully"
            }

        except Exception as e:
            self.logger.error(f"Error deleting user: {e}")
            raise

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