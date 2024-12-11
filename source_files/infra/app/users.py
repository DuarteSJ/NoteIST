import logging
from typing import Optional, Dict, Any
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

    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple[str, str]:
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
                    password: str) -> Dict[str, Any]:
        """
        Create a new user
        
        Args:
            username (str): Unique username
            password (str): User's password
        
        Returns:
            Dict with user details
        """
        try:
            # Check if username already exists
            existing_user = self.db_manager.find_document('users', {'username': username})
            if existing_user:
                raise ValueError("Username already exists")
            
            # Validate password
            if not self._validate_password(password):
                raise ValueError("Password does not meet complexity requirements")
            
            # Hash password
            password_hash, salt = self._hash_password(password)
            
            # Prepare user data
            user_data = {
                "username": username,
                "password": password_hash,
                "hash_of_digest": salt,
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
            return {
                "_id": user_id,
                "username": username,
                "owned_notes": [],
                "editor_notes": [],
                "viewer_notes": []
            }
        
        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            raise

    def authenticate_user(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate a user
        
        Args:
            username (str): User's username
            password (str): User's password
        
        Returns:
            Dict with user details if authentication succeeds
        """
        try:
            # Find user
            user = self.db_manager.find_document('users', {'username': username})
            
            if not user:
                raise ValueError("User not found")
            
            # Verify password
            stored_hash = user['password']
            salt = user['hash_of_digest']
            
            # Regenerate hash with stored salt
            input_hash, _ = self._hash_password(password, salt)
            
            if input_hash != stored_hash:
                raise ValueError("Invalid credentials")
            
            # Return user details (excluding sensitive info)
            return {
                "_id": user['_id'],
                "username": user['username'],
                "owned_notes": user.get('owned_notes', []),
                "editor_notes": user.get('editor_notes', []),
                "viewer_notes": user.get('viewer_notes', [])
            }
        
        except Exception as e:
            self.logger.error(f"Error authenticating user: {e}")
            raise

    def update_user_password(self, 
                              user_id: str, 
                              current_password: str, 
                              new_password: str) -> Dict[str, Any]:
        """
        Update user's password with current password verification
        
        Args:
            user_id (str): ID of the user
            current_password (str): User's current password
            new_password (str): New password to set
        
        Returns:
            Dict with update status
        """
        try:
            # Find user
            user = self.db_manager.find_document('users', {'_id': user_id})
            
            if not user:
                raise ValueError("User not found")
            
            # Verify current password
            stored_hash = user['password']
            salt = user['hash_of_digest']
            
            input_hash, _ = self._hash_password(current_password, salt)
            
            if input_hash != stored_hash:
                raise ValueError("Current password is incorrect")
            
            # Validate new password
            if not self._validate_password(new_password):
                raise ValueError("New password does not meet complexity requirements")
            
            # Hash new password
            new_password_hash, new_salt = self._hash_password(new_password)
            
            # Update password
            self.db_manager.update_document(
                'users',
                {'_id': user_id},
                {
                    "$set": {
                        "password": new_password_hash,
                        "hash_of_digest": new_salt
                    }
                }
            )
            
            return {
                "status": "success",
                "message": "Password updated successfully"
            }
        
        except Exception as e:
            self.logger.error(f"Error updating user password: {e}")
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
def get_users_service(mongo_uri='mongodb://localhost:27017', db_name='secure_document_db'):
    """
    Context manager for UsersService to ensure proper connection handling

    Usage:
    with get_users_service() as users_service:
        users_service.create_user(...)
    """
    try:
        with get_database_manager(mongo_uri, db_name) as db_manager:
            users_service = UsersService(db_manager)
            yield users_service
    except Exception as e:
        logging.error(f"Error in users service: {e}")
        raise
