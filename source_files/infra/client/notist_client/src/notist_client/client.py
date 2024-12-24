import os
import shutil
from typing import Optional, List, Dict, Any
from .crypto.keys import KeyManager
from .network.handler import NetworkHandler
from .utils.file import FileHandler
from .models.actions import ActionType
from .models.responses import Response
from .config.paths import get_config_dir, get_data_dir

class NoteISTClient:
    """
    Main client class for the NoteIST application. Handles user management,
    note operations, and synchronization with the server.
    """
    
    def __init__(self, host: str, port: int, cert_path: str):
        """
        Initialize the NoteIST client with server configuration and set up local directories.
        
        Args:
            host: Server hostname
            port: Server port number
            cert_path: Path to SSL certificate
        """
        # Initialize configuration paths
        self.base_config_dir = get_config_dir()
        self.base_data_dir = get_data_dir()
        self.notes_dir = os.path.join(self.base_data_dir, "notes")
        self.priv_key_path = os.path.join(self.base_config_dir, "priv_key.pem")
        self.username_path = os.path.join(self.base_config_dir, "username.json")

        # Server configuration
        self.host = host
        self.port = port
        self.cert_path = cert_path
        
        # Instance attributes
        self.username = None
        self.network_handler = None
        self.changes = []
        self.id_counter = 0

        # Set up the environment
        self._initialize_environment()

    def _initialize_environment(self) -> None:
        """Set up necessary directories and load or create user configuration."""
        # Create required directories
        FileHandler.ensure_directory(self.base_config_dir)
        FileHandler.ensure_directory(self.base_data_dir)
        FileHandler.ensure_directory(self.notes_dir)

        # Load existing configuration or register new user
        self._load_or_register_user()

    def _load_or_register_user(self) -> None:
        """Load existing user configuration or start new user registration process."""
        if not os.path.exists(self.priv_key_path):
            self._register_new_user()
            return
        
        try:
            self._login()
        except Exception:
            self._register_new_user()

    def _login(self) -> None:
        """Log in existing user and sync with server."""
        try:
            # Load username from stored configuration
            user_data = FileHandler.read_json(self.username_path)
            self.username = user_data["username"]
            
            if not self.username:
                raise ValueError("Username not found in configuration")

            # Initialize network handler
            self.network_handler = NetworkHandler(
                self.username,
                self.host,
                self.port,
                self.cert_path
            )

            # Sync with server
            self.pull_changes()
            
    def _register_new_user(self) -> None:
        """Handle the registration process for a new user."""
        while True:
            try:
                # Get username from user
                username = input("Enter your username (must be unique): ").strip()
                if not username:
                    print("Username cannot be empty. Please try again.")
                    continue

                # Generate and store key pair
                self.username = username
                public_key = KeyManager.generate_key_pair(self.priv_key_path)
                
                # Initialize network handler
                self.network_handler = NetworkHandler(
                    username,
                    self.host,
                    self.port,
                    self.cert_path
                )

                # Register with server
                response = self.network_handler.register_user(
                    KeyManager.get_public_key_json_serializable(public_key)
                )
                
                if response.status == "error":
                    raise Exception(f"Server registration failed: {response.message}")

                # Save username to configuration
                FileHandler.write_json(
                    self.username_path,
                    {"username": username}
                )

                print(f"Welcome to NoteIST, {username}!")
                break

            except Exception as e:
                print(f"Registration error: {e}")
                retry = input("Would you like to try again? [yes/no] ")
                if retry.lower() not in ["yes", "y"]:
                    print("Exiting NoteIST. Goodbye!")
                    exit(0)

    def pull_changes(self) -> None:
        """Synchronize local state with server."""
        try:
            response = self.network_handler.pull_changes(self.priv_key_path)
            if response.status == "error":
                raise Exception(f"Sync failed: {response.message}")
            
            # Process and apply server changes locally
            if response.documents:
                self._apply_server_changes(response.documents)
            return response #TODO: this ret is not required, just cause we printing it in main for now

        except Exception as e:
            raise Exception(f"Sync failed: {e}")

    def _apply_server_changes(self, changes: List[Dict[str, Any]]) -> None:
        """Apply changes received from server to local state."""
        # TODO: use this fuction to apply changes received by pull request
        print(f"Applying server changes: (this is not implemented yet, but here are the changes we are receiving here: {changes})")

    def create_note(self, title: str, content: str) -> None:
        """
        Create a new note with the given title and content.
        
        Args:
            title: The title of the note
            content: The content of the note
        """
        if not title.strip():
            raise ValueError("Title cannot be empty.")

        note_dir = os.path.join(self.notes_dir, title)
        if os.path.exists(note_dir):
            raise ValueError("A note with this title already exists.")

        # Create note directory and generate encryption key
        os.makedirs(note_dir)
        key_file = os.path.join(note_dir, "key")
        note_key = KeyManager.generate_symmetric_key()
        FileHandler.store_key(note_key, key_file)

        # Create first version of the note
        note = {
            "title": title,
            "content": content,
            "owner": self.username,
            "version": 1,
            "last_modified_by": self.username
        }

        # Store note and record change
        self._store_note(note, note_dir)
        self._record_change(ActionType.CREATE_NOTE, note)

    def _store_note(self, note: Dict[str, Any], note_dir: str) -> None:
        """
        Store a note in the local filesystem.
        
        Args:
            note: The note to store
            note_dir: Directory to store the note in
        """
        note_path = os.path.join(note_dir, f"v{note['version']}.notist")
        FileHandler.write_json(note_path, note)

    def _record_change(self, action_type: ActionType, note: Dict[str, Any]) -> None:
        """
        Record a change for later synchronization with the server.
        
        Args:
            action_type: Type of change made
            note: The note that was changed
        """
        self.changes.append({
            "type": action_type.value,
            "data": {
                "note": note
            }
        })

    def push_changes(self) -> Response:
        """Push recorded changes to the server."""
        # TODO: keep change array in memory for the case were the client crashes/closes wihtout pushing. Maybe store in a file or sm shi.
        if not self.changes:
            return Response(status="success", message="No changes to push (this wasn't sent by server)")
            
        return self.network_handler.push_changes(self.priv_key_path, self.changes)

    def get_note_list(self) -> List[Dict[str, Any]]:
        """Get a list of all local notes with their latest versions."""
        notes = []
        if not os.path.exists(self.notes_dir):
            return notes

        for note_dir in os.listdir(self.notes_dir):
            note_path = os.path.join(self.notes_dir, note_dir)
            if os.path.isdir(note_path):
                versions = sorted([
                    f for f in os.listdir(note_path)
                    if f.endswith(".notist")
                ])
                if versions:
                    latest_version = versions[-1]
                    note_data = FileHandler.read_json(
                        os.path.join(note_path, latest_version)
                    )
                    notes.append(note_data)

        return notes

    def get_note_content(self, title: str, version: Optional[int] = None) -> Dict[str, Any]:
        """
        Get the content of a specific note version.
        
        Args:
            title: The title of the note to retrieve
            version: Optional specific version to retrieve (latest if not specified)
            
        Returns:
            The note content and metadata
        """
        note_dir = os.path.join(self.notes_dir, title)
        if not os.path.exists(note_dir):
            raise ValueError(f"Note '{title}' not found")

        versions = sorted([
            f for f in os.listdir(note_dir)
            if f.endswith(".notist")
        ])
        if not versions:
            raise ValueError(f"No versions found for note '{title}'")

        if version is None:
            version_file = versions[-1]
        else:
            version_file = f"v{version}.notist"
            if version_file not in versions:
                raise ValueError(f"Version {version} not found for note '{title}'")

        return FileHandler.read_json(os.path.join(note_dir, version_file))

    def edit_note(self, title: str, new_content: str) -> None:
        """
        Edit an existing note with new content.
        
        Args:
            title: The title of the note to edit
            new_content: The new content for the note
        """
        note_dir = os.path.join(self.notes_dir, title)
        if not os.path.exists(note_dir):
            raise ValueError(f"Note '{title}' not found")

        # Get current note data
        current_note = self.get_note_content(title)
        
        # Create new version
        note = {
            "title": title,
            "content": new_content,
            "owner": current_note["owner"],
            "version": current_note["version"] + 1,
            "last_modified_by": self.username
        }

        # Store note and record change
        self._store_note(note, note_dir)
        self._record_change(ActionType.EDIT_NOTE, note)

    def delete_note(self, title: str) -> None:
        """
        Delete a note and all its versions.
        
        Args:
            title: The title of the note to delete
        """
        note_dir = os.path.join(self.notes_dir, title)
        if not os.path.exists(note_dir):
            raise ValueError(f"Note '{title}' not found")

        # Get note ID before deletion
        note_data = self.get_note_content(title)
        note_id = note_data.get("_id")

        # Delete note directory
        shutil.rmtree(note_dir)

        # Record change
        self.changes.append({
            "type": ActionType.DELETE_NOTE.value,
            "data": {
                "note_id": note_id
            }
        })

