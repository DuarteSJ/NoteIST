import os
import shutil
from typing import Optional, List, Dict, Any
from .crypto.keys import KeyManager
from .network.handler import NetworkHandler
from .utils.file import FileHandler
from .utils.auth import AuthManager
from .models.actions import ActionType
from .models.responses import Response
from .config.paths import get_config_file, get_notes_dir, get_priv_key_file
from .crypto.secure import SecureHandler
from uuid import uuid4


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
        self.notes_dir = get_notes_dir()
        self.priv_key_path = get_priv_key_file()
        self.config_path = get_config_file()
        self.key_manager = None
        

        # Server configuration
        self.host = host
        self.port = port
        self.cert_path = cert_path

        # Instance attributes
        self.username = None
        self.network_handler = None
        self.changes = []

        # Set up the environment
        self._load_or_register_user()

    def _get_next_id(self) -> int:
        """Get the next unique ID for a note."""
        return str(uuid4())

    def _load_or_register_user(self) -> None:
        """Load existing user configuration or start new user registration process."""
        
        if (
            not os.path.exists(self.priv_key_path)
            or not os.path.exists(self.auth_path)
            or not os.path.exists(self.notes_dir)
        ):
            self._register_new_user()
        else:
            self._login_with_retry()

    def _login_with_retry(self) -> None:
        """Handle login attempts with retry logic."""

        # Create required directories if they are missing (they shouldn't be)
        self.notes_dir = get_notes_dir()
        self.priv_key_path = get_priv_key_file()
        self.config_path = get_config_file()
        FileHandler.ensure_directory(self.notes_dir)
        FileHandler.ensure_directory(self.base_data_dir)
        FileHandler.ensure_directory(self.notes_dir)
        while True:
            try:
                self._login()
                break
            except ValueError:
                if not self._prompt_user("retry"):
                    print("Exiting NoteIST. Goodbye!")
                    exit(0)
            except Exception:
                self._register_new_user()
                break

    def _login(self) -> None:
        """Log in existing user and sync with server."""
        try:
            # Get username and password from configuration
            user_info = FileHandler.read_json(self.auth_path)
            self.username = user_info.get("username")
            local_password = user_info.get("password")
            self.salt = bytes.fromhex(user_info.get("salt"))

            if not self.username:
                raise Exception("Username not found in configuration")
            if not local_password:
                #TODO: WHAT TO DO?
                raise Exception("Password not found in configuration")
            if not self.salt:
                raise Exception("Salt not found in configuration")

            password = input(f"Hi {self.username}, enter your password: ")

            AuthManager.verify_password(local_password, password)

            self.key_manager = KeyManager(password,self.salt)

            self.network_handler = NetworkHandler(
                self.username, self.host, self.port, self.cert_path, self.key_manager
            )

        except ValueError as e:
            # password mismatch or missing username
            print(f"Login failed: {e}")
            raise ValueError(f"Login failed: {e}")
        except Exception as e:
            raise Exception(f"Login failed: {e}")

    def _prompt_user(self, msg) -> bool:
        """Prompt the user."""
        retry = input(f"Would you like to {msg}, {self.username}? [yes/no]").lower()
        return retry in ["yes", "y"]

    def _register_new_user(self) -> None:
        """Handle the registration process for a new user."""
        print("No user found. Proceeding with registration.")
        print("ATTENTION- This will overwrite any existing user data.")
        if not self._prompt_user("continue"):
            print("Exiting NoteIST. Goodbye!")
            exit(0)

        # Remove all previous user data
        FileHandler.delete_all(
            [self.priv_key_path, self.base_config_dir, self.base_data_dir]
        )
        FileHandler.ensure_directory(self.base_config_dir)
        FileHandler.ensure_directory(self.notes_dir)
        FileHandler.ensure_directory(self.base_data_dir)

        while True:
            try:


                # Get username from user
                username = input("Enter your username (must be unique): ").strip()
                if not username:
                    print("Username cannot be empty. Please try again.")
                    continue
                password = input("Enter your password: ").strip()

                passwordHash = AuthManager.hash_password(password)
                # Generate and store key pair
                self.username = username
                self.salt = os.urandom(16)
                self.key_manager = KeyManager(password, self.salt)
                public_key = self.key_manager.generate_key_pair(
                    self.priv_key_path
                )
                # Initialize network handler
                self.network_handler = NetworkHandler(
                    username, self.host, self.port, self.cert_path, self.key_manager
                )
                # Register with server
                response = self.network_handler.register_user(
                    self.key_manager.get_public_key_json_serializable(public_key),
                )
                if response.status == "error":
                    raise Exception(f"Server registration failed: {response.message}")
                # Save username to configuration
                FileHandler.write_json(
                    self.auth_path, {"username": username, "password": passwordHash, "salt": self.salt.hex()}
                )
                print(f"Welcome to NoteIST, {username}!")
                break

            except Exception as e:
                print(f"Registration error: {e}")
                if not self._prompt_user("try again"):
                    print("Exiting NoteIST. Goodbye!")
                    exit(0)

    def pull_changes(self) -> None:
        """Synchronize local state with server."""
        try:
            response = self.network_handler.pull_changes(self.priv_key_path)
            if response.status == "error":
                raise Exception(f"sync failed - {response.message}")

            # Process and apply server changes locally

            if response.documents:
                self._apply_server_changes(response.documents)
            return response  # TODO: this ret is not required, just cause we printing it in main for now

        except Exception as e:
            raise Exception(e)

    def _apply_server_changes(self, changes: List[Dict[str, Any]]) -> None:
        """Apply changes received from server to local state."""

        FileHandler.clean_note_directory(self.notes_dir)

        current_folder = None

        for document in changes:
            title = document.get("title")

            if not title:
                print("Wrongly formatted document, skipping")
                continue

            # Create new folder name when owner_id or _id changes
            #TODO: CHANGE THIS
            folder_name = SecureHandler.encrypt_string(title)

            # If we're processing a new group, create a new folder
            if folder_name != current_folder:
                current_folder = folder_name
                folder_path = os.path.join(self.notes_dir, folder_name)
                FileHandler.ensure_directory(folder_path)

            FileHandler.write_json(
                os.path.join(folder_path, f"v{document.get('version')}.notist"),
                document,
            )

        # TODO: adicionar as chaves que vieram do server para a pasta correta (adicionou owner)

    def create_note(self, title: str, content: str) -> None:
        """
        Create a new note with the given title and content.

        Args:
            title: The title of the note
            content: The content of the note
        """
        if not title.strip():
            raise ValueError("Title cannot be empty.")
        encrypted_title = self.key_manager.encrypt_note_title(title)

        note_dir = os.path.join(self.notes_dir, encrypted_title)
        if os.path.exists(note_dir):
            raise ValueError("A note with this title already exists.")

        # Create note directory and generate encryption key
        os.makedirs(note_dir)
        key_file = os.path.join(note_dir, "key")
        encrypted_note_key = self.key_manager.generate_encrypted_note_key()
        FileHandler.store_key(encrypted_note_key, key_file)

        # Create first version of the note
        note = {
            "_id": self._get_next_id(),
            "title": title,
            "content": content,
            "owner": self.username,
            "version": 1,
        }

        # Store note and record change
        self._store_note(note, note_dir)
        self._record_change(
            action_type=ActionType.CREATE_NOTE,
            note=FileHandler.read_json(os.path.join(note_dir, "v1.notist"))
        )

    def _store_note(self, note: Dict[str, Any], note_dir: str) -> None:
        """
        Store a note in the local filesystem.

        Args:
            note: The note to store
            note_dir: Directory to store the note in
        """
        note_path = os.path.join(note_dir, f"v{note['version']}.notist")
        key_path = os.path.join(note_dir, "key")
        FileHandler.write_encrypted_note(
            filePath=note_path,
            keyFile=key_path,
            key_manager=self.key_manager,
            id=note["_id"],
            title=note["title"],
            content=note["content"],
            owner=note["owner"],
            version=note["version"],
            # TODO: add editors and viewers < - Duarte
        )

    def _record_change(self, action_type: ActionType, **kwargs: Any) -> None:
        """
        Record a change for later synchronization with the server.

        Args:
            action_type: Type of change made
            kwargs: Additional arguments like `note` or `note_id`
        """
        data_mapping = {
            ActionType.DELETE_NOTE: {"note_id": kwargs.get("note_id")},
            ActionType.EDIT_NOTE: {"note": kwargs.get("note")},
            ActionType.CREATE_NOTE: {"note": kwargs.get("note")},
        }

        if action_type not in data_mapping:
            raise ValueError(f"Unsupported action type: {action_type}")
        self.changes.append({"type": action_type.value, "data": data_mapping[action_type]})

    def push_changes(self) -> Response:
        """Push recorded changes to the server."""
        # TODO: keep change array in memory for the case were the client crashes/closes wihtout pushing. Maybe store in a file or sm shi. Is this really needed <- Massas
        try:
            if not self.changes:
                return Response(
                    status="success",
                    message="No changes to push (this wasn't sent by server)",
                )

            response = self.network_handler.push_changes(
                self.priv_key_path, self.changes
            )
            if response.status == "success":
                self.changes = []
            else:
                print(f"Server response: {response.status} - {response.message}")
        except Exception as e:
            raise Exception(f"Failed to push changes: {e}")

    def get_note_list(self) -> List[tuple]:
        """Get a list of all local notes with their latest versions."""
        notes = []
        if not os.path.exists(self.notes_dir):
            return notes

        for note_dir in os.listdir(self.notes_dir):
            decrypt_title = self.key_manager.decrypt_note_title(note_dir)
            last_version = FileHandler.get_highest_version(os.path.join(self.notes_dir, note_dir))
            note = [decrypt_title, last_version]
            notes.append(note)

        return notes
    
    def list_notes(self) -> None:
        """List all notes with their latest versions."""
        notes = self.get_note_list()
        if not notes:
            print("No notes found.")
            return

        print("Available notes:")
        for note in notes:
            print(f"{note[0]} (v{note[1]})")

    def view_note(self, title: str, version: Optional[int] = None) -> None:
        """
        View the content of a specific note version.

        Args:
            title: The title of the note to view
            version: Optional specific version to retrieve (latest if not specified)
        """
        if not title.strip(): # TODO: add more checks
            raise ValueError("Title cannot be empty.")
        encrypted_title = self.key_manager.encrypt_note_title(title)
        note = self.get_note_content(encrypted_title, version)
        print(f"\nTitle: {note['title']}")
        print(f"Content: {note['note']}")

    def get_note_content(
        self, encrypted_title: str, version: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get the content of a specific note version.

        Args:
            note_dir: The path to the directory of the note
            version: Optional specific version to retrieve (latest if not specified)

        Returns:
            The note content and metadata
        """


        note_dir = os.path.join(self.notes_dir, encrypted_title)

        if not os.path.exists(note_dir):
            raise ValueError(f"Get_note_content: {note_dir} not found")

        if version:
            version = int(version)
        else: # choose the latest version
            version = FileHandler.get_highest_version(note_dir)
        version_file = f"v{version}.notist"

        note_file = os.path.join(note_dir, version_file)
        key_file = os.path.join(note_dir, "key")
        if not os.path.exists(note_file):
            raise ValueError(f"Get_note_content: Version {version_file} of note '{note_dir}' not found")
        elif not os.path.exists(key_file):
            raise ValueError(f"get_note_content: Key file not found for note '{note_dir}'")

        return FileHandler.read_encrypted_note(
            filePath=note_file,
            keyFile=key_file,
            key_manager=self.key_manager,
        )
    

    def edit_note(self, title: str, new_content: str) -> None:
        """
        Edit an existing note with new content.

        Args:
            title: The title of the note to edit
            new_content: The new content for the note
        """
        if not title.strip():
            raise ValueError("Title cannot be empty.")

        encrypted_title = self.key_manager.encrypt_note_title(title)

        note_dir = os.path.join(self.notes_dir, encrypted_title)

        # Get current note data
        current_note = self.get_note_content(encrypted_title)

        # Create new version
        note = {
            "_id": current_note["_id"],
            "title": title,
            "content": new_content,
            "owner": current_note["owner"],
            "version": current_note["version"] + 1,
        }

        # Store note and record change
        self._store_note(note, note_dir)
        self._record_change(
            action_type=ActionType.EDIT_NOTE,
            note=FileHandler.read_json(os.path.join(note_dir, f"v{note['version']}.notist")),
        )

    def delete_note(self, title: str) -> None:
        """
        Delete a note and all its versions.

        Args:
            title: The title of the note to delete
        """
        encrypted_title = self.key_manager.encrypt_note_title(title)
        note_dir = os.path.join(self.notes_dir, encrypted_title)

        # Get note ID before deletion
        note_data = self.get_note_content(encrypted_title)
        note_id = note_data.get("_id")

        # Delete note directory
        shutil.rmtree(note_dir)

        self._record_change(action_type=ActionType.DELETE_NOTE, note_id=note_id)
