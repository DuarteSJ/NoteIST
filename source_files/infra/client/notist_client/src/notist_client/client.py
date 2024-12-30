import os
from typing import Optional, List, Dict, Any
from .crypto.keys import KeyManager
from .network.handler import NetworkHandler
from .utils.file import FileHandler
from .utils.auth import AuthManager
from .models.actions import ActionType
from .models.responses import Response
from .config.paths import (
    get_config_file,
    get_notes_dir,
    get_priv_key_file,
    get_note_changes_file,
    get_user_changes_file,
)
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
        self.note_changes_path = get_note_changes_file()
        self.user_changes_path = get_user_changes_file()

        self.key_manager = None

        # Server configuration
        self.host = host
        self.port = port
        self.cert_path = cert_path

        # Instance attributes
        self.username = None
        self.network_handler = None

        # Set up the environment
        self._load_or_register_user()

    def _get_next_id(self) -> int:
        """Get the next unique ID for a note."""
        return str(uuid4())

    def _load_or_register_user(self) -> None:
        """Load existing user configuration or start new user registration process."""

        if not os.path.exists(self.priv_key_path) or not os.path.exists(
            self.config_path
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
            user_info = FileHandler.read_json(self.config_path)
            self.username = user_info.get("username")
            local_password = user_info.get("password")
            self.salt = bytes.fromhex(user_info.get("salt"))

            if not self.username:
                raise Exception("Username not found in configuration")
            if not local_password:
                # TODO: WHAT TO DO?
                raise Exception("Password not found in configuration")
            if not self.salt:
                raise Exception("Salt not found in configuration")

            password = input(f"Hi {self.username}, enter your password: ")

            AuthManager.verify_password(local_password, password)

            self.key_manager = KeyManager(password, self.salt)

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
        res = input(f"Would you like to {msg}, {self.username}? [yes/no]").lower()
        return res in ["yes", "y"]

    def _register_new_user(self) -> None:
        """Handle the registration process for a new user."""
        print("No user found. Proceeding with registration.")
        print("ATTENTION- This will overwrite any existing user data.")
        if not self._prompt_user("continue"):
            print("Exiting NoteIST. Goodbye!")
            exit(0)

        # Remove all previous user data
        FileHandler.delete_all(
            [
                self.priv_key_path,
                self.config_path,
                self.notes_dir,
                self.note_changes_path,
                self.user_changes_path,
            ]
        )
        FileHandler.ensure_directory(self.notes_dir)

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
                public_key = self.key_manager.generate_key_pair(self.priv_key_path)
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
                    self.config_path,
                    {
                        "username": username,
                        "password": passwordHash,
                        "salt": self.salt.hex(),
                    },
                )
                print(f"Welcome to NoteIST, {username}!")
                break

            except Exception as e:
                print(f"Registration error: {e}")
                if not self._prompt_user("try again"):
                    print("Exiting NoteIST. Goodbye!")
                    exit(0)

    def _apply_server_changes(self, changes: List[Dict[str, Any]]) -> None:
        """Apply changes received from server to local state."""

        FileHandler.clean_note_directory(self.notes_dir)

        current_id = None

        for note in changes:
            id = note.get("id")
            if not id:
                print("Wrongly formatted document, skipping")
                continue

            # If we're processing a new group, create a new folder
            if id != current_id:
                current_id = id
                folder_path = os.path.join(self.notes_dir, id)
                FileHandler.ensure_directory(folder_path)

            FileHandler.write_json(
                os.path.join(folder_path, f"v{note.get('version')}.notist"),
                note,
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

        id = self._get_next_id()

        note_dir = os.path.join(self.notes_dir, id)

        # Create note directory and generate encryption key
        os.makedirs(note_dir)
        key_file = os.path.join(note_dir, "key")
        encrypted_note_key = self.key_manager.generate_encrypted_note_key()
        FileHandler.store_key(encrypted_note_key, key_file)

        # Create first version of the note
        note = {
            "id": id,
            "title": title,
            "note": content,
            "owner": {
                "username": self.username,
            },
            "version": 1,
            "editors": [],
            "viewers": [],
        }

        # Store note and record change
        self._store_note(note, note_dir)
        self._record_change(
            action_type=ActionType.CREATE_NOTE,
            note=FileHandler.read_json(os.path.join(note_dir, "v1.notist")),
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
            id=note["id"],
            title=note["title"],
            content=note["note"],
            owner=note["owner"],
            version=note["version"],
            editors=note["editors"],
            viewers=note["viewers"],
        )

    def _record_change(self, action_type: ActionType, **kwargs: Any) -> None:
        """
        Record a change for later synchronization with the server.

        Args:
            action_type: Type of change made
            kwargs: Additional arguments like `note`, `note_id`, `user_id`, etc.
        """
        action_mapping = {
            ActionType.CREATE_NOTE: (
                self.note_changes_path,
                {"note": kwargs.get("note")},
            ),
            ActionType.EDIT_NOTE: (
                self.note_changes_path,
                {"note": kwargs.get("note")},
            ),
            ActionType.DELETE_NOTE: (
                self.note_changes_path,
                {"note_id": kwargs.get("note_id")},
            ),
            ActionType.ADD_USER: (
                self.user_changes_path,
                {
                    "collaborator_username": kwargs.get("collaborator_username"),
                    "note_id": kwargs.get("note_id"),
                    "is_editor": kwargs.get("is_editor"),
                },
            ),
            ActionType.REMOVE_USER: (
                self.user_changes_path,
                {
                    "collaborator_username": kwargs.get("collaborator_username"),
                    "note_id": kwargs.get("note_id"),
                    "is_editor": kwargs.get("is_editor"),
                },
            ),
        }

        if action_type not in action_mapping:
            raise ValueError(f"Unsupported action type: {action_type}")

        # Get the corresponding file path and data
        changes_path, data = action_mapping[action_type]
        change_record = {"type": action_type.value, "data": data}

        # Open the file and append the JSON-encoded string
        FileHandler.save_change(changes_path, change_record)

    def push_changes(self) -> Response:
        """Push recorded changes to the server."""
        try:
            note_changes = FileHandler.read_changes(self.note_changes_path)
            user_changes = FileHandler.read_changes(self.user_changes_path)
            response = self.network_handler.push_changes(
                self.priv_key_path, note_changes, user_changes
            )
            print(f"Server response: {response.status} - {response.message}")
            if response.status == "success":
                for res in response.action_results:
                    print(res)
                for res in response.user_results:
                    print(res)
                FileHandler.clean_file(self.user_changes_path)
                FileHandler.clean_file(self.note_changes_path)
        except Exception as e:
            raise Exception(f"Failed to push changes: {e}")

    def pull_changes(self) -> Response:
        """Sync with server."""

        try:
            hash_of_hmacs = self.get_hash_hmac_from_encrypted_notes()

            response = self.network_handler.pull_changes(
                self.priv_key_path, hash_of_hmacs
            )
            print(f"Server response: {response.status} - {response.message}")
            if response.status == "success":
                self._apply_server_changes(response.documents)
                FileHandler.clean_file(self.user_changes_path)
                FileHandler.clean_file(self.note_changes_path)
        except Exception as e:
            raise Exception(f"Failed to pull changes: {e}")

    def get_hash_hmac_from_encrypted_notes(self) -> str:
        """Get the hash of hmac of a specific note with all its versions."""
        hmacs = []
        note = []

        for encrypted_title in os.listdir(self.notes_dir):
            note_dir = os.path.join(self.notes_dir, encrypted_title)
            for version in os.listdir(note_dir):
                print(f"version: {version}")
                if version == "key":
                    continue
                note = FileHandler.read_json(os.path.join(note_dir, version))
                hmacs.append(note.get("hmac"))
        # sort notes by id
        sorted_notes = sorted(hmacs)
        hmac_str = "".join(sorted_notes)
        hash = SecureHandler.hash_hmacs_str(hmac_str)
        return hash

    def get_note_list(self) -> List[tuple]:
        """Get a list of all local notes with their latest versions."""
        notes = []
        if not os.path.exists(self.notes_dir):
            return notes

        for note_dir in os.listdir(self.notes_dir):
            note_path = os.path.join(self.notes_dir, note_dir)
            last_version = FileHandler.get_highest_version(note_path)
            note_path = os.path.join(note_path, f"v{last_version}.notist")
            key_path = os.path.join(self.notes_dir, note_dir, "key")
            note = FileHandler.read_encrypted_note(
                filePath=note_path,
                keyFile=key_path,
                key_manager=self.key_manager,
            )
            notes.append(note)
        return notes

    def list_notes(self, notes: Optional[Dict[str, any]] = None) -> None:
        """List all notes with their latest versions."""
        if not notes:
            notes = self.get_note_list()
        if not notes:
            print("No notes found.")
            return

        print("Available notes:")
        for i, note in enumerate(notes):
            print(f"{i+1}: {note.get('title')} (v{note.get('version')})")

    def select_note(self) -> Dict[str, Any]:
        """List all notes with their latest versions. And prompt the user to select one."""
        notes = self.get_note_list()

        self.list_notes(notes)

        while True:
            try:
                choice = input("Select a note by number: ")
                note = notes[int(choice) - 1]
                return note
            except (ValueError, IndexError):
                print("Invalid choice. Please try again.")
                continue

    def view_note(self) -> None:
        """
        View the content of a specific note version.

        Args:
            title: The title of the note to view
            version: Optional specific version to retrieve (latest if not specified)
        """
        note = self.select_note()

        while True:
            try:
                version = input("Select note version (empty for latest): ").strip()
                if version != "" and int(version) != note.get("version"):
                    note = FileHandler.read_encrypted_note(
                        filePath=os.path.join(
                            self.notes_dir, note["id"], f"v{version}.notist"
                        ),
                        keyFile=os.path.join(self.notes_dir, note["id"], "key"),
                        key_manager=self.key_manager,
                    )
                break
            except Exception as e:
                print(f"Invalid version number. Please try again.: {e}")
        print(f"\nTitle: {note.get('title')}\nContent: {note.get('note')}\n")

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
        else:  # choose the latest version
            version = FileHandler.get_highest_version(note_dir)
        version_file = f"v{version}.notist"

        note_file = os.path.join(note_dir, version_file)
        key_file = os.path.join(note_dir, "key")
        if not os.path.exists(note_file):
            raise ValueError(
                f"Get_note_content: Version {version_file} of note '{note_dir}' not found"
            )
        elif not os.path.exists(key_file):
            raise ValueError(
                f"get_note_content: Key file not found for note '{note_dir}'"
            )

        return FileHandler.read_encrypted_note(
            filePath=note_file,
            keyFile=key_file,
            key_manager=self.key_manager,
        )

    def edit_note(self) -> None:
        """
        Edit an existing note with new content.

        Args:
            title: The title of the note to edit
            new_content: The new content for the note
        """
        note = self.select_note()

        new_title = input("\nEnter new title: ")
        # new_content = input("Enter new content: ") # nao apaguem da jeito para correr teste automatico
        new_content = self.edit_note_with_editor(note.get("note"))

        # Create new version
        note["title"] = new_title
        note["note"] = new_content
        note["version"] += 1

        # Get note directory
        note_dir = os.path.join(self.notes_dir, note["id"])

        # Store note and record change
        self._store_note(note, note_dir)
        self._record_change(
            action_type=ActionType.EDIT_NOTE,
            note=FileHandler.read_json(
                os.path.join(note_dir, f"v{note['version']}.notist")
            ),
        )

    def delete_note(self) -> None:
        """
        Delete a note and all its versions.

        Args:
            title: The title of the note to delete
        """
        note = self.select_note()
        note_id = note.get("id")
        note_dir = os.path.join(self.notes_dir, note_id)

        # Delete note directory
        FileHandler.clean_note_directory(note_dir)

        self._record_change(action_type=ActionType.DELETE_NOTE, note_id=note_id)

    def add_contributor(self) -> None:
        note = self.select_note()
        contributor = input("Enter the username of the contributor: ")
        if contributor.strip() == "" or not contributor:
            raise ValueError("Contributor cannot be empty.")

        is_editor = self._prompt_user(
            f"give {contributor} editing permissions to this note"
        )

        if self.username != note["owner"]["username"]:
            raise Exception(f"Only the owner can add contributors to the note")

        # TODO: should we do this locally? no need to, just send to the server and he will retrieve it well. <- Massas
        if is_editor:
            note["editors"].append({"username": contributor})

        note["viewers"].append({"username": contributor})  # editors are also viewers

        note_path = os.path.join(
            self.notes_dir, note["id"], f"v{note['version']}.notist"
        )
        FileHandler.write_encrypted_note(
            filePath=note_path,
            keyFile=os.path.join(self.notes_dir, note["id"], "key"),
            key_manager=self.key_manager,
            id=note["id"],
            title=note["title"],
            content=note["note"],
            owner=note["owner"],
            version=note["version"],
            editors=note["editors"],
            viewers=note["viewers"],
        )

        self._record_change(
            action_type=ActionType.ADD_USER,
            collaborator_username=contributor,
            note_id=note.get("id"),
            is_editor=is_editor,
        )

    def remove_contributor(self) -> None:
        note = self.select_note()
        contributor = input("Enter the username of the contributor: ")
        if contributor.strip() == "" or not contributor:
            raise ValueError("Contributor cannot be empty.")

        if self.username != note["owner"]["username"]:
            raise Exception(f"Only the owner can remove contributors from the note")

        # TODO: podiamos so meter o if is editor dentro do if is viewer,
        # mas se alguem mudar localmente pode estar um gajo nos editors
        # que nao esta nos viewers por isso fiz assim, mas n sei vejam o que acham
        is_editor = None
        if any(viewer.get("username") == contributor for viewer in note["viewers"]):
            is_editor = False
            note["viewers"].remove({"username": contributor})
        if any(editor.get("username") == contributor for editor in note["editors"]):
            is_editor = True
            note["editors"].remove({"username": contributor})
        if is_editor is None:
            raise Exception(f"{contributor} is not a contributor to the note")

        note_path = os.path.join(
            self.notes_dir, note.get("id"), f'v{note.get("version")}.notist'
        )
        FileHandler.write_encrypted_note(
            filePath=note_path,
            keyFile=os.path.join(self.notes_dir, note.get("id"), "key"),
            key_manager=self.key_manager,
            id=note.get("id"),
            title=note.get("title"),
            content=note.get("note"),
            owner=note.get("owner"),
            version=note.get("version"),
            editors=note.get("editors"),
            viewers=note.get("viewers"),
        )

        self._record_change(
            action_type=ActionType.REMOVE_USER,
            collaborator_username=contributor,
            note_id=note.get("id"),
            is_editor=is_editor,
        )

    def edit_note_with_editor(self, old_content):
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile(
            delete=False, mode="w+", suffix=".txt"
        ) as temp_file:
            temp_file_name = temp_file.name
            temp_file.write(old_content)
            temp_file.flush()
            subprocess.call(
                [os.getenv("EDITOR", "nano"), temp_file_name]
            )  # Use user's default editor

        with open(temp_file_name, "r") as temp_file:
            new_content = temp_file.read()

        os.unlink(temp_file_name)  # Clean up the temporary file
        return new_content.strip()
