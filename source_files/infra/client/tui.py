import os
import shutil
from typing import Optional
from utils import *
from cryptography.hazmat.primitives.asymmetric import rsa
from key_manager import generate_key_pair
from secure_request_handler import SecureRequestHandler


class NoteIST:
    def __init__(self, host: str, port: int, cert_path: str):
        """
        Initialize the NoteIST instance with server and user configuration.

        Args:
            host (str): The server host for the request handler.
            port (int): The server port for the request handler.
            cert_path (str): The path to the server's certificate for secure communication.
        """
        self.changes = []

        # Configuration paths
        self.base_config_dir = os.path.expanduser("~/.config/NoteIST")
        self.base_data_dir = os.path.expanduser("~/.local/share/NoteIST")

        # Specific paths
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.notes_dir = os.path.join(self.base_data_dir, "notes")
        self.priv_key_path = os.path.join(self.base_config_dir, "priv_key.pem")
        self.username_path = os.path.join(self.base_config_dir, "username.json")

        # User and request handler attributes
        self.username = None
        self.request_handler = None

        # Set up the environment
        self._initialize_environment()

    def _initialize_environment(self):
        """
        Set up the required directories and initialize user configuration.
        """
        # Create necessary directories
        os.makedirs(self.base_config_dir, exist_ok=True)
        os.makedirs(self.base_data_dir, exist_ok=True)
        os.makedirs(self.notes_dir, exist_ok=True)

        # Check for existing configuration
        self._load_or_register_user()

    def _load_or_register_user(self):
        """
        Load existing user configuration or prompt for registration.
        """
        # Check for existing private key
        if not os.path.exists(self.priv_key_path):
            self._register_new_user()
            return

        # Try to load username
        try:
            self.username = self._load_username()
            if not self.username:
                self._register_new_user()
        except FileNotFoundError:
            self._register_new_user()

        # Initialize request handler if it is not yet innitialized (this is spaggeti code)
        if not self.request_handler:
            self.request_handler = SecureRequestHandler(
                self.username, self.host, self.port, self.cert_path
            )

    def _load_username(self) -> str:
        """
        Load username from persistent storage.

        Returns:
            str: The stored username
        """
        with open(self.username_path, "r") as f:
            return json.load(f)["username"]

    def _save_username(self, username: str):
        """
        Save username to persistent storage.

        Args:
            username (str): The username to save
        """
        with open(self.username_path, "w") as f:
            json.dump({"username": username}, f)

    def _register_new_user(self):
        """
        Handle new user registration process.
        """
        register = input(
            "We don't detect evidence of an existing account on this device... Do you want to create a new account?[yes/no]"
        )
        if register.lower() not in ["yes", "y"]:
            print(
                "Can't continue without creating an account... Exiting NoteIST. Goodbye!"
            )
            exit(0)
        while True:
            try:
                # Prompt for username
                username = input("Enter your username (must be unique): ").strip()

                # Validate username
                if not username:
                    print("Username cannot be empty. Please try again.")
                    continue

                # Generate key pair
                public_key = generate_key_pair(self.priv_key_path)

                # Register user on the server
                self._register_user_in_server(username, public_key)

                # Save username
                self._save_username(username)
                self.username = username

                print(f"Welcome to NoteIST, {username}!")
                break

            except Exception as e:
                print(f"Registration error: {e}")
                continue

    def _register_user_in_server(self, username: str, public_key: rsa.RSAPublicKey):
        """
        Register the user with the server.

        Args:
            username (str): The username to register
            public_key (rsa.RSAPublicKey): The user's public key
        """
        try:
            # Assuming request_handler is set up with necessary methods
            self.request_handler = SecureRequestHandler(
                username, self.host, self.port, self.cert_path
            )
            self.request_handler.register_user(self.username, public_key)
            print(f"User '{username}' registered successfully!")
        except Exception as e:
            print(f"Server registration error: {e}")
            raise

    def main_menu(self):
        """Displays the main menu and returns the user's choice."""
        print("\n=== NoteIST ===")
        print("1. Create a Note")
        print("2. Show Notes List")
        print("3. View Note Content")
        print("4. Edit a Note")
        print("5. Delete a Note")
        print("6. Push changes to remote server")
        print("7. Exit")

        choice = input("Choose an option: ")
        return choice

    def create_note(self):
        title = input("Enter note title: ")
        if not title.strip():
            raise ValueError("Title cannot be empty.")

        note_dir = os.path.join(self.notes_dir, title)
        if os.path.exists(note_dir):
            raise ValueError("A note with this title already exists.")

        os.makedirs(note_dir)

        key_file = os.path.join(note_dir, "key")
        note_key = generate_key()
        store_key(note_key, key_file)

        note_path = os.path.join(note_dir, "v1.notist")

        content = input("Enter note content: ")

        writeToFile(
            note_path,
            key_file,
            title,
            content,
            1,
        )
        self.changes.append({
            "type": "create_note",
            "note_title": title,
            "version": "v1.notist",
            "content": content
        })        
        print(f"Note '{title}' created successfully!")

    def display_notes_list(self):
        """Displays the list of notes with their latest version."""
        if not os.path.exists(self.notes_dir):
            print("No notes available.")
            return

        note_dirs = [
            d
            for d in os.listdir(self.notes_dir)
            if os.path.isdir(os.path.join(self.notes_dir, d))
        ]
        if not note_dirs:
            print("No notes available.")
            return

        print("\nAvailable Notes (showing latest version):")
        for idx, note in enumerate(note_dirs, start=1):
            note_dir = os.path.join(self.notes_dir, note)
            versions = sorted(
                [f for f in os.listdir(note_dir) if f.endswith(".notist")]
            )

            if versions:
                latest_version = versions[-1]
                latest_version_display = latest_version.replace(".notist", "")
                print(f"{idx}. {note} ({latest_version_display})")
            else:
                print(f"{idx}. {note} (No versions available)")

    def view_note_content(self):
        if not os.path.exists(self.notes_dir):
            print("No notes available.")
            return

        note_dirs = [
            d
            for d in os.listdir(self.notes_dir)
            if os.path.isdir(os.path.join(self.notes_dir, d))
        ]
        if not note_dirs:
            print("No notes available.")
            return

        self.display_notes_list()

        choice = input("Select a note by number to view its content: ")
        choice = int(choice)
        selected_note = note_dirs[choice - 1]
        note_dir = os.path.join(self.notes_dir, selected_note)

        key_file = os.path.join(note_dir, "key")

        version = self._select_version(note_dir)
        if version is None:
            return

        filepath = os.path.join(note_dir, version)

        content = readFromFile(filepath, key_file)

        print("\nContent of the selected note version:")
        print(content)

    def _select_version(self, note_dir: str) -> Optional[str]:
        """Helper function to allow selecting a version for a note."""
        versions = sorted([f for f in os.listdir(note_dir) if f.endswith(".notist")])
        if not versions:
            print("No versions available for this note.")
            return None

        if len(versions) == 1:
            return versions[0]

        print("\nAvailable Versions:")
        for idx, version in enumerate(versions, start=1):
            version_display = version.replace(".notist", "")
            print(f"{idx}. {version_display}")

        choice = input("Select a version to view: ").strip()
        choice = int(choice)
        if 1 <= choice <= len(versions):
            return versions[choice - 1]
        else:
            print("Invalid selection.")
            return None

    def edit_note(self):
        if not os.path.exists(self.notes_dir):
            print("No notes available.")
            return

        note_dirs = [
            d
            for d in os.listdir(self.notes_dir)
            if os.path.isdir(os.path.join(self.notes_dir, d))
        ]
        if not note_dirs:
            print("No notes available.")
            return

        self.display_notes_list()

        choice = input("Select a note by number to edit: ")
        choice = int(choice)
        selected_note = note_dirs[choice - 1]
        note_dir = os.path.join(self.notes_dir, selected_note)
        version = self._select_version(note_dir)
        if version is None:
            return

        filepath = os.path.join(note_dir, version)
        key_file = os.path.join(note_dir, "key")
        content = readFromFile(filepath, key_file)
        print("\nCurrent Content:")
        print(content)

        new_content = input("\nEnter new content (THIS WILL OVERWRITE OLD CONTENT): ")
        new_version = self._get_next_version(note_dir)
        new_filepath = os.path.join(note_dir, f"v{new_version}.notist")
        key_file = os.path.join(note_dir, "key")

        writeToFile(
            new_filepath,
            key_file,
            selected_note,
            new_content,
            new_version,
        )
        print(f"Note '{selected_note}' version {new_version} updated successfully!")

        self.changes.append({
            "type": "edit_note",
            "note_title": selected_note,
            "new_version": f"v{new_version}.notist",
            "new_content": new_content
        })

    def _get_next_version(self, note_dir):
        """Returns the next available version number for the note."""
        versions = [f for f in os.listdir(note_dir) if f.endswith(".notist")]
        version_numbers = []
        for version in versions:
            try:
                version_number = int(version.replace(".notist", "").replace("v", ""))
                version_numbers.append(version_number)
            except ValueError:
                continue
        return max(version_numbers, default=0) + 1

    def delete_note(self):
        if not os.path.exists(self.notes_dir):
            print("No notes available.")
            return

        note_dirs = [
            d for d in os.listdir(self.notes_dir)
            if os.path.isdir(os.path.join(self.notes_dir, d))
        ]
        if not note_dirs:
            print("No notes available.")
            return

        self.display_notes_list()

        choice = input("Select a note by number to delete: ")
        choice = int(choice)
        selected_note = note_dirs[choice - 1]
        note_dir = os.path.join(self.notes_dir, selected_note)

        shutil.rmtree(note_dir)
        print(f"All versions of note '{selected_note}' deleted successfully!")

        self.changes.append({
            "type": "delete_note",
            "": selected_note,
        })

    def push_changes(self):
        """Function to push changes to the server."""
        response = self.request_handler.push_changes(self.priv_key_path, self.changes)
        print(f"Push changes response: {response.status} - {response.message}")
    
    def pull_changes(self):
        """Function to pull changes from the server."""
        response = self.request_handler.pull_changes(self.priv_key_path)
        print(f"Pull changes response: {response.status} - {response.message}")

def main():
    host = "192.168.56.14"  # TODO: server host
    port = 5000  # TODO: server port
    cert_path = "/path/to/certificate.pem"  # TODO: certificate path

    app = NoteIST(host=host, port=port, cert_path=cert_path)

    while True:
        choice = app.main_menu()
        if choice == "1":
            try:
                app.create_note()
            except Exception as e:
                print(f"Error creating note: {e}")
        elif choice == "2":
            try:
                app.display_notes_list()
            except Exception as e:
                print(f"Error displaying notes: {e}")
        elif choice == "3":
            try:
                app.view_note_content()
            except Exception as e:
                print(f"Error viewing note content: {e}")
        elif choice == "4":
            try:
                app.edit_note()
            except Exception as e:
                print(f"Error editing note: {e}")
        elif choice == "5":
            try:
                app.delete_note()
            except Exception as e:
                print(f"Error deleting note: {e}")
        elif choice == "6":
            try:
                app.push_changes()
            except Exception as e:
                print(f"Error pushing changes: {e}")
        elif choice == "7":
            print(f"Exiting NoteIST. Goodbye {app.username}!")
            break


if __name__ == "__main__":
    main()
