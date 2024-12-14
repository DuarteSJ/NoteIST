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
        Initializes the NoteIST instance and sets up the environment.

        Args:
            host (str): The server host for the request handler.
            port (int): The server port for the request handler.
            cert_path (str): The path to the server's certificate for secure communication.
        """
        self.host = host
        self.port = port
        self.cert_path = cert_path

        self.notes_dir = os.path.expanduser("~/.local/share/NoteIST/notes")
        self.priv_key_path = os.path.expanduser("~/.config/NoteIST/priv_key.pem")

        self.username = None
        self.request_handler = None

        # this innititalizes the username, request_handler and other necessary files and directories
        self._initialize_environment()

    def _initialize_environment(self) -> str:
        """Sets up the required directories and checks for keys."""
        # Ensure the notes directory exists
        if not os.path.exists(self.notes_dir):
            os.makedirs(self.notes_dir)

        # Check for existing private key; if not found, prompt the user to create anwe account
        if not os.path.exists(self.priv_key_path):
            self._register_new_user()

    def _register_new_user(self):
        """Handles new user registration."""
        choice = input(
            "No key found. Would you like to register as a new user? [yes/no]: "
        )
        if choice.lower() in ["yes", "y"]:
            try:
                self.username = input("Enter your username (must be unique): ").strip()
                if not self.username:
                    raise ValueError("Username cannot be empty.")
                public_key = generate_key_pair(self.priv_key_path)
                self.request_handler = SecureRequestHandler(
                    self.username, self.host, self.port, self.cert_path
                )
                self.register_user_in_server(self.username, public_key)
                return self.username
            except Exception as e:
                print(f"Error during registration: {e}")
        else:
            print("Exiting. User registration is required.")
            exit(1)

    def register_user_in_server(self, username: str, public_key: rsa.RSAPublicKey):
        """Registers a new user by generating a key pair."""
        try:
            # Register the user in the server
            self.request_handler.register_user(username, public_key)
            print(
                f"User '{username}' registered successfully!.\nWelcome to NoteIST {username}!"
            )
        except Exception as e:
            print(f"Error registering user in the server: {e}")
            exit(1)

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
            d
            for d in os.listdir(self.notes_dir)
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

        versions = [f for f in os.listdir(note_dir) if f.endswith(".notist")]

        if len(versions) <= 1:
            shutil.rmtree(note_dir)
            print(f"All versions of note '{selected_note}' deleted successfully!")
            return

        delete_all = (
            input("Delete all versions of the note? (yes/no): ").strip().lower()
        )
        if delete_all == "yes":
            shutil.rmtree(note_dir)
            print(f"All versions of note '{selected_note}' deleted successfully!")
        else:
            version = self._select_version(note_dir)
            if version is None:
                return

            filepath = os.path.join(note_dir, version)
            os.remove(filepath)
            print(f"Note '{selected_note}' version '{version}' deleted successfully!")

            if not os.listdir(note_dir):
                os.rmdir(note_dir)

    def push_changes(self):
        """Placeholder for pushing changes to the remote server."""
        print("Pushing changes to the remote server...")
        # Implement the logic to sync changes with the server
        # self.request_handler.sync_notes()
        pass


def main():
    host = "192.168.56.14"  # Replace with your server host
    port = 5000  # Replace with your server port
    cert_path = "/path/to/certificate.pem"  # Replace with your certificate path

    app = NoteIST(host=host, port=port, cert_path=cert_path)

    while True:
        choice = app.main_menu()
        if choice == "1":
            app.create_note()
        elif choice == "2":
            app.display_notes_list()
        elif choice == "3":
            app.view_note_content()
        elif choice == "4":
            app.edit_note()
        elif choice == "5":
            app.delete_note()
        elif choice == "6":
            app.push_changes()
        elif choice == "7":
            print("Exiting NoteIST. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
