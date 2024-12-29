import os
from typing import Dict, Any, List
from secure_document import SecureDocumentHandler
from uuid import uuid4
import shutil
import json

from ..crypto.keys import KeyManager


class FileHandler:
    """Handles file operations for notes and configuration."""

    @staticmethod
    def store_key(key: bytes, key_file: str) -> None:
        """Stores an encryption key in a file."""
        try:
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(key)
        except Exception as e:
            raise Exception(f"Failed to store key: {e}")

    @staticmethod
    def load_key(key_file: str) -> bytes:
        """Loads an encryption key from a file."""
        try:
            if not os.path.exists(key_file):
                raise FileNotFoundError(f"Key file not found at {key_file}")

            with open(key_file, "rb") as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to load key: {e}")

    @staticmethod
    def write_json(filepath: str, data: Dict[str, Any]) -> None:
        """Writes JSON data to a file."""
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            raise Exception(f"Failed to write JSON file: {e}")

    @staticmethod
    def read_json(filepath: str) -> Dict[str, Any]:
        """Reads JSON data from a file."""
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except Exception as e:
            raise Exception (f"Failed to read JSON file: {e}")

    @staticmethod
    def ensure_directory(directory: str) -> None:
        """Ensures a directory exists, creating it if necessary."""
        os.makedirs(directory, exist_ok=True)

    @staticmethod
    def delete_all(paths: List[str]) -> None:
        """Deletes all files and directories in the list."""
        for path in paths:
            try:
                shutil.rmtree(path)  # Try removing it as a directory
            except NotADirectoryError:
                os.remove(path)  # Fallback to removing it as a file
            except FileNotFoundError:
                print(f"Path does not exist: {path}")
            except Exception as e:
                print(f"Error deleting {path}: {e}")
            else:
                print(f"Successfully deleted: {path}")

    @staticmethod
    def clean_note_directory(directory: str) -> None:
        # clean note files
        for sub_dir in os.listdir(directory):
            sub_dir_path = os.path.join(directory, sub_dir)
            if os.path.isdir(sub_dir_path):
                for file in os.listdir(sub_dir_path):
                    file_path = os.path.join(sub_dir_path, file)
                    if file != "key":
                        os.remove(file_path)

    @classmethod
    def write_encrypted_note(
        cls,
        # paths
        filePath: str,
        keyFile: str,
        key_manager: KeyManager,
        # note data
        id: int,
        title: str,
        content: str,
        owner: str,
        version: int,
        editors: List[str] = [],
        viewers: List[str] = [],
    ) -> None:
        """Writes content to a file in the specified format."""
        uuid = str(uuid4())
        # TODO: por favor isto é dogwater code race condition vulnerable
        tempFilePath = f"/tmp/notist_temp_{uuid}.json"
        tempKeyFile = f"/tmp/notist_key_{uuid}.json"
        note_key = key_manager.load_note_key(keyFile)
        cls.store_key(note_key, tempKeyFile)

        note_data = {
            "id": id,
            "title": title,
            "note": content,
            "owner": owner,
            "editors": editors,
            "viewers": viewers,
            "version": version,
        }

        try:
            with open(tempFilePath, "w") as f:
                json.dump(note_data, f, indent=4)

            handler = SecureDocumentHandler()
            handler.protect(tempFilePath, tempKeyFile, filePath)
        except Exception as e:
            raise Exception(f"Failed to write and encrypt file: {e}")
        finally:
            if os.path.exists(tempFilePath):
                os.remove(tempFilePath)
            if os.path.exists(tempKeyFile):
                os.remove(tempKeyFile)

    @classmethod
    def read_encrypted_note(
        cls, filePath: str, keyFile: str, key_manager: KeyManager
    ) -> str:
        """Reads teh entire note from a file after verification and decryption."""
        uuid = str(uuid4())
        # TODO: por favor isto é dogwater code race condition vulnerable
        tempFilePath = f"/tmp/notist_temp_{uuid}.json"
        tempKeyFile = f"/tmp/notist_key_{uuid}.json"

        note_key = key_manager.load_note_key(keyFile)
        cls.store_key(note_key, tempKeyFile)

        try:
            handler = SecureDocumentHandler()

            if not handler.checkSingleFile(filePath, tempKeyFile):
                raise Exception("The note's integrity is compromised.")

            handler.unprotect(filePath, tempKeyFile, tempFilePath)

            note_data = cls.read_json(tempFilePath)
            return note_data
        except Exception as e:
            raise Exception(f"Failed to read and decrypt file: {e}")
        finally:
            if os.path.exists(tempFilePath):
                os.remove(tempFilePath)
            if os.path.exists(tempKeyFile):
                os.remove(tempKeyFile)

    def get_highest_version(directory: str) -> int:
        """
        Finds the highest version in the given directory based on the version number.

        Args:
            directory (str): The directory to search.

        Returns:
            int: The highest version number.

        Raises:
            Exception: If no notes are found in the directory.
        """
        # TODO: try catch maybe idrk
        highest_version = -1

        for filename in os.listdir(directory):
            if filename.endswith(".notist") and filename.startswith("v"):
                try:
                    version = int(filename[1:-7])
                    if version > highest_version:
                        highest_version = version
                except ValueError:
                    continue

        if highest_version != -1:
            return highest_version
        else:
            raise Exception("No notes found in the directory.")

    def clean_file(file: str) -> None:
        """
        Cleans the file by removing its contents.

        Args:
            file (str): The file to clean.
        """
        try:
            open(file, "w").close()
        except Exception as e:
            raise Exception(f"Failed to clean file: {e}")


    def save_change(filepath: str, data: Dict[str, Any]) -> None:
        """Appends a dictionary to a JSON file as part of a valid JSON array."""
        try:
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    try:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, list):
                            raise ValueError(f"The existing file ({filepath}) does not contain a JSON array.")
                    except json.JSONDecodeError:
                        existing_data = []
            else:
                existing_data = []

            existing_data.append(data)

            with open(filepath, "w") as f:
                json.dump(existing_data, f, indent=4)
        except Exception as e:
            raise Exception(f"Failed to save change for file {filepath}: {e}")

    def read_changes(filepath: str) -> List[Dict[str, Any]]:
        """Reads a JSON file containing a list of dictionaries."""
        try:
            with open(filepath, "r") as f:
                content = f.read().strip()
                if not content:  # Handle empty file
                    return []
                data = json.loads(content)
                if not isinstance(data, list):
                    raise ValueError("The file does not contain a JSON array.")
                return data
        except FileNotFoundError:
            # Return an empty list if the file does not exist
            return []
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON file: {e}")
        except Exception as e:
            raise Exception(f"Failed to read changes: {e}")
