import os
import json
from typing import Dict, Any, List
from secure_document import SecureDocumentHandler
from uuid import uuid4


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
        print(f"note dict in write json function: {data}")
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
            raise Exception(f"Failed to read JSON file: {e}")

    @staticmethod
    def ensure_directory(directory: str) -> None:
        """Ensures a directory exists, creating it if necessary."""
        os.makedirs(directory, exist_ok=True)

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

    def write_encrypted_note(
        # paths
        filePath: str,
        keyFile: str,
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
        editors = editors
        viewers = viewers
        uuid = str(uuid4())
        tempFilePath = f"/tmp/notist_temp_{uuid}.json"

        note_data = {
            "_id": id,
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
            handler.protect(tempFilePath, keyFile, filePath)
        except Exception as e:
            raise Exception(f"Failed to write and encrypt file: {e}")
        finally:
            if os.path.exists(tempFilePath):
                os.remove(tempFilePath)

    def read_encrypted_note(filePath: str, keyFile: str) -> str:
        """Reads teh entire note from a file after verification and decryption."""
        tempFilePath = "/tmp/notist_temp_read.json"

        try:
            handler = SecureDocumentHandler()

            if not handler.checkSingleFile(filePath, keyFile):
                raise Exception("The note's integrity is compromised.")

            handler.unprotect(filePath, keyFile, tempFilePath)

            note_data = Exception(tempFilePath)
            return note_data
        except Exception as e:
            raise Exception(f"Failed to read and decrypt file: {e}")
        finally:
            if os.path.exists(tempFilePath):
                os.remove(tempFilePath)
