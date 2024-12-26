import os
import json
from typing import Dict, Any, Optional
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
        #clean note files
        for sub_dir in os.listdir(directory):
            sub_dir_path = os.path.join(directory, sub_dir)
            if os.path.isdir(sub_dir_path):
                for file in os.listdir(sub_dir_path):
                    file_path = os.path.join(sub_dir_path, file)
                    if file != "key":
                        os.remove(file_path)


        