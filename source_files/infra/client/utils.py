import json
from secure_document import SecureDocumentHandler
from uuid import uuid4
import os
from typing import List, Optional
from exceptions import *

def generate_key() -> bytes:
    """Generates a new random 256-bit encryption key."""
    key = os.urandom(32)  # 256-bit long
    return key


def store_key(key: bytes, key_file: str) -> None:
    """Stores the encryption key in a file."""
    try:
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "wb") as f:
            f.write(key)
        print(f"Key stored at: {key_file}")
    except Exception as e:
        raise SecureDocumentError(f"Failed to store key: {e}")


def load_key(key_file: str) -> bytes:
    """Loads the encryption key from the predefined file, or prompts the user to generate one."""
    try:
        if not os.path.exists(key_file):
            user_input = (
                input(
                    "Key file not found. Do you want to generate a new key? (yes/no): "
                )
                .strip()
                .lower()
            )
            if user_input in ["yes", "y"]:
                key = generate_key()
                store_key(key, key_file)
                print("New encryption key generated and stored.")
                return key
            else:
                raise KeyFileNotFoundError(
                    "Key file not found. Please generate a key using the 'generate-key' command."
                )

        with open(key_file, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise KeyFileNotFoundError(f"Key file not found at {key_file}.")
    except Exception as e:
        raise SecureDocumentError(f"Failed to load key: {e}")


def writeToFile(
    filePath: str,
    keyFile: str,
    title: str,
    content: str,
    version: int,
    editors: Optional[List[str]] = None,
    viewers: Optional[List[str]] = None,
) -> None:
    """Writes content to a file in the specified format."""
    editors = editors or []
    viewers = viewers or []
    uuid = str(uuid4())
    tempFilePath = f"/tmp/notist_temp_{uuid}.json"

    note_data = {
        "title": title,
        "note": content,
        "version": version,
        "editors": editors,
        "viewers": viewers,
    }

    try:
        with open(tempFilePath, "w") as f:
            json.dump(note_data, f, indent=4)

        handler = SecureDocumentHandler()
        handler.protect(tempFilePath, keyFile, filePath)
    except Exception as e:
        raise EncryptionError(f"Failed to write and encrypt file: {e}")
    finally:
        if os.path.exists(tempFilePath):
            os.remove(tempFilePath)


def readFromFile(filePath: str, keyFile: str) -> str:
    """Reads content (note) from a file after verification and decryption."""
    tempFilePath = "/tmp/notist_temp_read.json"

    try:
        handler = SecureDocumentHandler()

        if not handler.checkSingleFile(filePath, keyFile):
            raise IntegrityError(
                "The file integrity or authenticity cannot be verified."
            )

        handler.unprotect(filePath, keyFile, tempFilePath)

        with open(tempFilePath, "r") as f:
            note_data = json.load(f)

        return note_data["note"]
    except IntegrityError as e:
        raise e
    except Exception as e:
        raise EncryptionError(f"Failed to read and decrypt file: {e}")
    finally:
        if os.path.exists(tempFilePath):
            os.remove(tempFilePath)
