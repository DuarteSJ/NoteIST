# Note secret key management + reading and writing to local files

import json
from secure_document import SecureDocumentHandler
from uuid import uuid4
import os
from typing import List, Optional
from exceptions import (
    SecureDocumentError,
    KeyFileNotFoundError,
    EncryptionError,
    IntegrityError,
)


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
    except Exception as e:
        raise SecureDocumentError(f"Failed to store key: {e}")


def load_key(key_file: str) -> bytes:
    """Loads the encryption key from the predefined file. Raises an error if the key file is not found."""
    try:
        if not os.path.exists(key_file):
            raise KeyFileNotFoundError(
                f"Key file not found at {key_file}. Please ensure the key file exists."
            )

        with open(key_file, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise KeyFileNotFoundError(f"Key file not found at {key_file}.")
    except Exception as e:
        raise SecureDocumentError(f"Failed to load key: {e}")


def writeToFile(
    id: int,
    filePath: str,
    keyFile: str,
    title: str,
    content: str,
    version: int,
    owner: str,
    editors: List[str] = [],
    viewers: List[str] = [],
) -> None:
    """Writes content to a file in the specified format."""
    uuid = str(uuid4())
    tempFilePath = f"/tmp/notist_temp_write_{uuid}.json"

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
        raise EncryptionError(f"Failed to write and encrypt file: {e}")
    finally:
        if os.path.exists(tempFilePath):
            os.remove(tempFilePath)


def unencryptFile(filePath: str, keyFile: str) -> str:
    """Reads teh entire note from a file after verification and decryption."""
    uuid = str(uuid4())
    tempFilePath = f"/tmp/notist_temp_read_{uuid}.json"

    try:
        handler = SecureDocumentHandler()

        if not handler.checkSingleFile(filePath, keyFile):
            raise IntegrityError("The note's integrity is compromised.")

        handler.unprotect(filePath, keyFile, tempFilePath)

        note_data = readJson(tempFilePath)
        return note_data
    except IntegrityError as e:
        raise e
    except Exception as e:
        raise EncryptionError(f"Failed to read and decrypt file: {e}")
    finally:
        if os.path.exists(tempFilePath):
            os.remove(tempFilePath)


def getNoteInfo(note_file: str) -> tuple:
    """Extracts id hamc and iv from note"""
    try:
        with open(note_file, "r") as f:
            note_data = json.load(f)
        return note_data["id"], note_data["hmac"], note_data["iv"]
    except Exception as e:
        raise Exception(f"Failed to get note info: {e}")


def readJson(filePath: str) -> str:
    """Reads the entire note from a file."""
    try:
        with open(filePath, "r") as f:
            note_data = json.load(f)
        return note_data
    except Exception as e:
        raise Exception(f"Failed to read file: {e}")
