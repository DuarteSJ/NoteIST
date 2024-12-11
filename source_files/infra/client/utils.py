import json
from secure_document import SecureDocumentHandler
from datetime import datetime
from uuid import uuid4
import os

def writeToFile(filePath, keyFile, title, content, version, editors=[], viewers=[]):
    """Writes content to a file in the specified format."""

    uuid = str(uuid4())
    tempFilePath = "/tmp/notist_temp_" + uuid + ".json"

    #TODO: Change data
    note_data = {
        "title": title,
        "note": content,
    }

    # Write the note data to the file in JSON format
    with open(tempFilePath, "w") as f:
        json.dump(note_data, f, indent=4)
    
    SecureDocumentHandler().protect(tempFilePath, keyFile, filePath)

    # Remove the temporary file
    os.remove(tempFilePath)



def readFromFile(filePath, keyFile):
    """Reads content (note) from a file after verification and decryption."""
    tempFilePath = "/tmp/notist_temp_read.json"

    handler = SecureDocumentHandler()
    
    # Verify the file integrity and authenticity
    if not handler.checkSingleFile(filePath, keyFile):
        raise ValueError("The file integrity or authenticity cannot be verified.")
    
    # Decrypt and unprotect the file
    handler.unprotect(filePath, keyFile, tempFilePath)
    
    # Read the decrypted content
    with open(tempFilePath, "r") as f:
        note_data = json.load(f)
    
    # Remove the temporary file
    os.remove(tempFilePath)
    
    # Return only the note content
    return note_data["note"]

