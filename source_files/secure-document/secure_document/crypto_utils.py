from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import pbkdf2_hmac
import hmac
import hashlib
import base64
import json
import os

class SecureNoteHandler:
    def __init__(self, key):
        self.key = key

    def _encrypt(self, data):
        """Encrypts the data using AES-CBC."""
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted_data).decode()

    def _decrypt(self, encrypted_data):
        """Decrypts the data using AES-CBC."""
        raw_data = base64.b64decode(encrypted_data)
        iv = raw_data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(raw_data[AES.block_size:]), AES.block_size)
        return decrypted_data.decode()

    def _generate_hmac(self, data):
        """Generates an HMAC for the data."""
        return base64.b64encode(hmac.new(self.key, data.encode(), hashlib.sha256).digest()).decode()

    def _verify_hmac(self, data, hmac_value):
        """Verifies the HMAC for the data."""
        return hmac.compare_digest(self._generate_hmac(data), hmac_value)

    def protect(self, note, previous_hash="0"):
        """Protects a single note (encrypt and add integrity)."""
        
        # Prepare note metadata
        note_data = {
            "id": note["id"],
            "content": note["content"],
            "previousHash": previous_hash
        }

        

        # Generate HMAC
        note_data["hmac"] = self._generate_hmac(json.dumps(note_data))

        # Encrypt the note
        encrypted_note = self._encrypt(json.dumps(note_data))
        return encrypted_note

    def check(self, encrypted_note):
        """Verifies the integrity of a single encrypted note."""
        # Decrypt the note
        try:
            decrypted_note = self._decrypt(encrypted_note)
        except Exception as e:
            return {"status": "error", "message": "Decryption failed. Invalid data or corrupted content."}

        # Verify HMAC
        note_data = json.loads(decrypted_note)
        hmac_value = note_data.pop("hmac")
        if not self._verify_hmac(json.dumps(note_data), hmac_value):
            return {"status": "tampered", "message": f"Note {note_data['id']} has been altered or is corrupted."}
        
        return {"status": "ok", "message": f"Note {note_data['id']} is intact and verified."}

    def unprotect(self, encrypted_note):
        """Reverts a single protected note to its original state (decrypt and verify)."""
        # Decrypt the note
        try:
            decrypted_note = self._decrypt(encrypted_note)
        except Exception as e:
            return {"status": "error", "message": "Decryption failed. Invalid data or corrupted content."}

        # Verify HMAC
        note_data = json.loads(decrypted_note)
        hmac_value = note_data.pop("hmac")
        if not self._verify_hmac(json.dumps(note_data), hmac_value):
            return {"status": "error", "message": "Integrity verification failed. Cannot unprotect."}
        
        return {"status": "ok", "note": note_data}