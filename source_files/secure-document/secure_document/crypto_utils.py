# secure_document/crypto_utils.py
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import datetime

class SecureDocumentHandler:
    def __init__(self, salt=None):
        """
        Initialize the secure document handler with an optional salt.
        
        Args:
            salt (bytes, optional): Salt for key derivation. Generated if not provided.
        """
        self.salt = salt or os.urandom(16)

    def _derive_key(self, password):
        """
        Derive a secure encryption key from a password.
        
        Args:
            password (str): User-provided password
        
        Returns:
            bytes: Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def protect(self, input_file, password, output_file=None):
        """
        Encrypt a JSON document.
        
        Args:
            input_file (str): Path to input JSON file
            password (str): Encryption password
            output_file (str, optional): Path to output encrypted file
        
        Returns:
            dict: Encrypted document
        """
        # Read input document
        with open(input_file, 'r') as f:
            document = json.load(f)
        
        # Derive encryption key
        key = self._derive_key(password)
        fernet = Fernet(key)
        
        # Encrypt document content
        encrypted_doc = {
            'salt': base64.b64encode(self.salt).decode(),
            'encrypted_content': fernet.encrypt(json.dumps(document).encode()).decode(),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Write to output file if specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(encrypted_doc, f)
        
        return encrypted_doc

    def check(self, input_file):
        """
        Check if a document is encrypted.
        
        Args:
            input_file (str): Path to input file
        
        Returns:
            bool: Whether the document appears to be encrypted
        """
        try:
            with open(input_file, 'r') as f:
                doc = json.load(f)
            
            # Check for key encryption markers
            return all(key in doc for key in ['salt', 'encrypted_content', 'timestamp'])
        except Exception:
            return False

    def unprotect(self, input_file, password, output_file=None):
        """
        Decrypt a JSON document.
        
        Args:
            input_file (str): Path to input encrypted file
            password (str): Decryption password
            output_file (str, optional): Path to output decrypted file
        
        Returns:
            dict: Decrypted document
        """
        # Read encrypted document
        with open(input_file, 'r') as f:
            encrypted_doc = json.load(f)
        
        # Derive key using stored salt
        salt = base64.b64decode(encrypted_doc['salt'])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Decrypt document
        fernet = Fernet(key)
        try:
            decrypted_content = fernet.decrypt(encrypted_doc['encrypted_content'].encode())
            decrypted_doc = json.loads(decrypted_content)
            
            # Write to output file if specified
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(decrypted_doc, f, indent=2)
            
            return decrypted_doc
        except Exception as e:
            raise ValueError("Decryption failed. Incorrect password or corrupted file.") from e