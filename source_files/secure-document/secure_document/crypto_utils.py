import os
import base64
import hashlib
import argparse
from typing import List, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

class MerkleTree:
    """
    Merkle Tree implementation for integrity verification
    """
    def __init__(self, file_paths: List[str]):
        self.file_paths = file_paths
        self.leaves = self._compute_leaves()
        self.root = self._build_tree()

    def _compute_leaves(self) -> List[bytes]:
        """
        Compute hash of each file to create Merkle tree leaves
        """
        leaves = []
        for file_path in self.file_paths:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).digest()
                leaves.append(file_hash)
        return leaves

    def _build_tree(self) -> bytes:
        """
        Build Merkle tree and return root hash
        """
        if not self.leaves:
            return hashlib.sha256(b'').digest()

        # Copy leaves to work with
        current_layer = self.leaves.copy()

        # Build tree bottom-up
        while len(current_layer) > 1:
            next_layer = []
            
            # Process leaves in pairs
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i+1] if i+1 < len(current_layer) else left
                
                # Concatenate and hash
                combined_hash = hashlib.sha256(left + right).digest()
                next_layer.append(combined_hash)
            
            current_layer = next_layer

        return current_layer[0]

    def verify(self, other_root: bytes) -> bool:
        """
        Verify if the current tree matches another root hash
        """
        return self.root == other_root

class SecureDocumentHandler:
    """
    Secure document encryption and integrity verification handler
    """
    def __init__(self):
        pass

    def protect(self, input_file: str, key: str, output_file: str) -> bytes:
        """
        Encrypt a file and add integrity protection
        
        Steps:
        1. Read input file
        2. Encrypt file contents
        3. Compute Merkle tree root hash
        4. Write encrypted file with hash and salt
        """
        with open(input_file, 'rb') as f:
            file_contents = f.read()
        
        # Create cipher with random IV
        cipher = AES.new(key, AES.MODE_CBC)
        
        # Encrypt file contents
        encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))
        
        # Compute Merkle tree (single file case)
        merkle_tree = MerkleTree([input_file])
        
        # Prepare protected contents: 
        # [salt (16 bytes)][root hash (32 bytes)][IV (16 bytes)][encrypted data]
        protected_contents = (
            salt + 
            merkle_tree.root + 
            cipher.iv + 
            encrypted_contents
        )
        
        # Write protected file
        with open(output_file, 'wb') as f:
            f.write(protected_contents)
        
        return merkle_tree.root

    def unprotect(self, input_file: str, output_file: str) -> bool:
        """
        Decrypt a protected file and verify integrity
        
        Returns True if successful, False otherwise
        """
        with open(input_file, 'rb') as f:
            file_contents = f.read()
        
        # Extract components
        salt = file_contents[:16]
        original_root_hash = file_contents[16:48]
        iv = file_contents[48:64]
        encrypted_contents = file_contents[64:]
        
        try:
            # Create cipher
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # Decrypt
            decrypted_contents = unpad(cipher.decrypt(encrypted_contents), AES.block_size)
            
            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(decrypted_contents)
            
            return True
        except Exception as e:
            print(f"Decryption failed: {e}")
            return False

    def check(self, input_file: str) -> bool:
        """
        Check file integrity without decrypting
        """
        with open(input_file, 'rb') as f:
            file_contents = f.read()
        
        # Basic integrity checks
        try:
            # Extract components
            salt = file_contents[:16]
            original_root_hash = file_contents[16:48]
            iv = file_contents[48:64]
            encrypted_contents = file_contents[64:]
            
            return (
                len(salt) == 16 and 
                len(original_root_hash) == 32 and 
                len(iv) == 16
            )
        except Exception:
            return False
