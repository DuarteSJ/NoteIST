import hashlib
from typing import List, Union, Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
import sys

class SecureDocumentHandler:
    """
    Secure document encryption and integrity verification handler
    """

    def _parseEncryptedFile(file: str):
        try:
            with open(file, "rb") as f:
                file_contents = f.read()
            file_Hmac = file_contents[:32]
            iv = file_contents[32:48]
            encrypted_contents = file_contents[48:]
        except FileNotFoundError:
            print(f"Check Error: Input file '{file}' not found.")
            return False
        except Exception as e:
            print(f"Check Error: Unable to read input file '{file}'. Details: {e}")
            return False
        
        return file_Hmac, iv, encrypted_contents

    def _parseKeyFile(key_file: str) -> bytes:
        try:
            with open(key_file, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            print(f"Error: Key file '{key_file}' not found.")
            return False
        except Exception as e:
            print(f"Error: Unable to read key file '{key_file}'. Details: {e}")
        
        return key

    def protect(self, input_file: str, key_file: str, output_file: str) -> bytes:
        """
        Encrypt a file and add integrity protection

        Steps:
        1. Read input file
        2. Encrypt file contents
        3. Compute HMAC for integrity verification
        4. Write encrypted file with HMAC and IV
        """

        key = self._parseKeyFile(key_file)

        try:
            with open(input_file, "rb") as f:
                file_contents = f.read()
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found.")
            return False
        except Exception as e:
            print(f"Error: Unable to read input file '{input_file}'. Details: {e}")
            return False

        # Create cipher with random IV
        cipher = AES.new(key, AES.MODE_CBC)

        # Encrypt file contents
        encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))

        # Compute the HMAC of the encrypted content
        hmac = HMAC.new(key, digestmod=SHA256)
        hmac.update(cipher.iv + encrypted_contents)
        file_hmac = hmac.digest()

        # Prepare protected contents:
        # [HMAC (32 bytes)][IV (16 bytes)][encrypted data (n*16 bytes)]
        protected_contents = (
            file_hmac
            + cipher.iv
            + encrypted_contents
        )

        # Write protected file
        try:
            with open(output_file, "wb") as f:
                f.write(protected_contents)
        except Exception as e:
            print(f"Error: Unable to write to output file '{output_file}'. Details: {e}")
            return False

        print(f"File '{input_file}' successfully encrypted and protected.")
        return True

    def unprotect(self, input_file: str, key_file: str, output_file: str) -> bool:
        """
        Decrypt a protected file and verify integrity

        Returns True if successful, False otherwise
        """

        key = self._parseKeyFile(key_file)
        _, iv, encrypted_contents = self._parseEncryptedFile(input_file)

        try:
            # Create a cipher with the extracted IV
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Decrypt
            decrypted_contents = unpad(
                cipher.decrypt(encrypted_contents), AES.block_size
            )

            # Write decrypted file
            with open(output_file, "wb") as f:
                f.write(decrypted_contents)

            return True
        except Exception as e:
            print(f"Decryption failed: {e}")
            sys.exit(1)

    def checkMissingFiles(self, fileList: List[str], digestOfMacs: str) -> bool:
        currHashofMacs = b""  # Initialize as bytes

        for file in fileList:
            try:
                fileHmac, _, _ = self._parseEncryptedFile(file) # Read the first 32 bytes
                currHashofMacs += fileHmac  # Concatenate bytes
            except FileNotFoundError:
                print(f"Error: Input file '{file}' not found.")
                sys.exit(1)
            except Exception as e:
                print(f"Error: Unable to read input file '{file}'. Details: {e}")
                sys.exit(1)

        # Hash the concatenated HMACs
        hash = SHA256.new()
        hash.update(currHashofMacs)
        currDigestOfMacs = hash.hexdigest() 

        # Compare the computed hash with the provided one
        return currDigestOfMacs == digestOfMacs


    def checkSingleFile(self, file: str, key_file: str) -> bool:
        """
        Check the integrity of a single file
        """

        key = self._parseKeyFile(key_file)
        file_Hmac, iv, encrypted_contents = self._parseEncryptedFile(file)

        # Compute the HMAC of the encrypted content
        hmac = HMAC.new(key, digestmod=SHA256)
        hmac.update(iv + encrypted_contents)
        new_hmac = hmac.digest()

        return file_Hmac == new_hmac
     
