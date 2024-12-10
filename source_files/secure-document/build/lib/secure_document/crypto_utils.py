import hashlib
from typing import List, Union, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC


class SecureDocumentHandler:
    """
    Secure document encryption and integrity verification handler
    """

    def _parseEncryptedFile(self, file: str) -> Tuple[bytes, bytes, bytes]:
        """
        Parses an encrypted file and extracts its components.

        The function reads the specified file, extracts the HMAC, IV, and encrypted content.

        Args:
            file (str): The path to the encrypted file to be parsed.

        Returns:
            Tuple[bytes, bytes, bytes]:
                - file_Hmac (bytes): The first 32 bytes of the file representing the HMAC.
                - iv (bytes): The next 16 bytes of the file representing the initialization vector (IV).
                - encrypted_contents (bytes): The remaining bytes of the file containing the encrypted content.

        Raises:
            FileNotFoundError: If the specified file does not exist.
            Exception: For any other issues encountered while reading the file.
        """

        try:
            with open(file, "rb") as f:
                file_contents = f.read()
            file_Hmac = file_contents[:32]
            iv = file_contents[32:48]
            encrypted_contents = file_contents[48:]
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file '{file}' not found.")
        except Exception as e:
            raise Exception(f"Unable to read input file '{file}'. Details: {e}")

        return file_Hmac, iv, encrypted_contents

    def _parseKeyFile(self, key_file: str) -> bytes:
        try:
            with open(key_file, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file '{key_file}' not found.")
        except Exception as e:
            raise Exception(f"Unable to read key file '{key_file}'. Details: {e}")
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
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Input file '{input_file}' not found.") from e
        except Exception as e:
            raise Exception(f"Unable to read input file '{input_file}'.") from e

        try: # Encryption process
            cipher = AES.new(key, AES.MODE_CBC)

            encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))

            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(cipher.iv + encrypted_contents)
            file_hmac = hmac.digest()

            # [HMAC (32 bytes)][IV (16 bytes)][encrypted data (n*16 bytes)]
            protected_contents = file_hmac + cipher.iv + encrypted_contents

        except Exception as e:
            raise Exception(f"Encryption failed: {e}")

        try:
            with open(output_file, "wb") as f:
                f.write(protected_contents)
        except Exception as e:
            raise Exception(
                f"Error: Unable to write to output file '{output_file}'. Details: {e}"
            )

    def unprotect(self, input_file: str, key_file: str, output_file: str):
        """
        Decrypt a protected file and verify integrity

        Returns True if successful, False otherwise
        """

        key = self._parseKeyFile(key_file)
        _, iv, encrypted_contents = self._parseEncryptedFile(input_file)

        try: # Decryption process
            cipher = AES.new(key, AES.MODE_CBC, iv)

            decrypted_contents = unpad(
                cipher.decrypt(encrypted_contents), AES.block_size
            )

        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
        
        try:
            with open(output_file, "wb") as f:
                f.write(decrypted_contents)
        except Exception as e:
            raise Exception(
                f"Error: Unable to write to output file '{output_file}'. Details: {e}"
            )

    def checkMissingFiles(self, fileList: List[str], digestOfHmacs: str) -> bool:
        currDigestofHmacs = b""  # Initialize as bytes

        for file in fileList:
            try:
                fileHmac, _, _ = self._parseEncryptedFile(
                    file
                )  # Read the first 32 bytes
                currDigestofHmacs += fileHmac  # Concatenate bytes
            except FileNotFoundError:
                print(f"Error: Input file '{file}' not found.")
                return False
            except Exception as e:
                print(f"Error: Unable to read input file '{file}'. Details: {e}")
                return False

        # Hash the concatenated HMACs
        hash = SHA256.new()
        hash.update(currDigestofHmacs)
        currDigestOfHMacs = hash.hexdigest()

        # Compare the computed hash with the provided one
        return currDigestOfHMacs == digestOfHmacs

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
