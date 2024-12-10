import os

from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC


class SecureDocumentHandler:
    """
    A class to handle secure encryption, decryption, and integrity verification of files.

    This class provides methods to encrypt files with integrity protection, decrypt files while verifying their integrity,
    and perform checks to detect file tampering or missing files based on HMAC.
    """

    def _parseEncryptedFile(self, file: str) -> Tuple[bytes, bytes, bytes]:
        """
        Parse an encrypted file and extract its components.

        Args:
            file (str): The path to the encrypted file to be parsed.

        Returns:
            Tuple[bytes, bytes, bytes]:
                - file_Hmac (bytes): The first 32 bytes of the file containing the HMAC.
                - iv (bytes): The next 16 bytes of the file containing the initialization vector (IV).
                - encrypted_contents (bytes): The remaining bytes containing the encrypted content.

        Raises:
            FileNotFoundError: If the specified file does not exist.
            Exception: If any other issue occurs while reading the file.
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
        """
        Read and return the encryption key from a key file.

        Args:
            key_file (str): The path to the key file.

        Returns:
            bytes: The encryption key.

        Raises:
            FileNotFoundError: If the key file does not exist.
            Exception: If any other issue occurs while reading the key file.
        """
        try:
            with open(key_file, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file '{key_file}' not found.")
        except Exception as e:
            raise Exception(f"Unable to read key file '{key_file}'. Details: {e}")
        return key

    def protect(self, input_file: str, key_file: str, output_file: str) -> None:
        """
        Encrypt a file and add integrity protection.

        Args:
            input_file (str): Path to the file to be encrypted.
            key_file (str): Path to the key file containing the encryption key.
            output_file (str): Path to save the encrypted file.

        Raises:
            FileNotFoundError: If the input or key file does not exist.
            Exception: If encryption or writing the output file fails.
        """
        key = self._parseKeyFile(key_file)

        try:
            with open(input_file, "rb") as f:
                file_contents = f.read()
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Input file '{input_file}' not found.") from e
        except Exception as e:
            raise Exception(f"Unable to read input file '{input_file}'.") from e

        try:  # Encryption process
            cipher = AES.new(key, AES.MODE_CBC)
            encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))

            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(cipher.iv + encrypted_contents)
            file_hmac = hmac.digest()

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

    def unprotect(self, input_file: str, key_file: str, output_file: str) -> None:
        """
        Decrypt a protected file and verify its integrity.

        Args:
            input_file (str): Path to the encrypted file.
            key_file (str): Path to the key file containing the encryption key.
            output_file (str): Path to save the decrypted file.

        Raises:
            FileNotFoundError: If the input or key file does not exist.
            Exception: If decryption or integrity verification fails, or writing the output file fails.
        """
        key = self._parseKeyFile(key_file)
        file_Hmac, iv, encrypted_contents = self._parseEncryptedFile(input_file)

        try:  # Verify HMAC
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(iv + encrypted_contents)
            hmac.verify(file_Hmac)
        except Exception as e:
            raise Exception(f"Integrity check failed: {e}")

        try:  # Decrypt contents
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

    def checkMissingFiles(self, directoryPath: str, digestOfHmacs: str) -> bool:
        """
        Check if any files in the directory are missing or if any new files have been added.

        This method computes a hash of the HMACs of all files in the directory and compares it with
        a provided hash to detect any discrepancies.

        Args:
            directoryPath (str): Path to the directory containing files to check.
            digestOfHmacs (str): Expected hash of the concatenated HMACs.

        Returns:
            bool: True if the files match the expected state, False otherwise.

        Raises:
            Exception: If any file cannot be read or parsed.
        """
        currDigestofHmacs = b""

        # Iterate over all files in the directory
        for root, _, files in os.walk(directoryPath):
            for fileName in files:
                filePath = os.path.join(root, fileName)
                fileHmac, _, _ = self._parseEncryptedFile(filePath)
                currDigestofHmacs += fileHmac  # Concatenate bytes

        # Hash the concatenated HMACs
        hash = SHA256.new()
        hash.update(currDigestofHmacs)
        currDigestOfHMacs = hash.hexdigest()

        return currDigestOfHMacs == digestOfHmacs

    def checkSingleFile(self, file: str, key_file: str) -> bool:
        """
        Verify the integrity of a single file by checking its HMAC.

        Args:
            file (str): Path to the file to verify.
            key_file (str): Path to the key file containing the encryption key.

        Returns:
            bool: True if the file's HMAC matches the computed HMAC, False otherwise.

        Raises:
            FileNotFoundError: If the file or key file does not exist.
            Exception: If the file cannot be parsed or HMAC verification fails.
        """
        key = self._parseKeyFile(key_file)
        file_Hmac, iv, encrypted_contents = self._parseEncryptedFile(file)

        try:
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(iv + encrypted_contents)
            new_hmac = hmac.digest()
        except Exception as e:
            raise Exception(f"Error while computing HMAC: {e}")

        return file_Hmac == new_hmac
