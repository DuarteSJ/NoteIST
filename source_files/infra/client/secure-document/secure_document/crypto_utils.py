import os
import json

from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes


class SecureDocumentHandler:
    def _write_json(self, file_path: str, data: dict, indent: int = 2):
        """
        Dumps a dictionary into a JSON file.

        :param file_path: Path to the JSON file to be written.
        :param data: Dictionary to write to the file.
        :param indent: Indentation level for pretty-printing. Defaults to 4.
        """
        try:
            with open(file_path, "w") as file:
                json.dump(data, file, indent=indent)
            #print(f"JSON data successfully written to {file_path}")
        except Exception as e:
            print(f"Error writing JSON to file: {e}")

    def _read_json(self, file_path: str) -> dict:
        """
        Reads a JSON file and returns its contents as a dictionary.

        :param file_path: Path to the JSON file.
        :return: Dictionary containing the JSON data.
        """
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return {}
        except Exception as e:
            print(f"Unexpected error: {e}")
            return {}

    def _parse_encrypted_file(self, input_file: str) -> Tuple[bytes, str, dict]:
        """
        Parse an encrypted JSON file and return its components.

        Args:
            input_file (str): Path to the encrypted file.

        Returns:
            Tuple[bytes, str, dict]:
                - IV (bytes): Initialization vector for decryption.
                - HMAC (str): Stored HMAC from the file.
                - Encrypted Data (dict): Dictionary of encrypted values.

        Raises:
            FileNotFoundError: If the input file does not exist.
            Exception: If the file cannot be parsed or has an invalid format.
        """

        encrypted_json = self._read_json(input_file)

        # Validate encrypted JSON structure
        if not all(k in encrypted_json for k in ["iv", "hmac"]):
            raise Exception("Invalid encrypted file format")

        # Extract components
        iv = bytes.fromhex(encrypted_json["iv"])
        stored_hmac = encrypted_json["hmac"]
        encrypted_data = {
            k: v for k, v in encrypted_json.items() if k not in ["iv", "hmac"]
        }

        return iv, stored_hmac, encrypted_data

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

    def protect_string(input_string: str, key: bytes) -> str:
        """
        Encrypt a string and add integrity protection.

        Args:
            input_string (str): String to be encrypted
            key (bytes): Encryption key

        Returns:
            str: JSON string containing the encrypted data, IV, and HMAC

        Raises:
            Exception: If encryption fails
        """
        try:
            # Create IV for encryption
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Convert string to bytes and encrypt
            value_bytes = input_string.encode("utf-8")
            encrypted_value = cipher.encrypt(pad(value_bytes, AES.block_size))

            # Compute HMAC
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(value_bytes)

            # Create protected structure
            protected_data = {
                "iv": iv.hex(),
                "hmac": hmac.hexdigest(),
                "data": encrypted_value.hex(),
            }

            return json.dumps(protected_data)

        except Exception as e:
            raise Exception(f"String encryption failed: {e}")

    def protect(self, input_file: str, key_file: str, output_file: str) -> None:
        """
        Encrypt a JSON file and add integrity protection with a single IV.

        Args:
            input_file (str): Path to the JSON file to be encrypted.
            key_file (str): Path to the key file containing the encryption key.
            output_file (str): Path to save the encrypted file.

        Raises:
            FileNotFoundError: If the input or key file does not exist.
            Exception: If encryption or writing the output file fails.
        """
        key = self._parseKeyFile(key_file)

        json_data = self._read_json(input_file)

        try:  # Encryption process
            # Create a single IV for the entire encryption
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Prepare encrypted JSON
            encrypted_json = {}
            hmac_input = b""

            for k, v in json_data.items():
                if k in ["title", "note"]:
                    # Convert value to bytes for encryption
                    # TODO: assuming its string
                    value_bytes = str(v).encode("utf-8")

                    # Encrypt the value
                    encrypted_value = cipher.encrypt(pad(value_bytes, AES.block_size))

                    # Store encrypted value
                    encrypted_json[k] = encrypted_value.hex()

                    # Accumulate data for HMAC
                    hmac_input += k.encode("utf-8") + value_bytes
                else:
                    encrypted_json[k] = v

            # Compute HMAC for all keys and values
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(hmac_input)

            # Create final encrypted structure
            final_encrypted = {"iv": iv.hex(), "hmac": hmac.hexdigest()}

            for field, val in encrypted_json.items():
                final_encrypted[field] = val

        except Exception as e:
            raise Exception(f"Encryption failed: {e}")

        self._write_json(output_file, final_encrypted)

    def unprotect_string(protected_string: str, key: bytes) -> str:
        """
        Decrypt a protected string and verify its integrity.

        Args:
            protected_string (str): JSON string containing encrypted data
            key (bytes): Encryption key

        Returns:
            str: Decrypted string

        Raises:
            Exception: If decryption or integrity verification fails
        """
        try:
            # Parse protected data
            protected_data = json.loads(protected_string)

            # Validate structure
            if not all(k in protected_data for k in ["iv", "hmac", "data"]):
                raise Exception("Invalid protected string format")

            # Extract components
            iv = bytes.fromhex(protected_data["iv"])
            stored_hmac = protected_data["hmac"]
            encrypted_value = bytes.fromhex(protected_data["data"])

            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(encrypted_value), AES.block_size)
            decrypted_string = decrypted_bytes.decode("utf-8")

            # Verify HMAC
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(decrypted_bytes)

            if hmac.hexdigest() != stored_hmac:
                raise Exception(
                    "Integrity check failed: HMAC verification unsuccessful"
                )

            return decrypted_string

        except Exception as e:
            raise Exception(f"String decryption failed: {e}")

    def unprotect(self, input_file: str, key_file: str, output_file: str) -> None:
        """
        Decrypt a protected JSON file and verify its integrity.

        Args:
            input_file (str): Path to the encrypted file.
            key_file (str): Path to the key file containing the encryption key.
            output_file (str): Path to save the decrypted file.
        """
        key = self._parseKeyFile(key_file)

        iv, stored_hmac, encrypted_data = self._parse_encrypted_file(input_file)

        try:
            hmac_input = b""
            decrypted_json = {}

            # Create cipher with single IV
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Decrypt and verify each value
            for k, v in encrypted_data.items():
                if k in ["title", "note"]:
                    # Decrypt the value
                    encrypted_value = bytes.fromhex(v)
                    decrypted_value = unpad(
                        cipher.decrypt(encrypted_value), AES.block_size
                    ).decode("utf-8")

                    # Store decrypted value
                    decrypted_json[k] = decrypted_value

                    # Accumulate data for HMAC verification
                    hmac_input += k.encode("utf-8") + decrypted_value.encode("utf-8")
                else:
                    decrypted_json[k] = v

            # Verify HMAC
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(hmac_input)

            if hmac.hexdigest() != stored_hmac:
                raise Exception(
                    "Integrity check failed: HMAC verification unsuccessful."
                )

        except Exception as e:
            raise Exception(f"Decryption failed: {e}")

        self._write_json(output_file, decrypted_json)

    def check_string(protected_string: str, key: bytes) -> bool:
        """
        Verify the integrity of a protected string by checking its HMAC.

        Args:
            protected_string (str): JSON string containing encrypted data
            key (bytes): Encryption key

        Returns:
            bool: True if the string's HMAC matches the computed HMAC, False otherwise
        """
        try:
            # Parse protected data
            protected_data = json.loads(protected_string)

            # Validate structure
            if not all(k in protected_data for k in ["iv", "hmac", "data"]):
                return False

            # Extract components
            iv = bytes.fromhex(protected_data["iv"])
            stored_hmac = protected_data["hmac"]
            encrypted_value = bytes.fromhex(protected_data["data"])

            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(encrypted_value), AES.block_size)

            # Compute and verify HMAC
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(decrypted_bytes)

            return hmac.hexdigest() == stored_hmac

        except Exception:
            return False

    def checkSingleFile(self, file: str, key_file: str) -> bool:
        """
        Verify the integrity of a single encrypted JSON file by checking its HMAC.

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

        iv, stored_hmac, encrypted_data = self._parse_encrypted_file(file)

        try:
            hmac_input = b""
            cipher = AES.new(key, AES.MODE_CBC, iv)

            for k, v in encrypted_data.items():
                if k in ["title", "note"]:
                    # Convert encrypted value back to bytes
                    encrypted_value = bytes.fromhex(v)
                    decrypted_value = unpad(
                        cipher.decrypt(encrypted_value), AES.block_size
                    ).decode("utf-8")

                    # Prepare data for HMAC
                    hmac_input += k.encode("utf-8") + decrypted_value.encode("utf-8")

            # Compute HMAC and compare
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(hmac_input)
            return hmac.hexdigest() == stored_hmac

        except Exception as e:
            return False

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
                if ".notist" in fileName:
                    filePath = os.path.join(root, fileName)
                    _, fileHmac, _ = self._parse_encrypted_file(filePath)
                    currDigestofHmacs += fileHmac  # Concatenate bytes

        # Hash the concatenated HMACs
        hash = SHA256.new()
        hash.update(currDigestofHmacs)
        currDigestOfHMacs = hash.hexdigest()

        return currDigestOfHMacs == digestOfHmacs
