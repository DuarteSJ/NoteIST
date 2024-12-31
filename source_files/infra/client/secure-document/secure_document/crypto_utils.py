import os
import json

from typing import Tuple, Dict

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes


class SecureDocumentHandler:
    """Module to handle encryption and integrity protection of JSON documents."""

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
            # print(f"JSON data successfully written to {file_path}")
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

    def protect_file(self, input_file: str, key_file: str, output_file: str) -> None:
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
        self.protect(json_data, key)

    def protect(self, json_data: dict, key: bytes, output_file: str) -> None:
        """Protect a JSON object by encrypting its fields, adding an HMAC and writing it to a file."""
        try:  # Encryption process
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Prepare HMAC input (accumulate encrypted data for HMAC)
            hmac_input = b""

            for field in ["title", "note"]:
                if field not in json_data:
                    continue
                value = json_data[field]
                value_bytes = str(value).encode("utf-8")

                encrypted_value = cipher.encrypt(pad(value_bytes, AES.block_size))

                json_data[field] = encrypted_value.hex()

                # Accumulate the encrypted value for HMAC
                hmac_input += encrypted_value

            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(hmac_input)

            json_data["iv"] = iv.hex()
            json_data["hmac"] = hmac.hexdigest()
            self._write_json(output_file, json_data)

        except Exception as e:
            raise Exception(f"Encryption failed: {e}")

    def unprotect_to_file(
        self, input_file: str, key_file: str, output_file: str
    ) -> None:
        """
        Decrypt a protected JSON file and verify its integrity.

        Args:
            input_file (str): Path to the encrypted file.
            key_file (str): Path to the key file containing the encryption key.
            output_file (str): Path to save the decrypted file.
        """
        key = self._parseKeyFile(key_file)

        decrypted_data = self.unprotect(input_file, key)

        self._write_json(output_file, decrypted_data)

    def unprotect(self, input_file: str, key: bytes) -> Dict[str, any]:
        """Read and decrypt a JSON file, verifying its integrity using HMAC and returning the decrypted data."""
        json_data = self._read_json(input_file)
        try:  # Decryption process
            iv = bytes.fromhex(json_data["iv"])
            stored_hmac = json_data["hmac"]

            # Prepare HMAC input (accumulate encrypted data for HMAC verification)
            hmac_input = b""

            cipher = AES.new(key, AES.MODE_CBC, iv)

            for field in ["title", "note"]:
                if field not in json_data:
                    continue

                encrypted_value = bytes.fromhex(json_data[field])
                decrypted_value = unpad(
                    cipher.decrypt(encrypted_value), AES.block_size
                ).decode("utf-8")

                json_data[field] = decrypted_value
                hmac_input += encrypted_value  # Accumulate encrypted data for HMAC

            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(hmac_input)

            if hmac.hexdigest() != stored_hmac:
                raise Exception(
                    "Integrity check failed: HMAC verification unsuccessful."
                )

            return json_data

        except Exception as e:
            raise Exception(f"Decryption failed: {e}")

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

        try:  # Check HMAC
            # Prepare HMAC input (accumulate encrypted data for HMAC verification)
            hmac_input = b""

            cipher = AES.new(key, AES.MODE_CBC, iv)

            for field in ["title", "note"]:
                if field not in encrypted_data:
                    continue
                encrypted_value = bytes.fromhex(encrypted_data[field])
                hmac_input += encrypted_value  # Accumulate encrypted data for HMAC

            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(hmac_input)

            return hmac.hexdigest() == stored_hmac

        except Exception:
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
