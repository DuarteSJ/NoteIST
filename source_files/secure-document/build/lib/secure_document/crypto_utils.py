import hashlib
from typing import List

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

class SecureDocumentHandler:
    """
    Secure document encryption and integrity verification handler
    """

    def __init__(self):
        pass

    def protect(self, input_file: str, key_file: str, output_file: str) -> bytes:
        """
        Encrypt a file and add integrity protection

        Steps:
        1. Read input file
        2. Encrypt file contents
        3. Compute Merkle tree root hash
        4. Write encrypted file with hash and salt
        """

        try:
            with open(input_file, "rb") as f:
                file_contents = f.read()
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found.")
            return False
        except Exception as e:
            print(f"Error: Unable to read input file '{input_file}'. Details: {e}")
            return False

        try:
            with open(key_file, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            print(f"Error: Key file '{key_file}' not found.")
            return False
        except Exception as e:
            print(f"Error: Unable to read key file '{key_file}'. Details: {e}")
            return False


        # Create cipher with random IV
        cipher = AES.new(key, AES.MODE_CBC)

        # Encrypt file contents
        encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))


        # Prepare protected contents:
        # [root hash (32 bytes)][IV (16 bytes)][encrypted data (n*16 bytes)]
        protected_contents = (
            bytes(
                [ord("a") for _ in range(32)]
            )  # TODO: this should be merkle_tree.root if we use it. Currently just 32 bytes of "a"'s
            + cipher.iv
            + encrypted_contents
        )

        # Write protected file
        with open(output_file, "wb") as f:
            f.write(protected_contents)

        return 

    def unprotect(self, input_file: str, key_file: str, output_file: str) -> bool:
        """
        Decrypt a protected file and verify integrity

        Returns True if successful, False otherwise
        """

        try:
            with open(input_file, "rb") as f:
                file_contents = f.read()
        except FileNotFoundError:
            print(f"Error: Input file '{input_file}' not found.")
            return False
        except Exception as e:
            print(f"Error: Unable to read input file '{input_file}'. Details: {e}")
            return False

        try:
            with open(key_file, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            print(f"Error: Key file '{key_file}' not found.")
            return False
        except Exception as e:
            print(f"Error: Unable to read key file '{key_file}'. Details: {e}")
            return False

        # Extract components
        original_root_hash = file_contents[
            :32
        ]  # TODO: unless u changed line 93, this is just a bunch of "a"'s
        iv = file_contents[32:48]
        encrypted_contents = file_contents[48:]

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
            return False

    def check(self, input_file: str) -> bool:
        # TODO: falar com o stor sobre detalhes desta funcao.
        # hip 1. recebe file encriptado e key para desencriptar e ver hash?
        # hip 2. recebe file desencriptado e hash desse file para computar e comparar
        # hip 3. Nao checka integrity, so vê se ta encryptado (é o que se entende do enunciado, mas vai contra o que o professor disse)
        """
        Check file integrity without decrypting
        """
        with open(input_file, "rb") as f:
            file_contents = f.read()

        # Basic integrity checks
        try:
            # Extract components
            original_root_hash = file_contents[:32]
            iv = file_contents[32:48]
            encrypted_contents = file_contents[48:]

            return len(original_root_hash) == 32 and len(iv) == 16
        except Exception:
            return False
