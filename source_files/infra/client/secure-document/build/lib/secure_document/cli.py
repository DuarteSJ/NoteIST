import argparse
import sys
from typing import List

from secure_document.crypto_utils import SecureDocumentHandler


def initialize_handler() -> SecureDocumentHandler:
    """
    Initialize the SecureDocumentHandler with the key read from the file.
    """
    try:
        return SecureDocumentHandler()
    except Exception as e:
        print(f"Failed to initialize SecureDocumentHandler: {e}")
        sys.exit(1)


def execute_protect(
    handler: SecureDocumentHandler, input_file: str, key_file: str, output_file: str
):
    """
    Handles the 'protect' command logic.
    """
    try:
        handler.protect(input_file, key_file, output_file)
        print(f"Document successfully protected. Saved to: {output_file}")
    except Exception as e:
        print(f"Failed to protect document: {e}")


def execute_check_single(
    handler: SecureDocumentHandler, input_file: str, key_file: str
):
    """
    Handles the 'check' command logic for a single file.
    """
    try:
        is_protected = handler.checkSingleFile(input_file, key_file)
        print(
            f"Document integrity status: {'Verified' if is_protected else 'No integrity'}"
        )
    except Exception as e:
        print(f"Failed to check document's integrity status: {e}")


def execute_check_missing(
    handler: SecureDocumentHandler, input_files: List[str], digest_of_macs: str
):
    """
    Handles the 'check' command logic for multiple files with MAC digest.
    """
    try:
        # Assuming the handler has a method to check multiple files with a MAC digest
        verification_results = handler.checkMissingFiles(input_files, digest_of_macs)

        # Print results for each file
        for file, status in verification_results.items():
            print(f"{file}: {'Protected' if status else 'Unprotected'}")

    except Exception as e:
        print(f"Failed to check document status: {e}")


def execute_unprotect(
    handler: SecureDocumentHandler, input_file: str, key_file: str, output_file: str
):
    """
    Handles the 'unprotect' command logic.
    """
    try:
        handler.unprotect(input_file, key_file, output_file)
        print(f"Document successfully decrypted. Saved to: {output_file}")
    except Exception as e:
        print(f"Failed to decrypt document: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Secure Document Encryption Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Help command
    subparsers.add_parser("help", help="Display general tool information")

    # Protect command
    protect_parser = subparsers.add_parser("protect", help="Protect a document")
    protect_parser.add_argument("input_file", help="Input file to protect")
    protect_parser.add_argument(
        "key_file", help="Path to the key file used to protect the file"
    )
    protect_parser.add_argument("output_file", help="Output encrypted file")

    # Check command with two separate parsers

    # Check single file parser
    check_single_parser = subparsers.add_parser(
        "check-single", help="Check integrity of a single file"
    )
    check_single_parser.add_argument("input_file", help="Path to the file to check")
    check_single_parser.add_argument("key_file", help="Path to the key file")

    # Check multiple files parser
    check_multiple_parser = subparsers.add_parser(
        "check-missing", help="Check if there are missing files for the user"
    )
    check_multiple_parser.add_argument(
        "directory", help="Directory of all files to check"
    )
    check_multiple_parser.add_argument(
        "digest_of_hmacs", help="Digest of HMACs of all files"
    )

    # Unprotect command
    unprotect_parser = subparsers.add_parser("unprotect", help="Unprotect a document")
    unprotect_parser.add_argument("input_file", help="Input encrypted file")
    unprotect_parser.add_argument(
        "key_file", help="Path to the key file used to decrypt the file"
    )
    unprotect_parser.add_argument("output_file", help="Output decrypted file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Initialize handler
    handler = initialize_handler()

    # Execute command logic
    if args.command == "protect":
        execute_protect(handler, args.input_file, args.key_file, args.output_file)
    elif args.command == "check-single":
        execute_check_single(handler, args.input_file, args.key_file)
    elif args.command == "check-missing":
        execute_check_missing(handler, args.input_files, args.digest_of_macs)
    elif args.command == "unprotect":
        execute_unprotect(handler, args.input_file, args.key_file, args.output_file)
    elif args.command == "help":
        parser.print_help()
    else:
        print("Unknown command.")
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
