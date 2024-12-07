import argparse
import sys
from secure_document.crypto_utils import SecureDocumentHandler


def initialize_handler(key: str) -> SecureDocumentHandler:
    """
    Initialize the SecureDocumentHandler with the provided key.
    """
    try:
        return SecureDocumentHandler(key)
    except Exception as e:
        print(f"Failed to initialize SecureDocumentHandler: {e}")
        sys.exit(1)


def execute_protect(handler: SecureDocumentHandler, input_file: str, output_file: str):
    """
    Handles the 'protect' command logic.
    """
    try:
        handler.protect(input_file, output_file)
        print(f"Document successfully protected. Saved to: {output_file}")
    except Exception as e:
        print(f"Failed to protect document: {e}")


def execute_check(handler: SecureDocumentHandler, input_file: str):
    """
    Handles the 'check' command logic.
    """
    try:
        is_protected = handler.check(input_file)
        print(f"Document protection status: {'Protected' if is_protected else 'Unprotected'}")
    except Exception as e:
        print(f"Failed to check document status: {e}")


def execute_unprotect(handler: SecureDocumentHandler, input_file: str, output_file: str):
    """
    Handles the 'unprotect' command logic.
    """
    try:
        handler.unprotect(input_file, output_file)
        print(f"Document successfully decrypted. Saved to: {output_file}")
    except Exception as e:
        print(f"Failed to decrypt document: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Secure Document Encryption Tool")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Protect command
    protect_parser = subparsers.add_parser('protect', help='Protect a document')
    protect_parser.add_argument('input_file', help='Input file to protect')
    protect_parser.add_argument('key', help='Key used to protect the file')
    protect_parser.add_argument('output_file', help='Output encrypted file')

    # Check command
    check_parser = subparsers.add_parser('check', help='Check if a document is protected')
    check_parser.add_argument('input_file', help='Input file to check')
    check_parser.add_argument('key', help='Key used to check the file')

    # Unprotect command
    unprotect_parser = subparsers.add_parser('unprotect', help='Unprotect a document')
    unprotect_parser.add_argument('input_file', help='Input encrypted file')
    unprotect_parser.add_argument('key', help='Key used to decrypt the file')
    unprotect_parser.add_argument('output_file', help='Output decrypted file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    handler = initialize_handler(args.key)

    # Execute command logic
    if args.command == 'protect':
        execute_protect(handler, args.input_file, args.output_file)
    elif args.command == 'check':
        execute_check(handler, args.input_file)
    elif args.command == 'unprotect':
        execute_unprotect(handler, args.input_file, args.output_file)
    else:
        print("Unknown command.")
        parser.print_help()
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
