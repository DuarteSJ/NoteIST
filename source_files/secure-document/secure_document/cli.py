import argparse
import sys
import os
from secure_document.crypto_utils import SecureDocumentHandler

KEY_FILE = os.path.join(os.path.expanduser("~"), ".config", "secure_document", "key")

def generate_key() -> bytes:
    key = os.urandom(32)  # 256-bit long
    return key

def store_key(key: bytes) -> None:
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

def load_key() -> bytes:
    if not os.path.exists(KEY_FILE):
        user_input = input("Key file not found. Do you want to generate a new key? (yes/no): ").strip().lower()
        if user_input in ['yes', 'y', 'Yes']:
            key = generate_key()
            store_key(key)
            print("New encryption key generated and stored.")
            return key
        else:
            raise FileNotFoundError("Key file not found. Please generate a key using the 'generate-key' command.")
    with open(KEY_FILE, 'rb') as f:
        return f.read()

def main() -> int:
    parser = argparse.ArgumentParser(description="Secure Document Encryption Tool")

    # Subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Generate key command
    subparsers.add_parser('generate-key', help='Generate a new encryption key')

    # Protect command
    protect_parser = subparsers.add_parser('protect', help='Protect a document')
    protect_parser.add_argument('input_file', help='Input JSON file to protect')
    protect_parser.add_argument('output_file', help='Output encrypted file')

    # Check command
    subparsers.add_parser('check', help='Check if a document is protected')
    
    # Unprotect command
    unprotect_parser = subparsers.add_parser('unprotect', help='Unprotect a document')
    unprotect_parser.add_argument('input_file', help='Input encrypted file')
    unprotect_parser.add_argument('output_file', help='Output decrypted file')

    # Parse arguments
    args = parser.parse_args()

    # Create document handler
    try:
        handler = SecureDocumentHandler()
    except Exception as e:
        print(f"Failed to initialize SecureDocumentHandler: {e}")
        return 1

    try:
        # If no command is provided, show help
        if not args.command:
            parser.print_help()
            return 0

        if args.command == 'generate-key':
            key = generate_key()
            store_key(key)
            print("Encryption key generated and securely stored.")

        elif args.command == 'protect':
            key = load_key()
            handler.protect(args.input_file, key, args.output_file)
            print(f"Document successfully protected. Saved to {args.output_file}")

        elif args.command == 'check':
            is_protected = handler.check(args.input_file)
            print(f"Document protection status: {'Protected' if is_protected else 'Unprotected'}")

        elif args.command == 'unprotect':
            key = load_key()
            handler.unprotect(args.input_file, key, args.output_file)
            print(f"Document successfully decrypted. Saved to {args.output_file}")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
