import argparse
import sys
from secure_document.crypto_utils import SecureDocumentHandler

def main():
    parser = argparse.ArgumentParser(description="Secure Document Encryption Tool")
    
    # Subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Protect command
    protect_parser = subparsers.add_parser('protect', help='Protect a document')
    protect_parser.add_argument('input_file', help='Input JSON file to protect')
    protect_parser.add_argument('password', help='Password for encryption')
    protect_parser.add_argument('output_file', help='Output encrypted file')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check if a document is protected')
    check_parser.add_argument('input_file', help='Input file to check')
    
    # Unprotect command
    unprotect_parser = subparsers.add_parser('unprotect', help='Unprotect a document')
    unprotect_parser.add_argument('input_file', help='Input encrypted file')
    unprotect_parser.add_argument('password', help='Password for decryption')
    unprotect_parser.add_argument('output_file', help='Output decrypted file')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create document handler
    handler = SecureDocumentHandler()
    
    try:
        # If no command is provided, show help
        if not args.command:
            parser.print_help()
            return 0
        
        if args.command == 'protect':
            result = handler.protect(args.input_file, args.password, args.output_file)
            print(f"Document successfully protected. Saved to {args.output_file}")
        
        elif args.command == 'check':
            is_protected = handler.check(args.input_file)
            print(f"Document protection status: {'Protected' if is_protected else 'Unprotected'}")
        
        elif args.command == 'unprotect':
            result = handler.unprotect(args.input_file, args.password, args.output_file)
            print(f"Document successfully decrypted. Saved to {args.output_file}")
        
        return 0
    
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())