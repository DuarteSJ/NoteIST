import argparse
import sys
import os


KEY_FILE = os.path.join(os.path.expanduser("~"), ".config", "secure_document", "key")


def generate_key() -> bytes:
    """Generates a new random 256-bit encryption key."""
    key = os.urandom(32)  # 256-bit long
    return key


def store_key(key: bytes) -> None:
    """Stores the encryption key in a file."""
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    print(f"Key stored at: {KEY_FILE}")


def load_key() -> bytes:
    """Loads the encryption key from the predefined file, or prompts the user to generate one."""
    if not os.path.exists(KEY_FILE):
        user_input = input(
            "Key file not found. Do you want to generate a new key? (yes/no): "
        ).strip().lower()
        if user_input in ["yes", "y", "Yes"]:
            key = generate_key()
            store_key(key)
            print("New encryption key generated and stored.")
            return key
        else:
            raise FileNotFoundError(
                "Key file not found. Please generate a key using the 'generate-key' command."
            )

    with open(KEY_FILE, 'rb') as f:
        return f.read()


def main() -> int:
    """Main entry point of the application."""
    parser = argparse.ArgumentParser(description="Secure Document Key Management")
    parser.add_argument(
        "command", choices=["generate-key", "load-key"], help="Manage encryption keys"
    )

    args = parser.parse_args()

    if args.command == "generate-key":
        key = generate_key()
        store_key(key)
        print("Generated new key and stored it.")
        return 0

    elif args.command == "load-key":
        try:
            key = load_key()
            print(f"Key successfully loaded: {key.hex()}")
            return 0
        except Exception as e:
            print(f"Error: {e}")
            return 1

    print("Invalid command.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
