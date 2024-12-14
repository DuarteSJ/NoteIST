import key_manager
from tui import main as tui

from secure_request_handler import SecureRequestHandler

# TODO: might want to change these paths
PRIV_KEY_FILE = "/home/.config/NoteIST/priv_key.pem"
CERTIFICATE_FILE = "/home/vagrant/certs/ca.crt"


def main():
    username = input("what is ur username?\n\t> ")
    # pull changes from server if there are any
    request_handler.pull_changes(PRIV_KEY_FILE)
    # run cli and register changes
    changes = tui()
    # user closes cli
    print("user closed cli, backing up to srver...")
    # backup to server
    request_handler.push_changes(PRIV_KEY_FILE, changes)
    print("Back up successful!...")


if __name__ == "__main__":
    main()
