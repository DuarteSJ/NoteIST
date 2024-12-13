import key_manager
from cli import main as cli

from secure_document import SecureDocumentHandler
from secure_request_handler import SecureRequestHandler

# TODO: might want to change these paths
USERNAME_FILE = "/home/.config/NoteIST/username"
PRIV_KEY_FILE = "/home/.config/NoteIST/priv_key.pem"

if __name__ == "__main__":
    request_handler = SecureRequestHandler(
        host="192.168.56.14", port=5000, cert_path="/home/vagrant/setup/certs/ca.crt"
    )
    # pull changes from server if there are any
    request_handler.pull_changes(PRIV_KEY_FILE)
    # run cli
    cli()
    # user closes cli
    print("user closed cli, backing up to srver...")
    # backup to server
    request_handler.push_changes(PRIV_KEY_FILE)
    print("Back up successful!...")
