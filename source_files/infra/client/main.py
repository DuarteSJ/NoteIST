import key_manager
from cli import main as cli

from secure_document import SecureDocumentHandler
from secure_request_handler import SecureRequestHandler

if __name__ == "__main__":
    request_handler = SecureRequestHandler(
        host="192.168.56.14", port=5000, cert_path="/home/vagrant/setup/certs/ca.crt"
    )
    # pull changes from server if there are any
    request_handler.pull_changes()
    # run cli
    cli()
    # user closes cli
    print("user closed cli, backing up to srver...")
    # backup to server
    request_handler.push_changes()
    print("Back up successful!...")
