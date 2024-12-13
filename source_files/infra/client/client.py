import socket
import ssl
import json

# Test data
test_request = {
    "operation": "create",
    "document": {"name": "Test Document", "content": "This is a test document."},
}


def test_secure_server(host, port, cert_path):
    try:
        # Create a secure client socket
        context = ssl.create_default_context()

        # Load CA certificate to verify the server's certificate
        context.load_verify_locations(cafile=cert_path)  # CA cert to verify server

        # This is for server authentication only, not mutual TLS
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED  # We don't need client certificate

        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                print(f"Connected to server at {host}:{port}")

                # Send test request
                secure_sock.send(json.dumps(test_request).encode("utf-8"))

                # Receive and print response
                response = secure_sock.recv(4096)
                print(f"Server response: {response.decode('utf-8')}")
    except Exception as e:
        print(f"Test client error: {e}")


if __name__ == "__main__":
    test_secure_server("192.168.56.14", 5000, "/home/vagrant/setup/certs/ca.crt")
