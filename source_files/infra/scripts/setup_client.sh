#!/bin/bash

# Update system and install necessary packages
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev build-essential

# Install necessary Python libraries for secure communication
pip3 install -r ../client/notist_client/requirements.txt



# Set up the client to run (e.g., initiate the client script)
# Example: Running the client
# python3 tls_socket_client.py
