#!/bin/bash

# Update system and install necessary packages
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev build-essential

# Install necessary Python libraries for secure communication
pip install -r /home/vagrant/client/notist_client/requirements.txt
alias notist-client="cd client/notist_client/src; python3 main.py"


# Set up the client to run (e.g., initiate the client script)
# Example: Running the client
# python3 tls_socket_client.py
