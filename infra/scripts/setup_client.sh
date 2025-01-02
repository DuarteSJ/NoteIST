#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Update system and install necessary packages
echo "Updating system and installing dependencies..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-dev build-essential

pip install packaging==22.0

# Install necessary Python libraries for secure communication
REQUIREMENTS_FILE="/home/vagrant/client/notist_client/requirements.txt"

if [ -f "$REQUIREMENTS_FILE" ]; then
    echo "Installing Python dependencies..."
    pip install -r "$REQUIREMENTS_FILE"
else
    echo "Error: Requirements file not found at $REQUIREMENTS_FILE"
    exit 1
fi

# Create an alias for easier client execution
ALIAS_COMMAND="alias notist-client='cd /home/vagrant/client/notist_client/src && python3 main.py'"

if ! grep -q "alias notist-client" ~/.bashrc; then
    echo "Adding alias to ~/.bashrc..."
    echo "$ALIAS_COMMAND" >> ~/.bashrc
else
    echo "Alias already exists in ~/.bashrc."
fi

# Reload .bashrc to apply the alias immediately
echo "Reloading ~/.bashrc..."
source ~/.bashrc

