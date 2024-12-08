#!/bin/bash
# scripts/setup_client.sh

# Update package lists
sudo apt-get update

# Install Python and pip
sudo apt-get install -y python3 python3-pip

# Create a virtual environment
sudo apt-get install -y python3-venv
python3 -m venv /home/vagrant/venv
source /home/vagrant/venv/bin/activate

# Install testing dependencies
pip install requests pytest

# Make tests executable
chmod +x /home/vagrant/tests/test_api.py