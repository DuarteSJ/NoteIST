#!/bin/bash
# scripts/setup_app.sh

# Update package lists
sudo apt-get update

# Install Python and pip
sudo apt-get install -y python3 python3-pip

# Create a virtual environment (optional but recommended)
sudo apt-get install -y python3-venv
python3 -m venv /home/vagrant/venv
source /home/vagrant/venv/bin/activate

# Install project dependencies
pip install fastapi uvicorn pymongo pydantic

# Set up systemd service for the application
cat << EOF | sudo tee /etc/systemd/system/team-app.service
[Unit]
Description=Team Application Server
After=network.target

[Service]
User=vagrant
WorkingDirectory=/home/vagrant/app
ExecStart=/home/vagrant/venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl enable team-app
sudo systemctl start team-app