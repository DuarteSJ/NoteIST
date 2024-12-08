#!/bin/bash
set -e # Exit on error

# Update package lists and install required utilities
sudo apt-get update -y
sudo apt-get install -y wget gnupg

# Import MongoDB public GPG key
wget -qO- https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-org-archive-keyring.gpg

# Add MongoDB repository for Ubuntu 20.04 (focal)
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mongodb-org-archive-keyring.gpg] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Update package lists again
sudo apt-get update -y

# Install MongoDB
sudo apt-get install -y mongodb-org

# Configure MongoDB for remote access
if [ -f /etc/mongod.conf ]; then
    sudo sed -i 's/bindIp: 127.0.0.1/bindIp: 0.0.0.0/' /etc/mongod.conf
else
    echo "Error: MongoDB configuration file not found!"
    exit 1
fi

# Enable and start MongoDB
sudo systemctl enable mongod
sudo systemctl start mongod

# Wait for MongoDB to start
sleep 5

# Create initial database and user
mongosh <<EOF
use teamdb
db.createUser({
    user: "teamuser",
    pwd: "teampassword",
    roles: [
        { role: "readWrite", db: "teamdb" }
    ]
})
EOF

echo "MongoDB setup completed successfully."