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

# Start and enable MongoDB service
sudo systemctl enable mongod
sudo systemctl start mongod

# Wait for MongoDB to start
sleep 5

# Create initial database and user
mongosh <<EOF
use test
db.createUser({
    user: "admin",
    pwd: "admin",
    roles: [
        { role: "readWrite", db: "test" }
    ]
})
EOF

echo "MongoDB setup completed successfully."
