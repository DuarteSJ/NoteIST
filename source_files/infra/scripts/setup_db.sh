#!/bin/bash
set -e

# go to cert folder 
cd /home/vagrant/


echo "MongoDB TLS certificate generation complete ?."


# Update and Install MongoDB (previous steps remain the same)
apt-get update -y
apt-get install -y wget gnupg openssl

# Import MongoDB GPG key
wget -qO- https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-org-archive-keyring.gpg

# Add MongoDB repository
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mongodb-org-archive-keyring.gpg] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Update and install MongoDB
apt-get update -y
apt-get install -y mongodb-org

# Generate a strong random password for admin user
ADMIN_PASSWORD=$(openssl rand -base64 32)


# mv the mongod.cong file to /etc/mongod.conf

cp /home/vagrant/mongo/mongo.conf /etc/mongod.conf

# Ensure correct ownership and permissions
chown mongodb:mongodb /etc/mongod.conf
chmod 660 /etc/mongod.conf

# Start and enable MongoDB service
systemctl enable mongod
systemctl start mongod

# Wait for MongoDB to start
sleep 5

# Create initial admin user
mongosh --tls \
    --host 192.168.56.17 \
    --tlsCertificateKeyFile /home/vagrant/certs/mongodb/mongodb-server.pem \
    --tlsCAFile /home/vagrant/certs/ca.crt <<EOF
use admin
db.createUser({
    user: "admin",
    pwd: "$ADMIN_PASSWORD",
    roles: [
        { role: "userAdminAnyDatabase", db: "admin" },
        { role: "readWriteAnyDatabase", db: "admin" }
    ]
})
EOF


#create a user for the app
mongosh --tls \
    --host 192.168.56.17 \
    --tlsCertificateKeyFile /home/vagrant/certs/mongodb/mongodb-server.pem \
    --tlsCAFile /home/vagrant/certs/ca.crt <<EOF
use secure_document_db
db.createUser({
    user: "admin",
    pwd: "admin",
    roles: [
        { role: "readWrite", db: "secure_document_db" }
    ]
})                                   
EOF


# Securely store the password
echo "$ADMIN_PASSWORD" | sudo tee /root/.mongodb_admin_password > /dev/null
chmod 600 /root/.mongodb_admin_password

echo "Mutual TLS MongoDB setup completed successfully."
echo "Admin password has been saved to /root/.mongodb_admin_password"
echo "Client certificate located at: /etc/mongodb/ssl/mongodb-client.pem"


#enable authorization in /etc/mongod.conf
