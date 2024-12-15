#!/bin/bash

#wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-archive-keyring.gpg
#echo "deb [signed-by=/usr/share/keyrings/mongodb-archive-keyring.gpg] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list

##sudo apt update
#sudo apt install -y mongodb-mongosh


# MongoDB Server Details
MONGO_HOST="192.168.56.17"
MONGO_PORT="27017"
MONGO_USER="server"
CLIENT_CERT="/home/vagrant/certs/server/server.pem"
CA_CERT="/home/vagrant/certs/ca.crt"

# Connection Test Function
test_mongodb_connection() {
    echo "Testing MongoDB Connection..."
    
    # Network Connectivity
    echo "Checking network connectivity..."
    if ! ping -c 4 $MONGO_HOST; then
        echo "Network connectivity failed!"
        return 1
    fi
    
    
    # TLS and Authentication Test
    echo "Testing MongoDB connection with TLS..."
    mongosh \
        --host $MONGO_HOST \
        --port $MONGO_PORT \
        --tls \
        --tlsCertificateKeyFile $CLIENT_CERT \
        --tlsCAFile $CA_CERT \
        --username $MONGO_USER \
        --eval "db.runCommand({ping: 1})"
    
    if [ $? -eq 0 ]; then
        echo "MongoDB Connection Test Successful!"
        return 0
    else
        echo "MongoDB Connection Test Failed!"
        return 1
    fi
}

# Run the test
test_mongodb_connection