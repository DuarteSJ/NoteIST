#!/bin/bash

# Enable IP forwarding for NAT
sudo sysctl -w net.ipv4.ip_forward=1

# Flush existing iptables rules
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD DROP

# Allow established and related connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH for management (optional, be careful with this)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# DMZ Firewall Rules
# ONLY allow incoming connections to port 5000 from any source
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

#allow ping todo: remove this
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Allow app server to connect to DB server on port 27017
sudo iptables -A OUTPUT -p tcp -d 192.168.60.20 --dport 27017 -j ACCEPT

echo "Firewall rules applied successfully"