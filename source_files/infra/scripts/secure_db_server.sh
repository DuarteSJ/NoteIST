#!/bin/bash

# Firewall rules for DB server
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD DROP

# Allow established and related connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH connections
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ONLY allow MongoDB connections from the app server
sudo iptables -A INPUT -p tcp -s 192.168.56.14 --dport 27017 -j ACCEPT

#allow pings
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT


#remove vagrants NAT gateway (this nat is common to all VMs)
sudo ip route del 10.0.2.2

#add app server as default gateway
sudo ip route add default via 192.168.56.14

# Log and drop other incoming packets
sudo iptables -A INPUT -j LOG --log-prefix "DB-SERVER-DROPPED: "
sudo iptables -A INPUT -j DROP

echo "Firewall rules applied successfully"