#!/bin/bash

# Create veth pairs
sudo ip link add veth1 type veth peer name veth2
sudo ip link add veth3 type veth peer name veth4
sudo ip link add veth5 type veth peer name veth6
sudo ip link add veth7 type veth peer name veth8

# Bring up the veth interfaces
for i in {1..8}; do
    sudo ip link set veth$i up
done

# Assign IPv6 addresses to the veth interfaces
sudo ip addr add fe80::1/64 dev veth1
sudo ip addr add fe80::2/64 dev veth2
sudo ip addr add fe80::3/64 dev veth3
sudo ip addr add fe80::4/64 dev veth4
sudo ip addr add fe80::5/64 dev veth5
sudo ip addr add fe80::6/64 dev veth6
sudo ip addr add fe80::7/64 dev veth7
sudo ip addr add fe80::8/64 dev veth8

# Set MAC addresses for the veth interfaces
sudo ip link set dev veth1 address 02:01:01:01:01:01
sudo ip link set dev veth2 address 02:01:01:01:01:02
sudo ip link set dev veth3 address 02:01:01:01:01:03
sudo ip link set dev veth4 address 02:01:01:01:01:04
sudo ip link set dev veth5 address 02:01:01:01:01:05
sudo ip link set dev veth6 address 02:01:01:01:01:06
sudo ip link set dev veth7 address 02:01:01:01:01:07
sudo ip link set dev veth8 address 02:01:01:01:01:08

# Disable Router Solicitations and auto-configuration
for i in {1..8}; do
    sudo sysctl -w net.ipv6.conf.veth$i.accept_ra=0
    sudo sysctl -w net.ipv6.conf.veth$i.autoconf=0
done

# Flush existing iptables rules
sudo iptables -F
sudo iptables -X

# Block mDNS traffic using iptables
for i in {1..8}; do
    sudo iptables -A INPUT -i veth$i -p udp --dport 5353 -j DROP
    sudo iptables -A INPUT -i veth$i -p udp --sport 5353 -j DROP
    sudo iptables -A OUTPUT -o veth$i -p udp --dport 5353 -j DROP
    sudo iptables -A OUTPUT -o veth$i -p udp --sport 5353 -j DROP
done

# Add logging for all other UDP traffic
for i in {1..8}; do
    sudo iptables -A INPUT -i veth$i -p udp -j LOG --log-prefix "UDP INPUT: "
    sudo iptables -A OUTPUT -o veth$i -p udp -j LOG --log-prefix "UDP OUTPUT: "
done

# Example to block UDP traffic on port 123 (NTP)
for i in {1..8}; do
    sudo iptables -A INPUT -i veth$i -p udp --dport 123 -j DROP
    sudo iptables -A OUTPUT -o veth$i -p udp --dport 123 -j DROP
done

# Disable avahi-daemon to stop mDNS traffic
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon

# Disable IPv6 multicast and autoconfiguration
for i in {1..8}; do
    sudo sysctl -w net.ipv6.conf.veth$i.accept_ra=0
    sudo sysctl -w net.ipv6.conf.veth$i.autoconf=0
    sudo sysctl -w net.ipv6.conf.veth$i.disable_ipv6=1
done

# Use nmcli to disable mDNS on NetworkManager-managed interfaces
for iface in {veth1,veth2,veth3,veth4,veth5,veth6,veth7,veth8}; do
    sudo nmcli dev set $iface managed no
    sudo nmcli connection modify $iface ipv6.dns-search ""
    sudo nmcli connection modify $iface ipv4.dns-search ""
done

sudo systemctl restart NetworkManager

# Verify iptables rules
sudo iptables -L -v -n

