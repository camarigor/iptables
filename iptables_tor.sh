#!/bin/bash

# /etc/tor/torrc = "SocksPort 0\nTransPort 9040\nDNSPort 9053\nVirtualAddrNetworkIPv4 10.192.0.0/10\nAutomapHostsOnResolve 1"
# /etc/resolv.conf = "nameserver 127.0.0.1"

# removing any existant rule
iptables -t security -F
iptables -t security -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
iptables -t nat -F
iptables -t nat -X
iptables -F
iptables -X

################# CHAINS:
# drops everything we don't accept
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

################# TABLES:
#########################
######### NAT ###########
#########################

# enabling lookup of .onion addresses
iptables -t nat -A OUTPUT -d 10.192.0.0/10 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040

# enabling DNS through the tornet
iptables -t nat -A OUTPUT -d 127.0.0.1/8 -p udp -m udp --dport 53 -j REDIRECT --to-ports 9053

# avoiding routing through tor what is local
iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN

# associating to the "tor" user of uid=43
iptables -t nat -A OUTPUT -m owner --uid-owner 43 -j RETURN

# everything else goes to the tornet
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040

#########################
######## FILTER #########
#########################

# accepting packages with ESTABLISHED status
iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

# allow incoming connections to the HTTP service [ OPTIONAL ]
#iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# accepting connection on port 443 HTTPS service [ OPTIONAL ]
# iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# accepting packages arriving to ourselves
iptables -A INPUT -i lo -j ACCEPT

# avoiding kernel leaks (source: https://lists.torproject.org/pipermail/tor-talk/2014-March/032503.html )
iptables -A OUTPUT -m state --state INVALID -j DROP

# sending packages with ESTABLISHED status
iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

# associating to the "tor" user of uid=43
iptables -A OUTPUT -m owner --uid-owner 43 -j ACCEPT

# sending packages to ourselves
iptables -A OUTPUT -d 127.0.0.1/8 -j ACCEPT

# dropping everything else
iptables -A OUTPUT -j DROP

#########################

# saving the rules to the default iptables file
iptables-save > /etc/iptables/iptables.rules

