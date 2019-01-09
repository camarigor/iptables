#!/bin/sh

# Script is for stoping Portscan and smurf attack

### first flush all the iptables Rules
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

# drops everything we don't accept
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A OUTPUT -j ACCEPT
# INPUT iptables Rules

# Accept loopback input
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -d 127.0.0.0/8 -j DROP

# Accept loopback output
iptables -A OUTPUT -o lo -j ACCEPT 
iptables -A OUTPUT -d 127.0.0.0/8 -j DROP

# Allow Established and Related Incoming Connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#Allow Established Outgoing Connections
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Drop Invalid Packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# DROP spoofing packets
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -d 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -d 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -d 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.0.2.0/24 -j DROP
iptables -A INPUT -d 192.0.2.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/3 -j DROP
iptables -A INPUT -d 224.0.0.0/3 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -s 239.255.255.0/24 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -s 255.255.255.255 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# Drop ICMP.
iptables -A INPUT -p icmp -j DROP

# Block or Allow ICMP Ping Request.
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Drop fragmented icmp. Normally they aren't needed and blocking fragments will mitigate UDP fragmentation flood. 
iptables -A INPUT --fragment -p icmp -j DROP

# Destination-unreachable -- can be maliciously injected.
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j DROP

# Router Advertisement and router solicitation -- can be used to facilitate MITM attacks etc.
iptables -A INPUT -p icmp --icmp-type router-advertisement -j DROP
iptables -A INPUT -p icmp --icmp-type router-solicitation -j DROP

# Source Quench -- can be maliciously sent to make your server un-responsible.
iptables -A INPUT -p icmp --icmp-type source-quench -j DROP

# Invalid outgiong icmp packets, need/should to be dropped to prevent a possible exploit.
iptables -A OUTPUT -p icmp -m conntrack --ctstate INVALID -j DROP

# for SMURF attack protection
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP

# Syn-flood protection
iptables -N syn_flood
iptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -j RETURN
iptables -A syn_flood -j DROP

# Allow All Incoming SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow Incoming SSH from Specific IP address or subnet
#iptables -A INPUT -p tcp -s 192.168.240.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow Incoming Rsync from Specific IP Address or Subnet
#iptables -A INPUT -p tcp -s 192.168.240.0/24 --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 873 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 873 -m conntrack --ctstate ESTABLISHED -j ACCEPT

#Allow Outgoing SSH
#iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow All Incoming HTTP and HTTPS
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow All Incoming SMTP
#iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow All Incoming IMAP
#iptables -A INPUT -p tcp --dport 143 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 143 -m conntrack --ctstate ESTABLISHED -j ACCEPT


# Allow All Incoming IMAPS
#iptables -A INPUT -p tcp --dport 993 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 993 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow All Incoming POP3
#iptables -A INPUT -p tcp --dport 110 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 110 -m conntrack --ctstate ESTABLISHED -j ACCEPT

#Allow All Incoming POP3S
#iptables -A INPUT -p tcp --dport 995 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 995 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow All Incoming POP3
#iptables -A INPUT -p tcp --dport 587 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -p tcp --sport 587 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Protection against port scanning
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j RETURN
iptables -A port-scanning -j DROP

# Mitigating SYN Floods With SYNPROXY
iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j DROP

# Block New Packets That Are Not SYN
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Force Fragments packets check
iptables -A INPUT -f -j DROP

# XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Drop all NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Block Packets With Bogus TCP Flags
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

iptables-save > /etc/iptables.rules
