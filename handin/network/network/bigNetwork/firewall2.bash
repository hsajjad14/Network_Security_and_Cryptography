#!/bin/bash
IPT="/sbin/iptables"

# Flush all tables
$IPT -F # filter is the default table
$IPT -F -t nat
$IPT -F -t mangle

# State rules to make life easier
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # (a) The only publicly routable ip address in the organization is 93.184.216.34,
    #     this means that all of the hosts on the 192.168.*.* network share the one
    #     public IP 93.184.216.34

# First add default blacklist to both firewalls
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# for firewall2 default out to firewall1:
route add default gw 192.168.10.10

    # (b) As far as the internet is concerned, the organization is running a web server
    #     at IP 93.184.216.34. All http traffic received at Firewall1 is forwarded to
    #     192.168.10.100.

# NO RULE NEEDED HERE                                                                         #(b)

    # (c) As far as the internet is concerned, the organization is running a mail server
    #     at IP 93.184.216.34. All smtp traffic received at Firewall1 is forwarded to
    #     192.168.10.25.

# NO RULE NEEDED HERE                                                                         #(c)

    # (d) Firewall1 allows ssh in, but only from the admins office machine
    #     192.168.11.19, and from the admins home machine 128.2.2.17.

# Allow forwarding through firewall2 from admin's office machine to firewall1
$IPT -A FORWARD -p tcp -s 192.168.11.19 -d 192.168.10.10 --dport 22 -j ACCEPT
$IPT -A FORWARD -p tcp -s 192.168.11.19 -d 93.184.216.34 --dport 22 -j ACCEPT

    # (e) The ceo can, from their home machine (34.14.10.18) rdp into their office
    #     desktop (192.168.11.18) using port 3389 on Firewall1.

# Allow forwarding through firewall2 from ceo's home machine to their office
$IPT -A FORWARD -p tcp -s 34.14.10.18 -d 192.168.11.18 --dport 3389 -j ACCEPT

    # (f) For convenience, the admin can ssh into their office machine via...
    #     ssh -p 2222 93.184.216.36 # only works from 128.2.2.17

# allow admin to ssh into their machine from their home via port 2222
$IPT -A FORWARD -p tcp -s 128.2.2.17 -d 192.168.11.19 --dport 22 -j ACCEPT

    # Similarly, the ceo can ssh into their ceo desktop via...
    # ssh -p 2222 93.184.216.36 # only works from 34.14.10.18

# allow ceo to ssh into their machine from their home via port 2222
$IPT -A FORWARD -p tcp -s 34.14.10.18 -d 192.168.11.18 --dport 22 -j ACCEPT

    # (g) The mail server at 192.168.10.25 is accessible from the LAN.

# Allow anyone in the organization to get into the mailserver (port 22)
$IPT -A FORWARD -d 192.168.10.25 -j ACCEPT
# $IPT -A FORWARD -p tcp -d 192.168.10.25 --dport 22 -j ACCEPT

    # (h) The web server (192.168.10.100) is running some web applications, it is accessible
    #     from the LAN.

# Allow anyone in the organization to access the webserver applications (port 80)
$IPT -A FORWARD -p tcp -d 192.168.10.100 --dport 80 -j ACCEPT

    # (i) To get its work done, the web server needs to connect to the postgresql db server at 192.168.11.100
    #     No other connection into the db server are allowed.

# Allow the webserver to connect to the postgresql db server at 192.168.11.100 on port 5432 (postgresql port)
$IPT -A FORWARD -p tcp -s 192.168.10.100 -d 192.168.11.100 --dport 5432 -j ACCEPT

    # (j) All LAN machines can access the internet, but are restricted to web (http and https) traffic only.
    #     So, for example, none of the LAN machines can ssh out past firewall1.

# All machines can connect to the isp on port 80 and port 443 (http and https ports), ISP is 93.184.216.1
$IPT -A FORWARD -p tcp -d 93.184.216.1 --dport 80 -j ACCEPT
$IPT -A FORWARD -p tcp -d 93.184.216.1 --dport 443 -j ACCEPT

    # (k) No other access to any hosts is allowed.

# Assuming hosts = organization machines, we have a default drop policy (blacklist everything) at the top, or if we list it again:
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

    # (l) 17.17.17.17 has been found to be attacking the organizations systems. Access
    #     to all services from this IP is denied.

# This won't ever get run, its just for precaution
# -I places this at the top, so it gets dropped right away.
$IPT -I INPUT -s 17.17.17.17 -j DROP
$IPT -I FORWARD -s 17.17.17.17 -j DROP

    # (m) As a precaution, in case 17.17.17.17 has compromised one of our systems,
    #     no outgoing connections to 17.17.17.17 are allowed.

# drop any packets going to 17.17.17.17
# -I places this at the top, so it gets dropped right away.
$IPT -I OUTPUT -d 17.17.17.17 -j DROP
$IPT -I FORWARD -d 17.17.17.17 -j DROP
