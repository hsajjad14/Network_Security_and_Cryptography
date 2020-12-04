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

# First add default blacklist to firewall1
$IPT -P INPUT DROP
$IPT -P OUPUT DROP
$IPT -P FORWARD DROP

# use postrouting to hide our entire network behind 93.184.216.34
$IPT -t nat -A POSTROUTING -o eth0 -j SNAT --to 93.184.216.34

    # (b) As far as the internet is concerned, the organization is running a web server
    #     at IP 93.184.216.34. All http traffic received at Firewall1 is forwarded to
    #     192.168.10.100.

# allow forwarding through firewall1 to the webserver (and back, this is taken care of in state rules at the top)
$IPT -A FORWARD -p tcp -d 192.168.10.100 --dport 80 -j ACCEPT

# redirect traffic from port 80 on ip 93.184.216.34 to our webserver 192.168.10.100
$IPT -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to 192.168.10.100

    # (c) As far as the internet is concerned, the organization is running a mail server
    #     at IP 93.184.216.34. All smtp traffic received at Firewall1 is forwarded to
    #     192.168.10.25.

# allow forwarding through firewall1 to the mailserver (and back, this is taken care of in state rules at the top)
# ports used for mail server are 25 and and 587, and since they are both listening on Ubuntu804_owasp we will allow forwarding through both
$IPT -A FORWARD -p tcp -d 192.168.10.25 --dport 25 -j ACCEPT
$IPT -A FORWARD -p tcp -d 192.168.10.25 --dport 587 -j ACCEPT

# redirect traffic from port 25 and 587 on ip 93.184.216.34 to our mailserver 192.168.10.25
$IPT -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j DNAT --to 192.168.10.25
$IPT -t nat -A PREROUTING -i eth0 -p tcp --dport 587 -j DNAT --to 192.168.10.25

    # (d) Firewall1 allows ssh in, but only from the admins office machine
    #     192.168.11.19, and from the admins home machine 128.2.2.17.

# allow admin's home machine to be able to ssh into firewall1 (firewall1 can reply b/c of the state rules)
$IPT -A INPUT -p tcp -s 128.2.2.17 --dport 22 -j ACCEPT

# allow admins office machine to be able to ssh into firewall1
$IPT -A INPUT -p tcp -s 192.168.11.19 --dport 22 -j ACCEPT

    # (e) The ceo can, from their home machine (34.14.10.18) rdp into their office
    #     desktop (192.168.11.18) using port 3389 on Firewall1.

# redirect traffic from port 3389 on ip 93.184.216.34 coming from ceo's home machine to ceo's office desktop
$IPT -t nat -A PREROUTING -i eth0 -p tcp -s 34.14.10.18 --dport 3389 -j DNAT --to 192.168.11.18

# allow forwarding of rdp from ceo's home machine through firewall1 to ceo's office desktop
$IPT -A FORWARD -p tcp -s 34.14.10.18 -d 192.168.11.18 --dport 3389 -j ACCEPT

    # (f) For convenience, the admin can ssh into their office machine via...
    #     ssh -p 2222 93.184.216.36 # only works from 128.2.2.17

# redirect traffic from port 2222 coming from 128.2.2.17 to admin's office machine (192.168.11.19)
$IPT -t nat -A PREROUTING -i eth0 -p tcp -s 128.2.2.17 --dport 2222 -j DNAT --to 192.168.11.19:22

# allow admin to ssh into their machine from their home via port 2222
$IPT -A FORWARD -p tcp -s 128.2.2.17 -d 192.168.11.19 --dport 22 -j ACCEPT

    # Similarly, the ceo can ssh into their ceo desktop via...
    # ssh -p 2222 93.184.216.36 # only works from 34.14.10.18

# redirect traffic from port 2222 coming from 34.14.10.18 to ceo's office machine
$IPT -t nat -A PREROUTING -i eth0 -p tcp -s 34.14.10.18 --dport 2222 -j DNAT --to 192.168.11.18:22

# allow ceo to ssh into their machine from their home via port 2222
$IPT -A FORWARD -p tcp -s 34.14.10.18 -d 192.168.11.18 --dport 22 -j ACCEPT

    # (g) The mail server at 192.168.10.25 is accessible from the LAN.

# NO RULE NEEDED HERE                                                                         #(g)

    # (h) The web server (192.168.10.100) is running some web applications, it is accessible
    #     from the LAN.

# NO RULE NEEDED HERE                                                                         #(h)

    # (i) To get its work done, the web server needs to connect to the postgresql db server at 192.168.11.100
    #     No other connection into the db server are allowed.

# NO RULE NEEDED HERE                                                                         #(i)

    # (j) All LAN machines can access the internet, but are restricted to web (http and https) traffic only.
    #     So, for example, none of the LAN machines can ssh out past firewall1.

# All machines can connect to the isp on port 80 and port 443 (http and https ports), ISP is 93.184.216.1
$IPT -A FORWARD -p tcp -d 93.184.216.1 --dport 80 -j ACCEPT
$IPT -A FORWARD -p tcp -d 93.184.216.1 --dport 443 -j ACCEPT

    # (k) No other access to any hosts is allowed.

# NO RULE NEEDED HERE                                                                         #(k)

    # (l) 17.17.17.17 has been found to be attacking the organizations systems. Access
    #     to all services from this IP is denied.

# drop any packets coming from 17.17.17.17, either through or to firewall1
$IPT -A INPUT -s 17.17.17.17 -j DROP
$IPT -A FORWARD -s 17.17.17.17 -j DROP

    # (m) As a precaution, in case 17.17.17.17 has compromised one of our systems,
    #     no outgoing connections to 17.17.17.17 are allowed.

# drop any packets going to 17.17.17.17
$IPT -A OUTPUT -s 17.17.17.17 -j DROP
