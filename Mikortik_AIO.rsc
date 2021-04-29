############################################
###   Mikrotik Configuration               #
############################################

# Change Mikrotik Identity
:global mikrotikName "MikrotikName"

#User Configuration
#Add another admin user
:global newMikrotikUser "Giuseppe"


#Lan Configuration
:global lanIpGateway "192.168.1.1"
:global lanIpDhcpRange "192.168.1.100-192.168.1.200"
:global lanIpDns "192.168.1.1"
:global lanNetworkAddress "192.168.1.0"
:global lanNetworkBits "24"
:global globalDNS1 "8.8.8.8"
:global globalDNS2 "8.8.4.4"

#Whitelist IP (not filtered ip)
:global whiteListAddr1 "1.1.1.1"
:global whiteListAddr2 "3.3.3.3"
:global whiteListAddrComment1 "First Allowed IP"
:global whiteListAddrComment2 "Second Allowed IP"

#Clock Configuration
:global ntpAddr1 "31.14.133.122"
:global ntpAddr2 "193.183.98.38"

#Email Configuration
:global smtpAddr "mail.smtpserver.com"
:global smtpPort "587"
:global smtpUser "smtp@mail.com"
:global smtpPassword "smtp password"
:global smtpTls "yes"
:global notificationMail "fromemail@smtpserver.com"
:global backupMail "toEmail@smtpserver.com"

#Dude Configuration Snmp v3
:global configureDude "yes"
:global newMikrotikDude "Dude"
:global dudeAuthenticationProtocol "SHA1"
:global dudeEncProtocol "AES"
:global dudeSnmpCommName "DudeName"
:global dudeSnmpLocation "Location"
:global notificationMail "toEmail@smtpserver.com"

###########################

###########################
#  Don't edit after this  #
###########################

:global mikrotikAdminPassword (:put ([/tool fetch mode=https http-method=get url="https://www.passwordrandom.com/query\?command=password" as-value output=user ]->"data"))
:global newMikrotikUserPassword (:put ([/tool fetch mode=https http-method=get url="https://www.passwordrandom.com/query\?command=password" as-value output=user ]->"data"))
:global newMikrotikDudePassword (:put ([/tool fetch mode=https http-method=get url="https://www.passwordrandom.com/query\?command=password" as-value output=user ]->"data"))
:global dudeAuthenticationPassword (:put ([/tool fetch mode=https http-method=get url="https://www.passwordrandom.com/query\?command=password" as-value output=user ]->"data"))
:global dudeEncPassword (:put ([/tool fetch mode=https http-method=get url="https://www.passwordrandom.com/query\?command=password" as-value output=user ]->"data"))

/file print file=passwordfile.txt
:delay 5
/file set passwordfile.txt contents=""

:global passwordfile [/file get passwordfile.txt contents]
:set passwordfile ($passwordfile . $mikrotikName . "\n" . "AdminPassword: " . $mikrotikAdminPassword . "\n" . "Username:" . $newMikrotikUser . " Password: " . $newMikrotikUserPassword . "\n" . "Dude:" . $newMikrotikDudePassword . " DudeAuthenticationPassword:" . $dudeAuthenticationPassword . " DudeEncPassword:" . $dudeEncPassword )
/file set passwordfile.txt contents="$passwordfile"

#Configure Basic Lan 
/ip address set interface=bridge address="$lanIpGateway/$lanNetworkBits" network="$lanNetworkAddress" comment="LAN" numbers=0
/ip pool set default-dhcp ranges="$lanIpDhcpRange"
/ip pool set default-dhcp name="Pool_Lan"
/ip dhcp-server network set address="$lanNetworkAddress/$lanNetworkBits" gateway="$lanIpGateway" dns-server="$lanIpDns" numbers=0

# Set DNS upstream server
/ip dns set servers="$globalDNS1,$globalDNS2"

# Enable Email
/tool e-mail set address="$smtpAddr" port="$smtpPort" from="$backupMail" user="$smtpUser" password="$smtpPassword" start-tls="$smtpTls"

# Enable Dynamic DNS
/ip cloud set ddns-enabled=yes

# Enable NTP Client
/system ntp client set primary-ntp="$ntpAddr1"
/system ntp client set secondary-ntp="$ntpAddr2"
/system ntp client set enabled=yes

# Do more security restrictions - Disable unused service
/ip service disable api
/ip service disable api-ssl
/ip service disable ftp
/ip service disable ssh
/ip service disable www
/ip service disable www-ssl
/ip service disable telnet
/ip ssh set strong-crypto=yes
/tool romon set enabled=no
/ip firewall service-port set sip disabled=yes

# Disable touchscreen
/lcd set read-only-mode=yes

# Disable BT server
/tool bandwidth-server set enabled=no

# Protect Your Router Against IP Spoofing
/ip settings set rp-filter=strict tcp-syncookies=yes

# Some whitelist IP
/ip firewall address-list add address="$whiteListAddr1" list="Allowed" comment="$whiteListAddrComment1"
/ip firewall address-list add address="$whiteListAddr2" list="Allowed" comment="$whiteListAddrComment2"
/ip firewall address-list add address="$globalDNS1" list="DNSServer" comment="DNSServer"
/ip firewall address-list add address="$globalDNS2" list="DNSServer" comment="DNSServer"
/ip firewall address-list add address="$lanIpDns" list="DNSServer" comment="DNSServer"

# Bogus List
/ip firewall address-list 
add address=0.0.0.0/8 comment="RFC 1122 This host on this network" list=Bogons disabled=yes
add address=10.0.0.0/8 comment="RFC 1918 (Private Use IP Space)" list=Bogons disabled=yes
add address=100.64.0.0/10 comment="RFC 6598 (Shared Address Space)" list=Bogons 
add address=127.0.0.0/8 comment="RFC 1122 (Loopback)" list=Bogons
add address=169.254.0.0/16 comment="RFC 3927 (Dynamic Configuration of IPv4 Link-Local Addresses)" list=Bogons
add address=172.16.0.0/12 comment="RFC 1918 (Private Use IP Space)" list=Bogons disabled=yes
add address=192.0.0.0/24 comment="RFC 6890 (IETF Protocol Assingments)" list=Bogons
add address=192.0.2.0/24 comment="RFC 5737 (Test-Net-1)" list=Bogons
add address=192.168.0.0/16 comment="RFC 1918 (Private Use IP Space)" disabled=yes list=Bogons
add address=198.18.0.0/15 comment="RFC 2544 (Benchmarking)" list=Bogons
add address=198.51.100.0/24 comment="RFC 5737 (Test-Net-2)" list=Bogons
add address=203.0.113.0/24 comment="RFC 5737 (Test-Net-3)" list=Bogons
add address=224.0.0.0/4 comment="RFC 5771 (Multicast Addresses) – Will affect OSPF, RIP, PIM, VRRP, IS-IS, and others. Use with caution.)" disabled=yes list=Bogons
add address=240.0.0.0/4 comment="RFC 1112 (Reserved)" list=Bogons disabled=yes
add address=192.31.196.0/24 comment="RFC 7535 (AS112-v4)" list=Bogons
add address=192.52.193.0/24 comment="RFC 7450 (AMT)" list=Bogons
add address=192.88.99.0/24 comment="RFC 7526 (Deprecated (6to4 Relay Anycast))" list=Bogons
add address=192.175.48.0/24 comment="RFC 7534 (Direct Delegation AS112 Service)" list=Bogons
add address=255.255.255.255 comment="RFC 919 (Limited Broadcast)" disabled=yes list=Bogons

# Delete default firewall rule
/ip firewall filter remove [/ip firewall filter find action!=passthrough ]

# Allow ip in whitelist
/ip firewall filter add chain=input src-address-list=Allowed action=accept comment="--0-1-- Allowed IP"
/ip firewall filter add chain=forward src-address-list=Allowed action=accept comment="--0-2-- Allowed IP"
/ip firewall raw add action=accept chain=prerouting comment="--0-1-- Allowed IP" src-address-list=Allowed

# DDoS Detection and Blocking
/ip firewall filter add chain=output action=accept disabled=yes comment="--2-0-- DDoS Detection and Blocking"
/ip firewall filter add action=drop chain=input comment="--2-1-- Drop Invalid Connections from LAN" connection-state=invalid in-interface-list="LAN"
/ip firewall filter add action=drop chain=forward comment="--2-2-- Drop Invalid Connections from LAN" connection-state=invalid in-interface-list="LAN"
/ip firewall filter add action=drop chain=input comment="--2-3-- Drop Invalid Connections from WAN" connection-state=invalid in-interface-list="WAN"
/ip firewall filter add action=drop chain=forward comment="--2-4-- Drop Invalid Connections from WAN" connection-state=invalid in-interface-list="WAN"
/ip firewall filter add action=accept chain=output comment="Section Break" disabled=yes
/ip firewall filter add action=add-src-to-address-list address-list="WAN High Connection Rates" address-list-timeout=1d chain=input comment="--2-5-- Add WAN High Connections to Address List – Helps with DDoS Attacks" connection-limit=100,32 in-interface-list="WAN"
/ip firewall filter add action=add-src-to-address-list address-list="LAN High Connection Rates" address-list-timeout=1d chain=forward comment="--2-6-- Add LAN High Connections toAddress List – Helps identify compromised systems on your network" connection-limit=500,32 in-interface-list="LAN"
/ip firewall filter add chain=output action=accept disabled=yes comment="--2-0-- DDoS Detection and Blocking"
/ip firewall filter add action=accept chain=output comment="Section Break" disabled=yes

# PortScanner finding
/ip firewall raw add chain=output action=accept disabled=yes comment="--3-0-- PortScanner Blocking"
/ip firewall raw add action=jump chain=prerouting comment="--3-1-- Jump to RFC Port Scans" jump-target="RFC Port Scans" protocol=tcp
/ip firewall raw add action=jump chain=prerouting comment="--3-2-- Jump to RFC Port Scans" jump-target="RFC Port Scans" protocol=udp src-address-list="!DNSServer"
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=none-dynamic chain="RFC Port Scans" comment="--3-3-- Detect WAN TCP Port Scans" in-interface-list="WAN" protocol=tcp psd=21,3s,3,1 log=yes
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=none-dynamic chain="RFC Port Scans" comment="--3-4-- Detect WAN UDP Port Scans" in-interface-list="WAN" protocol=udp psd=21,3s,3,1 log=yes
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-5-- Detect WAN NMAP FIN Stealth scan" in-interface-list="WAN" protocol=tcp tcp-flags=fin,!syn,!rst,!psh,!ack,!urg log=yes
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-6-- Detect WAN SYN/FIN scan" in-interface-list="WAN" protocol=tcp tcp-flags=fin,syn log=yes
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-7-- Detect WAN SYN/RST scan" in-interface-list="WAN" protocol=tcp tcp-flags=syn,rst log=yes
/ip firewall raw add action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-8-- Detect WAN FIN/PSH/URG scan" in-interface-list="WAN" protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack log=yes
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-9-- Detect WAN ALL/ALL scan" in-interface-list="WAN" protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg log=yes
/ip firewall raw add action=add-src-to-address-list address-list="WAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-10-- Detect WAN NMAP NULL scan" in-interface-list="WAN" protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=none-dynamic chain="RFC Port Scans" comment="--3-11-- Detect LAN TCP Port Scans" in-interface-list="LAN" protocol=tcp psd=21,3s,3,1 log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=none-dynamic chain="RFC Port Scans" comment="--3-12-- Detect LAN UDP Port Scans" in-interface-list="LAN" protocol=udp psd=21,3s,3,1 log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-13-- Detect LAN NMAP FIN Stealth scan" in-interface-list="LAN" protocol=tcp tcp-flags=fin,!syn,!rst,!psh,!ack,!urg log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-14-- Detect LAN SYN/FIN scan" in-interface-list="LAN" protocol=tcp tcp-flags=fin,syn log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-15-- Detect LAN SYN/RST scan" in-interface-list="LAN" protocol=tcp tcp-flags=syn,rst log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-16-- Detect LAN FIN/PSH/URG scan" in-interface-list="LAN" protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-17-- Detect LAN ALL/ALL scan" in-interface-list="LAN" protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg log=yes
/ip firewall raw add action=add-src-to-address-list address-list="LAN Port Scanners" address-list-timeout=2w chain="RFC Port Scans" comment="--3-18-- Detect LAN NMAP NULL scan" in-interface-list="LAN" protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg log=yes
/ip firewall raw add action=return chain="RFC Port Scans" comment="--3-19-- Return from RFC Port Scans"
/ip firewall raw add chain=output action=accept disabled=yes comment="--3-0-- PortScanner Blocking"

# Raw Blocking Rule
/ip firewall raw add chain=output action=accept disabled=yes comment="--6-0-- Raw Blocking Rule"
/ip firewall raw add action=accept chain=output comment="Section Break" disabled=yes
/ip firewall raw add action=drop chain=prerouting comment="--6-1-- Drop all packets on Joshaven Potter’s Blacklist for SpamHaus, dshield, and malc0de" src-address-list=blacklist
/ip firewall raw add action=drop chain=prerouting comment="--6-2-- Drop all packets on Joshaven Potter’s Blacklist for SpamHaus, dshield, and malc0de" dst-address-list=blacklist
/ip firewall raw add action=drop chain=prerouting comment="--6-3-- Drop all packets on Joshaven Potter’s VOIP Blacklist" src-address-list=voip-blacklist
/ip firewall raw add action=drop chain=prerouting comment="--6-4-- Drop all packets on Joshaven Potter’s VOIP Blacklist" dst-address-list=voip-blacklist
/ip firewall raw add action=drop chain=prerouting comment="--6-5-- Drop anyone in the WAN Port Scanner List" src-address-list="WAN Port Scanners"
/ip firewall raw add action=drop chain=prerouting comment="--6-6-- Drop anyone in the WAN Port Scanner List" dst-address-list="WAN Port Scanners"
/ip firewall raw add action=drop chain=prerouting comment="--6-7-- Drop anyone in the LAN Port Scanner List" src-address-list="LAN Port Scanners" disabled=yes
/ip firewall raw add action=drop chain=prerouting comment="--6-8-- Drop anyone in the LAN Port Scanner List" dst-address-list="LAN Port Scanners" disabled=yes
/ip firewall raw add action=drop chain=prerouting comment="--6-9-- Drop anyone in the WAN High Connections List" src-address-list="WAN High Connection Rates"
/ip firewall raw add action=drop chain=prerouting comment="--6-10-- Drop anyone in the WAN High Connections List" dst-address-list="WAN High Connection Rates"
/ip firewall raw add action=drop chain=prerouting comment="--6-11-- Drop anyone in the LAN High Connections List" src-address-list="LAN High Connection Rates" disabled=yes
/ip firewall raw add action=drop chain=prerouting comment="--6-12-- Drop anyone in the LAN High Connections List" dst-address-list="LAN High Connection Rates" disabled=yes
/ip firewall raw add action=accept chain=output comment="Section Break" disabled=yes
/ip firewall raw add action=jump chain=prerouting comment="--6-13-- Jump to RFC Bogon Chain" jump-target="RFC Bogon Chain"
/ip firewall raw add action=drop chain="RFC Bogon Chain" comment="--6-14-- Drop all packets soured from Bogons" src-address-list=Bogons
/ip firewall raw add action=drop chain="RFC Bogon Chain" comment="--6-15-- Drop all packets destined to Bogons" dst-address-list=Bogons
/ip firewall raw add action=return chain="RFC Bogon Chain" comment="--6-16-- Return from RFC Bogon Chain"
/ip firewall raw add action=accept chain=output comment="Section Break" disabled=yes
/ip firewall raw add action=drop chain=prerouting comment="--6-17-- Drop packets that contain YERSINIA" content=yersinia
/ip firewall raw add action=drop chain=prerouting comment="--6-18-- Drop packets that contain KALI" content=kali
/ip firewall raw add action=accept chain=output comment="Section Break" disabled=yes
/ip firewall raw add action=jump chain=prerouting comment="--6-19-- Jump to RFC ICMP Protection Chain" jump-target="RFC ICMP Protection" protocol=icmp
/ip firewall raw add action=add-dst-to-address-list address-list="Suspected SMURF Attacks" address-list-timeout=none-dynamic chain="RFC ICMP Protection" comment="--6-20-- Detect Suspected SMURF Attacks" dst-address-type=broadcast log=yes log-prefix="FW-SMURF Attacks" protocol=icmp
/ip firewall raw add action=drop chain="RFC ICMP Protection" comment="--6-21-- Drop Suspected SMURF Attacks" dst-address-list="Suspected SMURF Attacks" protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-22-- Accept Echo Requests" icmp-options=8:0 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-23-- Accept Echo Replys" icmp-options=0:0 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-24-- Accept Destination Network Unreachable" icmp-options=3:0 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-25-- Accept Destination Host Unreachable" icmp-options=3:1 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-26-- Accept Destination Port Unreachable" icmp-options=3:3 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-27-- Fragmentation Messages" icmp-options=3:4 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-28-- Source Route Failed" icmp-options=3:5 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-29-- Network Admin Prohibited" icmp-options=3:9 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-30-- Host Admin Prohibited" icmp-options=3:10 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-31-- Router Advertisemnet" icmp-options=9:0 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-32-- Router Solicitation" icmp-options=9:10 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-33-- Time Exceeded" icmp-options=11:0-255 protocol=icmp
/ip firewall raw add action=accept chain="RFC ICMP Protection" comment="--6-34-- Tracerout" icmp-options=30:0 protocol=icmp
/ip firewall raw add action=drop chain="RFC ICMP Protection" comment="--6-35-- Drop ALL other ICMP Messages" log=yes log-prefix="FW-ICMP Protection" protocol=icmp
/ip firewall raw add chain=output action=accept disabled=yes comment="--6-0-- Raw Blocking Rule"

# OpenVPN BruteForce Prevention
/ip firewall filter add chain=output action=accept disabled=yes comment="--4-0-- OpenVPN BruteForce Prevention"
/ip firewall filter add action=reject chain=input log=yes log-prefix="OpenVPNProtection_" reject-with=icmp-network-unreachable src-address-list=Blocked_OpenVPN comment="--4-1-- BLOCK Bruteforce OpenVPN"
/ip firewall filter add action=add-src-to-address-list address-list=Blocked_OpenVPN address-list-timeout=180m chain=input connection-state=new dst-port=1194 protocol=tcp src-address-list=OpenVPN_stage3 comment="--4-3-- BLOCK Bruteforce OpenVPN stage 1"
/ip firewall filter add action=add-src-to-address-list address-list=OpenVPN_stage3 address-list-timeout=1m chain=input connection-state=new dst-port=1194 protocol=tcp src-address-list=OpenVPN_stage2 comment="--4-3-- BLOCK Bruteforce OpenVPN stage 2"
/ip firewall filter add action=add-src-to-address-list address-list=OpenVPN_stage2 address-list-timeout=1m chain=input connection-state=new dst-port=1194 protocol=tcp src-address-list=OpenVPN_stage1 comment="--4-4-- BLOCK Bruteforce OpenVPN stage 3"
/ip firewall filter add action=add-src-to-address-list address-list=OpenVPN_stage1 address-list-timeout=1m chain=input connection-state=new dst-port=1194 protocol=tcp comment="--4-5-- BLOCK Bruteforce OpenVPN stage 4"
/ip firewall filter add chain=output action=accept disabled=yes comment="--4-0-- OpenVPN BruteForce Prevention"
# Add a firewall rule
/ip firewall filter add chain=input dst-port=1194 protocol=tcp comment="Allow OpenVPN"

# Minimal firewall rule
/ip firewall filter add chain=output action=accept disabled=yes comment="--10-0-- Firewall Rule"
/ip firewall filter add action=drop chain=forward disabled=no dst-address-list=Bogons comment="--10-1-- defconf: Drop to bogon list"
/ip firewall filter add chain=input action=accept connection-state=established,related,untracked comment="--10-1-- defconf: accept established,related,untracked"
/ip firewall filter add chain=input action=drop connection-state=invalid comment="--10-2-- defconf: drop invalid"
/ip firewall filter add chain=input action=drop in-interface-list=!LAN comment="--10-3-- defconf: drop all not coming from LAN"
/ip firewall filter add chain=forward action=accept ipsec-policy=in,ipsec comment="--10-4-- defconf: accept in ipsec policy"
/ip firewall filter add chain=forward action=accept ipsec-policy=out,ipsec comment="--10-5-- defconf: accept out ipsec policy"
/ip firewall filter add chain=forward action=fasttrack-connection connection-state=established,related comment="--10-6-- defconf: fasttrack" disabled=yes
/ip firewall filter add chain=forward action=accept connection-state=established,related,untracked comment="--10-7-- defconf: accept established,related, untracked"
/ip firewall filter add chain=forward action=drop connection-state=invalid comment="--10-8-- defconf: drop invalid"
/ip firewall filter add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="--10-9-- defconf:  drop all from WAN not DSTNATed"
/ip firewall filter add chain=output action=accept disabled=yes comment="--10-0-- Firewall Rule"

# Enable Send Email on login failure
/system logging action add email-start-tls=yes email-to="$notificationMail" name=email target=email
/system logging add action=email topics=critical

# Configure Authentication Logging to a dedicated log file
/system logging action add disk-file-count=1 disk-file-name=auth.log disk-lines-per-file=5000 name=auth target=disk
/system logging add action=auth topics=critical
/system logging add action=auth topics=account

# Configure persistent Log
/system logging action set disk disk-lines-per-file=4096 disk-file-count=10 disk-file-name=persistentLog
/system logging add action=disk topics=error 
/system logging add action=disk topics=info  
/system logging add action=disk topics=warning
/system logging add action=disk topics=critical

# Drop Malicious IP
# These scripts pull a signifcant number of addresses to the address list and will require higher end routers.
/system script
add dont-require-permissions=no name=BlackList owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source="/\
    ip firewall address-list\r\
    \n:local update do={\r\
    \n:do {\r\
    \n:local data ([:tool fetch url=\$url output=user as-value]->\"data\")\r\
    \nremove [find list=blacklist comment=\$description]\r\
    \n:while ([:len \$data]!=0) do={\r\
    \n:if ([:pick \$data 0 [:find \$data \"\\n\"]]~\"^[0-9]{1,3}\\\\.[0-9]{1,3\
    }\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\") do={\r\
    \n:do {add list=blacklist address=([:pick \$data 0 [:find \$data \$delimit\
    er]].\$cidr) comment=\$description timeout=1d} on-error={}\r\
    \n}\r\
    \n:set data [:pick \$data ([:find \$data \"\\n\"]+1) [:len \$data]]\r\
    \n}\r\
    \n} on-error={:log warning \"Address list <\$description> update failed\"}\
    \r\
    \n}\r\
    \n\$update url=https://feeds.dshield.org/block.txt description=DShield del\
    imiter=(\"\\t\") cidr=/24\r\
    \n\$update url=https://www.spamhaus.org/drop/drop.txt description=\"Spamha\
    us DROP\" delimiter=(\"\\_\")\r\
    \n\$update url=https://www.spamhaus.org/drop/edrop.txt description=\"Spamh\
    aus EDROP\" delimiter=(\"\\_\")\r\
    \n\$update url=https://sslbl.abuse.ch/blacklist/sslipblacklist.txt descrip\
    tion=\"Abuse.ch SSLBL\" delimiter=(\"\\r\")\r\
    \n\$update url=http://malc0de.com/bl/IP_Blacklist.txt description=\"malc0d\
    e\" delimiter=(\"\\n\")"

/system scheduler
add interval=1d name=Blacklist on-event=Blacklist policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=nov/23/2020 start-time=00:00:00

# Backup Script to mail
/system script
add name=Backup owner=admin policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":log warning Mikrotik Router Backup JOB Started . . .\r    \n:local backupfile mt_config_backup\r    \n:local mikrotikexport mt_export_backup\r    \n:local sub1 ([/system identity get name])\r    \n:local sub2 ([/system clock get time])\r    \n:local sub3 ([/system clock get date])\r    \n\r    \n:log warning \$sub1 : Creating new up to date backup files . . . \r    \n \r    \n# Start creating Backup files backup and export both\r    \n/system backup save name=mt_config_backup dont-encrypt=yes\r    \n/export terse file=mt_export_backup\r    \n \r    \n:log warning \$sub1 : Backup JOB process pausing for 10s so it can complete creating backup. Usually for Slow systems ...\r    \n:delay 10s\r    \n \r    \n:log warning Backup JOB is now sending Backup File via Email using SMTP . . .\r    \n \r    \n# Start Sending email files, make sure you have configured tools email section before this. or else it will fail\r    \n/tool e-mail send to=\$backupMail subject=\$sub3 \$sub2 \$sub1 Configuration BACKUP File file=mt_config_backup.backup start-tls=yes\r    \n/tool e-mail send to=\$backupMail subject=\$sub3 \$sub2 \$sub1 Configuration EXPORT File file=mt_export_backup.rsc start-tls=yes\r    \n \r    \n:log warning \$sub1 : BACKUP JOB: Sleeping for 30 seconds so email can be delivered, \r    \n:delay 10s\r    \n \r    \n# REMOVE Old backup files to save space.\r    \n/file remove \$backupfile\r    \n/file remove \$mikrotikexport\r    \n \r    \n# Print Log for done\r    \n:log warning \$sub1 : Backup JOB: Process Finished & Backup File Removed. All Done. You should verify your inbox for confirmation\r    \n \r    \n# Script END"

/system scheduler
add interval=7d name=Backup on-event=Backup policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jun/13/2017 start-time=00:00:00

# SNMP v3 Configuration for Dude
/user add name="$newMikrotikDude" password="$newMikrotikDudePassword" group=full
/snmp community set 0 name=not_public read-access=no write-access=no
/snmp community add name="$dudeSnmpCommName" read-access=yes write-access=no authentication-protocol="$dudeAuthenticationProtocol" authentication-password="$dudeAuthenticationPassword" encryption-protocol="$dudeEncProtocol" encryption-password="$dudeEncPassword" security=private
/snmp set contact="$notificationMail" location="$dudeSnmpLocation" enabled=yes
/snmp set trap-community="$dudeSnmpCommName" trap-version=3

#Send Email with password file
/tool e-mail send to=$backupMail subject=MikrotikPassword body=PasswordFile file=passwordfile.txt

# Set Mikrotik name & password
/system identity set name="$mikrotikName"
/user set 0 password="$mikrotikAdminPassword"
/user add name="$newMikrotikUser" password="$newMikrotikUserPassword" group=full


