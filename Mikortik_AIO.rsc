############################################
###   Mikrotik Configuration                                                                             #
###   Connect to Mikrotik and paste this script in terminal           #      
###   Change Default Password!!!								      #
############################################

#User Configuration
:local mikrotikName "MikrotikName"
:local mikrotikAdminPassword "Password"
:local newMikrotikAdmin "User1"
:local newMikrotikAdminPassword "Password"

#Dude Configuration Snmp v3
:local newMikrotikDude "Dude"
:local newMikrotikDudePassword "Password"
:local dudeAuthenticationProtocol "SHA1"
:local dudeAuthenticationPassword "Password"
:local dudeEncProtocol "AES"
:local dudeEncPassword "Password"
:local dudeSnmpCommName "Dude_Comm"
:local dudeSnmpLocation "Somewhere"

#Lan Configuration
:local lanIpGateway "192.168.1.1"
:local lanIpDhcpRange "192.168.1.100-192.168.1.200"
:local lanIpDns "192.168.1.1"
:local lanNetworkAddress "192.168.1.0"
:local lanNetworkBits "24"
:local globalDNS1 "8.8.8.8"
:local globalDNS2 "8.8.4.4"

#Whitelist IP [If you want some ip in whitelist]
#:local whiteListAddr1 "8.8.8.8"
#:local whiteListAddr2 "8.8.4.4"
#:local whiteListAddrComment1 "Datacenter"
#:local whiteListAddrComment2 "Office"

#Clock Configuration
:local ntpAddr1 "31.14.133.122"
:local ntpAddr2 "193.183.98.38"

#Email Configuration
:local smtpAddr "8.8.8.8"
:local smtpPort "587"
:local smtpUser "user@domain.com"
:local smtpPassword "Password"
:local smtpTls "yes"
:global notificationMail "user@domain.com"
:global backupMail "user@domain.com"


#################
# Don't edit after this   #
#################

# Set Mikrotik name & password
/system identity set name="$mikrotikName"
/user set 0 password="$mikrotikAdminPassword"
/user add name="$newMikrotikAdmin" password="$newMikrotikAdminPassword" group=full

#Configure Basic Lan 
/ip address set interface=bridge address="$lanIpGateway/$lanNetworkBits" network="$lanNetworkAddress" comment="LAN"  numbers=0
/ip pool set default-dhcp ranges="$lanIpDhcpRange"
/ip pool set default-dhcp name="Pool_Lan"
/ip dhcp-server network set address="$lanNetworkAddress/$lanNetworkBits" gateway="$lanIpGateway" dns-server="$lanIpDns"  numbers=0

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
/ip firewall address-list add address="$whiteListAddr1" list="Allowed"  comment="$whiteListAddrComment1"
/ip firewall address-list add address="$whiteListAddr2" list="Allowed" comment="$whiteListAddrComment2"

# Delete default firewall rule
/ip firewall filter remove [/ip firewall filter find action!=passthrough ]

# Allow ip in whitelist
/ip firewall filter add chain=input src-address-list=Allowed action=accept comment="--0-1-- Allowed IP"
/ip firewall filter add chain=forward src-address-list=Allowed action=accept comment="--0-2-- Allowed IP"

#CREATE DROP RULES FOR BLACKLISTS
/ip firewall filter add chain=input action=accept disabled=yes comment="--1-0-- Squid Blacklist sbl blocklist.de"
/ip firewall filter add action=drop chain=input src-address-list="sbl blocklist.de" log=no log-prefix="BL_sbl_blocklist.de" comment="--1-1-- Squid Blacklist: SBL Blocklist.de"
/ip firewall filter add action=drop chain=forward src-address-list="sbl blocklist.de" log=no log-prefix="BL_sbl_blocklist.de" comment="--1-2-- Squid Blacklist: SBL Blocklist.de"
/ip firewall filter add action=drop chain=forward dst-address-list="sbl blocklist.de" log=no log-prefix="BL_sbl_blocklist.de" comment="--1-3-- Squid Blacklist: SBL Blocklist.de"
/ip firewall filter add action=drop chain=input src-address-list="sbl dshield" log=no log-prefix="BL_sbl_dshield" comment="--1-4-- Squid Blacklist: SBL DShield"
/ip firewall filter add action=drop chain=forward src-address-list="sbl dshield" log=no log-prefix="BL_sbl_dshield" comment="--1-5-- Squid Blacklist: SBL DShield"
/ip firewall filter add action=drop chain=forward dst-address-list="sbl dshield" log=no log-prefix="BL_sbl_dshield" comment="--1-6-- Squid Blacklist: SBL DShield"
/ip firewall filter add action=drop chain=input src-address-list="sbl spamhaus" log=no log-prefix="BL_sbl_spamhaus" comment="--1-7-- Squid Blacklist: SBL Spamhaus"
/ip firewall filter add action=drop chain=forward src-address-list="sbl spamhaus" log=no log-prefix="BL_sbl_spamhaus" comment="--1-8-- Squid Blacklist: SBL Spamhaus"
/ip firewall filter add action=drop chain=forward dst-address-list="sbl spamhaus" log=no log-prefix="BL_sbl_spamhaus" comment="--1-9-- Squid Blacklist: SBL Spamhaus"
/ip firewall filter add action=drop chain=input src-address-list="sbl bogons" log=no log-prefix="BL_sbl_bogons" comment="--1-10-- Squid Blacklist: SBL Bogons"
/ip firewall filter add action=drop chain=forward src-address-list="sbl bogons" log=no log-prefix="BL_sbl_bogons" comment="--1-11-- Squid Blacklist: SBL Bogons"
/ip firewall filter add action=drop chain=forward src-address-list="sbl tornodes" log=no log-prefix="BL_sbl_tornodes" comment="--1-12-- Squid Blacklist: SBL Tor Nodes"
/ip firewall filter add action=drop chain=forward dst-address-list="sbl tornodes" log=no log-prefix="BL_sbl_tornodes" comment="--1-13-- Squid Blacklist: SBL Tor Nodes"
/ip firewall filter add chain=input action=accept disabled=yes comment="--1-0-- Squid Blacklist sbl blocklist.de"

# DDoS Detection and Blocking Exeption
/ip firewall address-list add address="$lanNetworkAddress/$lanNetworkBits" list="DDosExeption"
/ip firewall address-list add address="$globalDNS1" list="DDosExeption"
/ip firewall address-list add address="$globalDNS2" list="DDosExeption"

# DDoS Detection and Blocking
/ip firewall filter add chain=input action=accept disabled=yes comment="--2-0-- DDoS Detection and Blocking"
/ip firewall filter add chain=forward connection-state=new action=jump jump-target=detect-ddos comment="--2-1-- DDosProtection"
/ip firewall filter add chain=detect-ddos dst-limit=32,32,src-and-dst-addresses/10s action=return comment="--2-2-- DDosProtection"
/ip firewall filter add chain=detect-ddos src-address-list=DDosExeption action=return comment="--2-3-- DDosExeption"
/ip firewall filter add chain=detect-ddos action=add-dst-to-address-list address-list=ddosed address-list-timeout=10m comment="--2-4-- DDosProtection"
/ip firewall filter add chain=detect-ddos action=add-src-to-address-list address-list=ddoser address-list-timeout=10m comment="--2-5-- DDosProtection"
/ip firewall filter add chain=forward connection-state=new src-address-list=ddoser dst-address-list=ddosed action=drop comment="--2-6-- DDosProtection"
/ip firewall filter add chain=input action=accept disabled=yes comment="--2-0-- DDoS Detection and Blocking"

# PortScanner Blocking
/ip firewall filter add chain=input action=accept disabled=yes comment="--3-0-- PortScanner Blocking"
/ip firewall filter add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-1-- Port scanners to list " disabled=no
/ip firewall filter add chain=input protocol=tcp tcp-flags=fin,!syn,!rst,!psh,!ack,!urg action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-2-- NMAP FIN Stealth scan"
/ip firewall filter add chain=input protocol=tcp tcp-flags=fin,syn action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-3-- SYN/FIN scan"
/ip firewall filter add chain=input protocol=tcp tcp-flags=syn,rst action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-4-- SYN/RST scan"
/ip firewall filter add chain=input protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-5-- FIN/PSH/URG scan"
/ip firewall filter add chain=input protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-6-- ALL/ALL scan"
/ip firewall filter add chain=input protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="--3-7-- NMAP NULL scan"
/ip firewall filter add chain=input src-address-list="port scanners" action=drop comment="--3-8-- dropping port scanners" disabled=no
/ip firewall filter add chain=input action=accept disabled=yes comment="--3-0-- PortScanner Blocking"

# Minimal firewall rule
/ip firewall filter add chain=input action=accept disabled=yes comment="--10-0-- Firewall Rule"
/ip firewall filter add chain=input action=accept connection-state=established,related,untracked comment="--10-1-- defconf: accept established,related,untracked"
/ip firewall filter add chain=input action=drop connection-state=invalid comment="--10-2-- defconf: drop invalid"
/ip firewall filter add chain=input action=drop in-interface-list=!LAN comment="--10-3-- defconf: drop all not coming from LAN"
/ip firewall filter add chain=forward action=accept ipsec-policy=in,ipsec comment="--10-4-- defconf: accept in ipsec policy"
/ip firewall filter add chain=forward action=accept ipsec-policy=out,ipsec comment="--10-5-- defconf: accept out ipsec policy"
/ip firewall filter add chain=forward action=fasttrack-connection connection-state=established,related comment="--10-6-- defconf: fasttrack"
/ip firewall filter add chain=forward action=accept connection-state=established,related,untracked comment="--10-7-- defconf: accept established,related, untracked"
/ip firewall filter add chain=forward action=drop connection-state=invalid comment="--10-8-- defconf: drop invalid"
/ip firewall filter add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="--10-9-- defconf:  drop all from WAN not DSTNATed"
/ip firewall filter add chain=input action=accept disabled=yes comment="--10-0-- Firewall Rule"


# Enable Send Email on login failure
/system logging action add email-start-tls=yes email-to="$notificationMail" name=email target=email
/system logging add action=email topics=critical

# Configure Authentication Logging to a dedicated log file
/system logging action add disk-file-count=1 disk-file-name=auth.log disk-lines-per-file=5000 name=auth target=disk
/system logging add action=auth topics=critical
/system logging add action=auth topics=account

# SquidBlackList Drop Malicious IP
/system script
add comment=Firewall dont-require-permissions=no name=Blacklist_SquidBlacklist_Download owner=admin policy=read,write,test source=":log warning \"START - Download blacklist (drop.malicious.rsc,sbl-bogons.rsc,sbl-tornodes.rsc) updates.\";\r\
    \n/tool fetch address=www.squidblacklist.org host=www.squidblacklist.org mode=http src-path=/downloads/drop.malicious.rsc dst-path=drop.malicious.rsc\r\
    \n/tool fetch address=www.squidblacklist.org host=www.squidblacklist.org mode=http src-path=/downloads/sbl-bogons.rsc dst-path=sbl-bogons.rsc\r\
    \n/tool fetch address=www.squidblacklist.org host=www.squidblacklist.org mode=http src-path=/downloads/sbl-tornodes.rsc dst-path=sbl-tornodes.rsc\r\
    \n:log warning \"END - Download blacklist (drop.malicious.rsc,sbl-bogons.rsc,sbl-tornodes.rsc) updates.\";\r\
    \n\r\
    \n:delay 30s\r\
    \n\r\
    \n:log warning \"START - Import blacklist (drop.malicious.rsc,sbl-bogons.rsc,sbl-tornodes.rsc) update.\";\r\
    \nimport drop.malicious.rsc\r\
    \nimport sbl-tornodes.rsc\r\
    \nimport sbl-bogons.rsc\r\
    \n:log warning \"END - Import blacklist (drop.malicious.rsc,sbl-bogons.rsc,sbl-tornodes.rsc) update.\";"

# CREATE DOWNLOAD BLACKLISTS SCHEDULER
/system scheduler
add comment=Firewall interval=1d name=Blacklist_SquidBlacklist_Download on-event="/system script run Blacklist_SquidBlacklist_Download" policy=read,write,test start-date=jan/01/2017 start-time=01:00:00

# Backup Script to mail
/system script
add name=Backup owner=admin policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=":log warning \"Mikrotik Router Backup JOB Started . . .\"\r\
    \n:local backupfile mt_config_backup\r\
    \n:local mikrotikexport mt_export_backup\r\
    \n:local sub1 ([/system identity get name])\r\
    \n:local sub2 ([/system clock get time])\r\
    \n:local sub3 ([/system clock get date])\r\
    \n\r\
    \n:log warning \"\$sub1 : Creating new up to date backup files . . . \"\r\
    \n \r\
    \n# Start creating Backup files backup and export both\r\
    \n/system backup save name=mt_config_backup dont-encrypt=yes\r\
    \n/export file=mt_export_backup\r\
    \n \r\
    \n:log warning \"\$sub1 : Backup JOB process pausing for 10s so it can complete creating backup. Usually for Slow systems ...\"\r\
    \n:delay 10s\r\
    \n \r\
    \n:log warning \"Backup JOB is now sending Backup File via Email using SMTP . . .\"\r\
    \n \r\
    \n# Start Sending email files, make sure you have configured tools email section before this. or else it will fail\r\
    \n/tool e-mail send to=\$backupMail subject=\"\$sub3 \$sub2 \$sub1 Configuration BACKUP File\" file=\"mt_config_backup.backup\" start-tls=yes\r\
    \n/tool e-mail send to=\$backupMail subject=\"\$sub3 \$sub2 \$sub1 Configuration EXPORT File\" file=\"mt_export_backup.rsc\" start-tls=yes\r\
    \n \r\
    \n:log warning \"\$sub1 : BACKUP JOB: Sleeping for 30 seconds so email can be delivered, \"\r\
    \n:delay 10s\r\
    \n \r\
    \n# REMOVE Old backup files to save space.\r\
    \n/file remove \$backupfile\r\
    \n/file remove \$mikrotikexport\r\
    \n \r\
    \n# Print Log for done\r\
    \n:log warning \"\$sub1 : Backup JOB: Process Finished & Backup File Removed. All Done. You should verify your inbox for confirmation\"\r\
    \n \r\
    \n# Script END"

/system scheduler
add interval=2w1d name=Backup on-event=Backup policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=jun/13/2017 start-time=00:00:00

# SNMP v3 Configuration for Dude
/user add name="$newMikrotikDude" password="$newMikrotikDudePassword" group=full
/snmp community set 0 name=not_public read-access=no write-access=no
/snmp community add name="$dudeSnmpCommName" read-access=yes write-access=no authentication-protocol="$dudeAuthenticationProtocol" authentication-password="$dudeAuthenticationPassword" encryption-protocol="$dudeEncProtocol" encryption-password="$dudeEncPassword" security=private
/snmp set contact="$notificationMail" location="\$dudeSnmpLocation" enabled=yes
/snmp set trap-community="$dudeSnmpCommName" trap-version=3