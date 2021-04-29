# Mikrotik All in One Script
+ Tested on RB3011 - From RouterOS 6.48

![Status: Alpha](https://img.shields.io/badge/status-alpha-red.svg?longCache=true "Status: Alpha")

## Feature
+ Basic Lan Configuration
+ Basic Firewall configuration
+ Whitelist IP
+ Port Scanner Blocking
+ Simple Dude configuration for remote logging
+ Simple DDoS Detection and Blocking
+ Simple OpenVPV port scanner blocking
+ Block spamhaus.org drop
+ Block spamhaus.org edrop
+ Block dshield.org
+ Block sslbl.abuse.ch
+ Block malc0de.com
+ Schedule Backup configuration to email
+ Email Notification on failed login
+ Authentication Logging to a dedicated log file
+ Persistent Log
+ Strong password generator
+ Generate password file and sent it to email
+ Weekly Backup to email

## Usage
+ Connect using winbox
+ Make sure you have a connection on Mikrotik (enable dhcp-client on ether1)
+ Do a System -- > Reset Configuration [keep default config after reboot]
+ Copy, Modify and import the file "import Mikrotik_AIO.rsc"

## To Do
+ Email Notification on port scanning
+ Improve security
+ Offline configuration
+ Wifi Configuration
