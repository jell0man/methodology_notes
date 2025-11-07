Initial NMAP
```bash
#Nmap UDP scan
sudo nmap <IP> -A -T4 -p- -sU -v -oN nmap-udpscan.txt
```

Install MIBs and configure for use
```bash
#Download
sudo apt install snmp-mibs-downloader -y

#Configure to print MIBs instead of OIDs
sudo vi /etc/snmp/snmp.conf
then comment out (#) mibs :
```
note you might have to disable this in some cases...


Brute Forcing Community Strings
	onesixtyone (only snmpv1)
	[SNMP-Brute](https://github.com/SECFORCE/SNMP-Brute) (snmpv2 also)
```bash
## DO BOTH
# Onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <ip_address>

# SNMP-Brute
python3 ~/tools/SNMP-Brute/snmpbrute.py -t <ip>
```

SNMP Enumeration (v1 and v2)
```bash
#USE ME
#Default string is 'public'

snmpwalk -c <community_string> -v 2c <ip_address>
and
snmpwalk -c <community_string> -v 2c <ip_address> NET-SNMP-EXTEND-MIB::nsExtendObjects

______________________________________________________________________________

snmpcheck -t <IP> -c public #Better version than snmpwalk as it displays more user friendly

snmpwalk -c public -v1 -t 10 <IP> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

#Windows MIB values
# These work for linux as well
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports
```

SNMP Enumeration (v3)
```bash
snmpwalk -v3 -u <user> -l authPriv -A <authentication_password> -a SHA -X <privacy_password(might not need)> -x AES <ip_address> system
	-u user
	-A auth password
	-X privacy password
	-l sets securityLevel to authPriv (auth AND priv)
	-a auth protocol (might not need, auth protocol) 
	-x privacy protocol (might not need)
	system -- retrieve basic system info, use to test connectivity
```

SNMP v3 Buteforce -- [snmpwn](https://github.com/hatlord/snmpwn)
```bash
./snmpwn.rb -h hosts.txt -u users.txt -p passwords.txt -e passwords.txt
```