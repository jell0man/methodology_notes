Cobalt Strike OPSEC Notes
```powershell
beacon> upload msedge.exe   # naming payloads as msedge helps with evasion
beacon> timestomp [payload] [other thing] # helps blend it in 

LSASS Dumping generally a bad idea -- triage and dump (kerberos) dump from memory and are better

Kerberos has a lot of OPSEC to be aware of...

LDAP Queries, be careful

# Lateral Movement
WinRM is good
PSExec sucks, SCShell is better
LOLBAS overrated, usually blocked

# Pivoting
Kerberos > NTLM

# Kerberos
lost of cool stuff
run klist is BAD OPSEC 
```