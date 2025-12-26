Cobalt Strike OPSEC Notes
```powershell
beacon> upload msedge.exe   # naming payloads as msedge helps with evasion
beacon> timestomp [payload] [other thing] # helps blend it in 

LSASS Dumping generally a bad idea -- triage and dump (kerberos) dump from memory and are better

Kerberos has a lot of OPSEC to be aware of...
```