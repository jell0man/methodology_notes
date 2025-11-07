Knockd is a program that opens an SSH connection only if a specific knock sequence is initiated, as shown below.

/etc/knockd.conf example
```
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

Opening SSH
```bash
knock -v <attack_ip> 571 290 911 -d 500
```
The sequence follows the attack ip we are opening the SSH port to