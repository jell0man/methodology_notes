Secure Shell

Usage:
```bash
# Standard Auth
ssh <user>@<ip/hostname>

# Auth with Private Key
ssh -i <key> <user>@<ip/hostname>

# SSH with unrestricted profile (restricted shell breakout)
ssh <user>@<ip/hostname> -t "bash - noprofile"
```

File Transfer
```bash
scp
```

#### Errors
Unable to negotiate with 10.129.229.183 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
    resolution:
        `-o KexAlgorithms=diffie-hellman-group1-sha1

Unable to negotiate with 10.129.229.183 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
    resolution:
        `-o HostKeyAlgorithms=ssh-dss

you can combine these!!!!!!!!