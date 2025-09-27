#### SSH via PuTTY Keys
If we obtain a PuTTY User Key (`.ppk`), we can generate a PEM key (`.pem`) from it which can then be used to SSH

Usage
```bash
sudo apt install putty-tools
puttygen key.ppk -O private-openssh -o key.pem
ssh -i key.pem <user>@<ip>
```

#### Looting Credentials
If PuTTY is installed on a windows host, you can query the registry and potentially obtain credentials for other users

Query
```cmd
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

