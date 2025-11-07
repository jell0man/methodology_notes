Port : 3128

If we run into this, we need to proxy in order to access internal resources.

Once our proxy is setup, we can leverage proxychains to access internal resources, internal interfaces, etc....

Setup Squid Proxy
```bash
# Modify froxyproxy 
Foxyproxy > Proxies > Squid
	Modify IP of Squid proxy to host we are attacking

# Modify /etc/proxychains.conf
# (s) depends on setup
...SNIP...
http(s) <ip> 3128

# proxychains with credentials
http(s) <ip> <port> <user> <password>
```
Example
![[Pasted image 20250726153119.png]]

After this we can run commands via proxychains

Proxied Commands
```bash
# Access webapps -- be PATIENT
# Must be ONLY browser running
proxychains4 firefox

# Nmap scan -- MUST USE -sT, sudo, -e tun0, etc... or else results are FRAUDS
sudo proxychains4 -q nmap <ip> -sT -Pn -n -vv -e tun0 --min-rate=1000
```