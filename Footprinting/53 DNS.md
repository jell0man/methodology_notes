See [[DNS]] If you would like more background information about this service

## Footprinting

The dig command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records

#### DIG Queries
We can sometimes get information from DNS by running queries
```bash
# Nameserver query
dig ns <domain> @<ip>

# version query
dig CH TXT version.bind <ip>    # entry must exist on DNS server to work

# view ALL available records
dig any <domain> @<ip>
```

#### AXFR Zone Transfer
Zone transfer refers to the transfer of zones to another server in DNS, which generally happens over TCP port 53. This procedure is abbreviated Asynchronous Full Transfer Zone (AXFR). 

Sometimes we can successfully zone transfer one domain, revealing information about other domains which we can query/zone transfer as well.

DIG Zone Transfer
```bash
# AXFR Zone Transfer
dig axfr <domain> @<ip>    # repeat for any additional domains identified
```


#### Subdomain Brute Forcing
We can sometimes identify subdomains via DNS without using `ffuf` 

Subdomain Brute Forcing
```bash
# DIG for loop
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

# DNSenum alternative
dnsenum --dnsserver <ip> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt <domain>
```