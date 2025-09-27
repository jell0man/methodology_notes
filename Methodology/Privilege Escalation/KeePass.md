KeePass is a open source password manager we often find on targets that stores passwords we can abuse

.kdbx is the KeePass 2.x database file format

KeePass program exists on my Windows host
Alternatively we can use `kpcli` to extract passwords from the KeePass Database
#### Cracking .kdbx Files
We can often crack .kdbx files using keepass2john 

.kdbx Workflow
```bash
# Crack keepass db master password
keepass2john db.kdbx > db.kdbx.hash
john db.kdbx.hash --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64

# Copy .kdbx file to mountpoint
cp db.kdbx /mnt/hgfs/Mount/.

# Open Keepass 2 on Windows host (or kpcli) and open db file
```

kpcli Usage
```bash
kpcli --kdb db.kdbx
Please provide the master password: <password>

# List all passwords
find .

# Display passwords
show -f <n.>
```

#### KeePass Dump Files
Sometimes we may find application dump files (`.dmp`) associated with KeePass.

We can use this [repo](https://github.com/vdohney/keepass-password-dumper) to process the dump file and extract the master pass

Extract pass from dump file
```powershell
1. # Copy .dmp file to mountpoint
2. # Start powershell from Windows host
3. # cd to keepass-password-dumper repo
cd "C:\Users\joshu\Downloads\keepass-password-dumper"

4. # move the .dmp file to local repo
5. # run tool
dotnet run .\<keepass.dmp>
```
