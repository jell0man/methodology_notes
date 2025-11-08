ALWAYS CHECK ANONYMOUS AUTH

Password Spraying? Use auxiliary/scanner/ftp/ftp_login or Netexec
	ftp_login is more useful if you have a USER_PASS list in 1 file

#### Usage:
```bash
ftp <ip>

# anonymous auth
creds
	anonymous :
	anonymous : anonymous    # check both blank pass AND anonymous:anonymous

# acvive mode     sometimes necessary to auth, transfer files, etc...
-A

# binary mode
binary

# upload files
put <file>
```

Need extra perms to do anything?
	try default creds
		admin:admin
		Admin:Admin
	`<User>:<User>`
	Any cred combos you have already found, etc

#### Download Files
```bash
# all files (fails directories)
mget *

# ALL files
wget -m --user=username --password=password ftp://ip:port
```

able to put files?
	great!
	consider uploading reverse shells in webroot OR ftp root 
		iis? put in iisstart.htm directory

Any files that seem to be useless? Check their properties ie author fields
	`exiftool <file>
	do this for ALL files you find that seem out of place

