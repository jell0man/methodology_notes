
Remember to always `chmod 600` ssh keys

Authorized_keys file may load other scripts when we attempt to ssh into a node
	may need to modify it if these scripts get in our way and replace the OG Authorized_keys file


`scp -O` can be used to force legacy SCP protocol for file transfers
	in case we get these errors...
		scp: Received message too long 1094927173
		scp: Ensure the remote shell produces no output for non-interactive sessions.


scp syntax
```bash
# transfer to victim
## key PRECEDES our file
scp -i id_rsa <file_to_transfer> <user>@<victim_host>:<file_destination>


# Force legacy scp protocol
scp -O -i id_rsa <file_to_transfer> <user>@<victim_host>:<file_destination>


# Transfer to kali
scp -i id_rsa <user>@<victim_host>:<file_to_transfer> <kali_destination>

```