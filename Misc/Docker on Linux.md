To install Docker on Kali you need to remember that there is already a package named “docker”, therefore Docker has to be installed under a different name. If you install docker you will not end up with the container version. The version we will be installing is named docker.io. All commands are the same however, so running docker on the command line will be the appropriate command:

This gives some issues because docker isnt built for ARM linux

```
kali@kali:~$ sudo apt update
kali@kali:~$
kali@kali:~$ sudo apt install -y docker.io
kali@kali:~$
kali@kali:~$ sudo systemctl enable docker --now
kali@kali:~$
kali@kali:~$ docker
kali@kali:~$
```

Use docker as user (not root)
```
kali@kali:~$ sudo usermod -aG docker $USER
kali@kali:~$

```

Using
`sudo systemctl enable docker --now
`docker

Install
`docker pull --platform linux/amd64 kalilinux/kali-rolling`

Run
`docker run -it --platform linux/amd64 kalilinux/kali-rolling bash

Docker Inspect Usage
```bash
# List docker containers
docker-ps

# Inspect contents of containers
docker-inspect '{{json .}}' <container_name> | jq .
```
