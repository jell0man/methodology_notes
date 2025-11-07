If port 113 is open and running 'ident', we can use this to enumerate users. User against ALL PORTS

`ident-user-enum <ip_address> <ALL_PORTS>
	example:
	`ident-user-enum 192.168.225.60 113 80 8080 10000 ...