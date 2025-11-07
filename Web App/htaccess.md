htaccess is a file while governs what files may be uploaded to a webapp

It can also specify required headers to access web apps

## Required Headers
If a .htaccess file specifes required headers, we can add these headers to our Burp requests or to Firefox directly to gain access

Example .htaccess
```
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

Modifying Firefox
```
Use simple-modify-headers extension
```
![[Pasted image 20250815134029.png]]
then save

