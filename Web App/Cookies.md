If you identify cookies such as JSESSIONID, you can modify Requests with Burp with the cookie and potentially login

Example Request
```Burp
POST /login
...SNIP...
Cookie: JESSIONID=<token>
...SNIP...
username=test&password=test
```