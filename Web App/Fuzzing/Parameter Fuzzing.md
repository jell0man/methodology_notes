Sometimes we can fuzz for parameters that allow access to pages we normally wouldn't have. Similarly to how we have been fuzzing various parts of a website, we will use `ffuf` to enumerate parameters.

Wordlists to reference
```bash
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```
## GET Request Fuzzing
We can fuzz for `GET` requests which are usually passed right after the URL with a ?

GET Request Fuzzing
```bash
# Initial Fuzz
ffuf -w <wordlist>:FUZZ -u http://<server>:<port>/dir/admin.php?FUZZ=key 

# Filter out default response size
-fs xxx
```

## POST Request Fuzzing
`POST` requests are passed in the data filed within the HTTP request. Do do this, we use -d flag

POST Request Fuzzing
```bash
# Initial FUZZ
ffuf -w <wordlist>:FUZZ -u http://<server>:<port>/dir/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' 

# Filter out default response size
-fs xxx     # make note of parameter we get

# curl using identified paramater
curl http://<server>:<port>/dir/admin.php -X POST -d '<paramater>=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

## Value Fuzzing
Similar to POST request fuzzing, but the value is fuzzed instead of the parameter.

Value Fuzzing example
```bash
# Create wordlist (or use one)
for i in $(seq 1 1000); do echo $i >> ids.txt; done

# Fuzz the value
ffuf -w ids.txt:FUZZ -u http://<server>:<port>/dir/admin.php -X POST -d '<paramater>=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' 
# filter out default response size 
-fs xxx

```