The term `fuzzing` refers to a testing technique that sends various types of user input to a certain interface to study how it would react.

`ffuf` can be used for this, although ferox is pretty power most of the time...
## Directory Fuzzing
```bash
ffuf -w <wordlist>:FUZZ -u http://<server>:<port>/FUZZ
```

## Page Fuzzing

Extension Fuzzing
```bash
# /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
ffuf -w <extensions_wordlist>:FUZZ -u http://<server>:<port>/dir/index.FUZZ
```

Page Fuzzing
```bash
# /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
ffuf -w <wordlist>:FUZZ -u http://<server>:<port>/dir/FUZZ.php
```

## Recursive Fuzzing
```bash
ffuf -w <wordlist>:FUZZ -u http://<server>:<port>/FUZZ -recursion -recursion-depth 1 -e .php -v
```