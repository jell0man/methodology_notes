https://wiki.zacheller.dev/pentest/privilege-escalation/spawning-a-tty-shell

The first thing to do is use python3 -c 'import pty;pty.spawn("/bin/bash")', which uses Python to spawn a better-featured bash shell. At this point, our shell will look a bit prettier, but we still won’t be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.

Step two is: export TERM=xterm – this will give us access to term commands such as clear.

Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use stty raw -echo; fg. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

One-Liners
```bash
# which python
python -c 'import pty; pty.spawn("/bin/bash")'

python3 -c 'import pty; pty.spawn("/bin/bash")'

echo os.system('/bin/bash')

/bin/sh -i

perl —e 'exec "/bin/sh";'
```

```perl
exec "/bin/sh";
```

```ruby
exec "/bin/sh"
```

```lua
os.execute('/bin/sh')
```

```IRB
exec "/bin/sh"
```

```vi
:!bash

:set shell=/bin/bash:shell
```



