If a box uses git, we can enumerate it

`git status
	display state of git working directory
	if we see deleted files, use `git restore

`sudo git restore .`
	use in git directory if files were deleted (git status will reveal this)
	then `ls -la` to see any new files 

`git log
	shows commit history

`git show <commit_id>
	goes in depth on each commit
	`/<search>` to filter key words
	`n` to jump to each keyword highlighted
	`| grep <filter>` to see all instances of keyword


#### git-dumper
Use to dump gits from repo to a local directory

Set up virtual env prior to usage
```bash
python3 -m venv .venv
source .venv/bin/activate 
python3 -m pip install git-dumper
```

Fire away
```bash
git-dumper <URL> <output_directory>
```

Once we dump it, we enter the directory
	then perform git status, log, show as if we are the the actual directory

Enumerate the files as well


#### Modifying git files for privesc
Sometimes we may need to make changes to a files within a git server
	example: a cron file runs within a git-server

Step 1 -- Clone it
`git clone`
	we can use this to clone a directory to a location we can then modify
```
cd /tmp/      # or any writeable location
git clone file:///<git_server_directory>/`
```
now we can modify files in here

Step 2 -- Modify Files
	echo, vim, etc... 
	`chmod 777 <file>   # so all users can access the file

Step 3 -- Commit changes
```
git add <file>     OR     git add -A
git commit -m "<any_name_you_want>"

# when we commit, we may get an unknown author error we need to fix
git config --global user.name "<name_we_want"
git config --global user.email "<name_we_want"
```

Step 4 -- Push changes to master
```
git push origin master
```


#### Git commands across SSH
What if we need to make changes to a git server from our local box?
```
# git clone a git-server from victim machine TO our machine
	ssh command will vary based on if we have a key, password, different port, etc

GIT_SSH_COMMAND='ssh -i <path/to/key> -p <port> etc...' git clone <user>@<victim_ip>:/path/to/<git-server>


# push changes back to master

GIT_SSH_COMMAND='ssh -i <path/to/key> -p <port> etc...' git push origin master
```

Aside from these, all other changes follow the previous section

example: see [[Hunit]]