#### Authenticate to MySQL Database

anonymous auth
```bash
mysql -h <Hostname> -u root --skip-ssl
```

authenticated auth
```bash 
mysql -h <hostname> -u <user> -p -D <database_name> -P <port> --skip-ssl
password: <password goes here>
```

local windows authentication
```cmd
c:\path\to\bin> mysql.exe -u root -p
```

#### Password Reuse
If you find a password, try to authenticate to mysql as ROOT as well
	if successful, ALL databases will be revealed

#### Dump Database
Sometimes we can just dump the database if we are unable to authenticate via mysql

Dump
```bash
1. # Transfer over mysqldump binary

2. # Fire
# Dump specific database
mysqldump -u <username> -p <database> > backup.sql

# Dump all databases
mysqldump -u <username> -p --all-databases > all_databases_backup.sql
```

#### Enumeration
Basic Enumeration
```sql
-- Retrieve Version
select version();

-- Inspect current session user
select system_user();

-- Databases
show databases;
use <database>

-- Tables
show tables;
select * from <table>;
select <field1,field2,...> from table;
```

User hash retrieval example:
```sql
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';

+--------+------------------------------------------------------------------------+
| user   | authentication_string                                                  |
+--------+------------------------------------------------------------------------+
| offsec | $A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6|
+--------+------------------------------------------------------------------------+
```
pass is stored as [_Caching-SHA-256_ algorithm](https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html).
	we could potentially reverse/crack this

#### Editing Databases
Sometimes we are able to modify entries in a SQL database
```sql
# Setting password equal to 'admin' (this is a sha1 hash)
# WHERE is a refernce to show which row we are modifying

UPDATE <table> SET password='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' WHERE <column_1>='<value>';
```
