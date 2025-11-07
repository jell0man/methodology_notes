```
Make sure to use compatible versions of sharphound with legacy bloodhound

https://github.com/SpecterOps/BloodHound-Legacy

https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors
```

Start
	`bloodhound`
	or
	`~/tools/BloodHound/BloodHound --no-sandbox

Collection:
Run sharphound
	Sharphound.exe
	or
	`Import-Module .\sharphound.ps1
		`Get-Help Invoke-Bloodhound
		`Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\joe\Documents\windows -OutputPrefix "audit"`
Bloodhound-python (ldap)
```
bloodhound-python -c All -d 'ad.lab' -u 'john.doe' -p 'P@$$word123!' -ns 10.80.80.2

# via proxy
proxychains -q bloodhound-python -c All -d 'ad.lab' -u 'john.doe' -p 'P@$$word123!' -ns 10.80.80.2 --dns-tcp
```

consider netexec


Enum computers
	MATCH (m:Computer) RETURN m
		save to computers.txt file
		`nslookup <FQDN>
			with ligolo...
				
Enum users
	MATCH (m:User) Return m
		save to users.txt file


Clear database
![[Pasted image 20250226191828.png]]

