Enumerate Services
	PS `Get-Service -name "<service>`
		enumerates state of service
	PS` Get-CimInstance
	cmd
	sc.exe
		sc.exe query state= all
		sc (if you are in cmd line)

Using services
	powershell
		PS `Start-Service <service>
			starts service
		PS `Stop-Service <service>`
			stops service
	cmd
		`sc.exe start <service>
		`sc.exe stop <service>`

```
in PowerShell sc is an alias for Set-Content cmdlet and not sc.exe , the reason you are getting medtech\wario from test.txt is because when you run start auditTracker in PowerShell, it will find and execute the binary, instead of starting the service, hence you are running the binary as the current user which explains the results from test.txt file, since you are executing sc start auditTracker which is not starting the service, instead executing the sc cmdlet instead. You need to use sc.exe in this case
```

```
Note: Errors like this may be NORMAL

[SC] StartService FAILED 1053:
The service did not respond to the start or control request in a timely fashion.


When you replace a binary with a malicious one, the service when you start it is going to FAIL because it isnt working properly... Your payload may still be executing in the backgroud


```