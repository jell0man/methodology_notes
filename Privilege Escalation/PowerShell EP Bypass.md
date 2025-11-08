In case scripts are disabled on a system, you can run the following to run them again
```PowerShell
powershell -ep bypass
```

In case you need it in your CURRENT shell, you can try this
```powershell
# Change execution policy to PERSIST for the current user
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```