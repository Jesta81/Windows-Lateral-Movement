## Introduction


### Introduction to Windows Lateral Movement

> Lateral movement refers to the techniques we use to move through a network after gaining initial access. 
>
> By understanding lateral movement, attackers and defenders can better navigate and secure networks. 
>
> This knowledge allows defenders to implement more effective security measures and helps attackers identify and exploit weaknesses in network defenses, ultimately leading to a more robust and resilient security posture. 



### Description of Lateral Movement


> Lateral movement involves moving from one system to another within a network, often with the goal of escalating privileges or accessing sensitive data. 
> 
> Using lateral movement techniques, we can move deeper into a network in search of credentials, sensitive data, and other high-value assets. 
>
>
> To perform a lateral movement, we need **any form of credentials, including passwords, hashes, tickets, SSH keys, and session cookies.** 
> 
> We can leverage those to connect to a remote computer in the network. 
> 
> Effective lateral movement requires a deep understanding of network architectures and the ability to identify services and protocols we can leverage to execute code on remote systems. 



### MITRE ATT&CK Framework



> The [MITRE ATT&CK framework](https://attack.mitre.org/tactics/TA0008/) defines lateral movement as techniques used to enter and control remote systems on a network. 
> 
> This often involves exploring the network, pivoting through multiple systems and accounts, and using either remote access tools or legitimate credentials with native tools. 
> 
>
> [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0008/) lists several techniques for lateral movement, including: 



![Windows LM](/Introduction-to-Windows-Lateral-Movement/images/mitre.png) 



![Windows LM](/Introduction-to-Windows-Lateral-Movement/images/mitre-1.png) 


> These techniques illustrate the various methods we can use to navigate and control remote systems within a network. 


### Networks & Systems 


> Understanding how networks and systems work is crucial to performing lateral movement. 
> 
> Our **initial step is to identify or map the network devices that we can target;** we can do that through **port scanning, ping sweep, or using Active Directory information.** 
>
>
> Once we understand the network, we need to be aware that **some systems may be out of reach because of network segmentation or firewall restrictions.** 
> 
> In those cases, we need to think outside the box to get access to those services. Let's divide these scenarios into **direct lateral movement and indirect lateral movement.** 



### Direct Lateral Movement


> Direct lateral movement is where we can execute commands directly on the target machine and force the target machine to connect back to us. 
> 
> For example, if we **compromise SRV01 and need to move laterally to SRV02, we can use PSExec from SRV01 to execute commands on SRV02** and obtain a session or shell on SRV02. 



![Windows LM](/Introduction-to-Windows-Lateral-Movement/images/direct.png) 



### Indirect Lateral Movement


> Indirect lateral movement involves executing commands on the target machine when it receives instructions from another system. 
> 
> For example, suppose we can't reach SRV02 directly from SRV01 due to a network firewall restriction, but SRV02 can connect to the Windows Update Server (WSUS). 
> 
> In this case, if we compromise the WSUS server and create a fake Windows Update that executes our desired command, once SRV02 retrieves the update, it will run our malicious update, allowing us to obtain a shell on SRV02. 



![Windows LM](/Introduction-to-Windows-Lateral-Movement/images/indirect.png) 



### Command Execution


> As we see, command execution is very important when working with lateral movement. 
> 
> The ability to execute commands can help us gain access to remote services. 
>
> Throughout this module, we will use different methods to execute commands or payloads that will be helpful when dealing with networks that employ various security mechanisms. 



### Topology of the Lab


> To provide hands-on experience, the lab topology will simulate a typical corporate network environment, including: 
>
> -  Multiple network segments: Representing different departments or security zones.
>
> -  Key infrastructure components: Domain controllers, update servers, and management servers. 
> 
> We will practice identifying and exploiting lateral movement opportunities, reinforcing our understanding of the techniques and defenses discussed. 



### Network Segmentation



> Understanding network segmentation is crucial for effectively performing lateral movement as attackers. 
> 
> Network segmentation involves dividing a network into smaller, isolated segments to limit the spread of an attack. 
>
> Proper network segmentation can:
>
> -  **Contain breaches:** Restrict our movement and reduce the attack surface. 
>
> -  **Enhance monitoring:** Allow for more focused and effective monitoring of network traffic. 
>
> -  **Improve access control:** Enforce strict access policies between different segments. 


![Windows LM](/Introduction-to-Windows-Lateral-Movement/images/lab.png) 


![Windows LM](/Introduction-to-Windows-Lateral-Movement/images/lab-1.png) 



> In the above image, we can see a high-level overview of the network topology. 
> 
> There are three network segments, and the device that determines which network can reach the other is the Switch Layer 3. 
> 
> In other networks, this device can be a router, a Linux server, or a firewall. 
> 
> Understanding how these devices control communication between segments is essential for planning lateral movement. 
> 
> 
> Through testing, we can identify which communication is allowed, but in this case, we will start the engagement from an assumed breach scenario. 
> 
> 
> Not all servers will be available in every section; sometimes, we will start from a different server. > 
> This variability highlights the importance of understanding network segmentation and its impact on our ability to move laterally. 
>
>
> By the end of this module, we will have a solid foundation in Windows lateral movement, providing us with the knowledge to carry out and defend against these advanced attacks. 
