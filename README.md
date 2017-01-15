# Invoke-TheHash
Invoke-TheHash contains PowerShell functions for performing pass the hash WMI and SMB command execution. WMI and SMB services are accessed through .NET TCPClient connections. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privilege is not required client-side.  

# Requirements
Minimum PowerShell 2.0  

# Import 
Import-Module ./Invoke-TheHash.psd1  

or   

. ./Invoke-WMIExec.ps1  
. ./Invoke-SMBExec.ps1  
. ./Invoke-TheHash.ps1  

## Functions  
* Invoke-WMIExec  
* Invoke-SMBExec  
* Invoke-TheHash  
* ConvertTo-TargetList  

### Invoke-WMIExec
* WMI command execution function.  

##### Parameters:
* __Target__ - Hostname or IP address of target.  
* __Username__ - Username to use for authentication.  
* __Domain__ - Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username.  
* __Hash__ - NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.  
* __Command__ - Command to execute on the target. If a command is not specified, the function will just check to see if the username and hash has access to WMI on the target.  
* __Sleep__ - Default = 10 Milliseconds: Sets the function's Start-Sleep values in milliseconds.  

##### Example:
Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose  

##### Screenshot:
![wmi](https://cloud.githubusercontent.com/assets/5897462/21598463/7379df8a-d12b-11e6-8e8e-6dc6da4be235.png)

### Invoke-SMBExec
* SMB (PsExec) command execution function supporting SMB1, SMB2, and SMB signing.  

##### Parameters:
* __Target__ - Hostname or IP address of target.  
* __Username__ - Username to use for authentication.  
* __Domain__ - Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username.  
* __Hash__ - NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.  
* __Command__ - Command to execute on the target. If a command is not specified, the function will just check to see if the username and hash has access to SCM on the target.  
* __CommandCOMSPEC__ - Default = Enabled: Prepend %COMSPEC% /C to Command.  
* __Service__ - Default = 20 Character Random: Name of the service to create and delete on the target.  
* __SMB1__ - (Switch) Force SMB1. The default behavior is to perform SMB version negotiation and use SMB2 if supported by the target.  
* __Sleep__ - Default = 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds.  

##### Example:
Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose  

##### Screenshot:
![smb](https://cloud.githubusercontent.com/assets/5897462/21594963/b899ecf2-d0f6-11e6-9bd7-750b218e86a0.png)

### Invoke-TheHash  
* Function for running Invoke-WMIExec and Invoke-SMBExec against multiple targets.  

##### Parameters:
* __Type__ - Sets the desired Invoke-TheHash function. Set to either WMIExec or SMBExec.  
* __Targets__ - List of hostnames, IP addresses, or CIDR notation for targets.  
* __TargetsExclude__ - List of hostnames and/or IP addresses to exclude form the list or targets.  
* __PortCheckDisable__ - (Switch) Disable WMI or SMB port check. Since this function is not yet threaded, the port check serves to speed up he function by checking for an open WMI or SMB port before attempting a full synchronous TCPClient connection.  
* __PortCheckTimeout__ - Default = 100: Set the no response timeout in milliseconds for the WMI or SMB port check.  
* __Username__ - Username to use for authentication.  
* __Domain__ - Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username.  
* __Hash__ - NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.  
* __Command__ - Command to execute on the target. If a command is not specified, the function will just check to see if the username and hash has access to WMI or SCM on the target.  
* __CommandCOMSPEC__ - Default = Enabled: SMBExec type only. Prepend %COMSPEC% /C to Command.  
* __Service__ - Default = 20 Character Random: SMBExec type only. Name of the service to create and delete on the target.  
* __SMB1__ - (Switch) Force SMB1. SMBExec type only. The default behavior is to perform SMB version negotiation and use SMB2 if supported by the target.  
* __Sleep__ - Default = WMI 10 Milliseconds, SMB 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds.  

##### Example:
Invoke-TheHash -Type WMIExec -Targets 192.168.100.0/24 -TargetsExclude 192.168.100.50 -Username Administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0  

##### Screenshot:
![ithsmb](https://cloud.githubusercontent.com/assets/5897462/21594966/c0f69a62-d0f6-11e6-91f2-af9103571bde.png)

### ConvertTo-TargetList
* Converts Invoke-TheHash output to an array that contains only targets discovered to have Invoke-WMIExec or Invoke-SMBExec access. The output from this function can be fed back into the Targets parameter of Invoke-TheHash.   





