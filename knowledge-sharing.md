# Knowledge Sharing

## Content Loading

```powershell
function ConvertTo-OneLine {
    <#
    .SYNOPSIS
        Converts a given payload to a single line.
    
    .DESCRIPTION
        Payloads are loaded as a string array and joined together with a semicolon to allow for single line conversions.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .EXAMPLE
        PS C:\> ConvertTo-OneLine -Payload $value1
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Array]$Payload
    )
    Process {
        $Payload = $Payload -join ';'
    }
    End {
        return $Payload
    }
}

$Content = [System.IO.File]::ReadAllLines( ( Resolve-Path .\payload.ps1 ))
$Content = ConvertTo-OneLine -Value $Content
```

## Beacons

```powershell
Function New-EncodedBeacon() {
    <#
    .SYNOPSIS
        Genenerates an encoded beacon value from a given value.
    
    .DESCRIPTION
        Genenerates an encoded beacon to enable us to obfuscate each instance of a non-unqiue value.

    .PARAMETER Value
        The Value parameter is used to instruct the function which value needs to be converted into a beacon.
        If no value is provided, then the function will insert a timestamp.
    
    .EXAMPLE
        PS C:\> New-EncodedBeacon -Value 'value'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [System.String]$Value
    )
    Begin {
        $Start = "<obfus"
        $End = 'cate>'
    }
    Process {
        if ($Value) {
            $Beacon = $Start + (($Value -split '') -join '%') + $End
        }
        else {
            $Beacon = $Start + ((Get-Date -UFormat %s).Split('.')[0]) + $End
        }
    }
    End {
        return $Beacon
    }
}
```

## Discovery

```powershell
function Find-Cmdlet() {
    <#
    .SYNOPSIS
        Identifies and replaces cmdlets within a given payload.
    
    .DESCRIPTION
        Peforms a regex search for all cmdlets within the payload and replaces each cmdlet instance with a new value.
    
    .PARAMETER Payload
        The payload containing the powershell script to be converted
    
    .EXAMPLE
        PS C:\> Find-Cmdlet -Payload 'Value1'
    
    .NOTES
        This replaces each instance with a unique value by inserting unique beacon values that get replaced.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload
    )
    Begin {
        $Occurrences = Get-Command | Where-Object { $_.name -like "*-*" } | Select-Object -ExpandProperty Name | ForEach-Object { 
            if ($Payload -like "*$_*") { 
                $_ 
            } 
        }
    }
    Process {  
        try {
            # For each occurence, replace it with a beacon value
            $Occurrences | ForEach-Object {
                $Beacon = New-EncodedBeacon -Value $_
                [regex]$Pattern = "(?<!<obfu%)$_(?!%cate>)"
                $Payload = $Pattern.replace($Payload, $Beacon)
            }

            # For each occurence, replace it with an obfuscated value
            (($Payload | Select-String '<obfus(.*?)cate>' -AllMatches)).Matches.Value | ForEach-Object {
                $Decoded = $_ -replace '<obfus' -replace 'cate>' -replace '%'
                $NewValue = Get-ObfuscatedCmdlet -cmdlet $Decoded
                $Payload = $Payload.Replace("$_", $NewValue, 1)

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "    $Decoded >> $NewValue"
                }
            }
        }
        Catch {
            Write-Host "[!] $($MyInvocation.MyCommand.Name) Error - $($_.Exception.Message) - Skipping"
        }
    }
    End {
        return $Payload
    }
}
```

## Generator

```powershell
function Get-ObfuscatedCmdlet() {
    <#
    .SYNOPSIS
        Genenerates a new variation of the derived cmdlet.
    
    .DESCRIPTION
        Genenerates a new variation of the derived cmdlet variation using a randomly selected algorithm.
    
    .PARAMETER Cmdlet
        The cmdlet that will be replaced within the given payload.

    .EXAMPLE
        PS C:\> Get-ObfuscatedCmdlet -Cmdlet 'value'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Cmdlet
    )
    Begin {
        $Picker = 1..2 | Get-Random
    }
    Process {
        Switch ($Picker) {
            1 { 
                # All valid characters in a cmdlet name
                $Valid = ('-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Sort-Object { Get-Random }) -join ''
                $ReplaceWith = $Valid.ToCharArray()
                $ExtractedCharArray = @()
                $CmdletCharArray = $Cmdlet.ToCharArray()
                
                # Loop through each character within each command
                ForEach ($Char in $CmdletCharArray) {
                    If ($Char -in $ReplaceWith) {
                        $ExtractedCharArray += $([array]::IndexOf($ReplaceWith, $Char))
                    }
                }

                # Final Value
                $NewValue = "& ((""$Valid"")[$($ExtractedCharArray -join ',')] -join '')"
            }
            2 {
                $CharArrayString = ($Cmdlet.ToCharArray() | ForEach-Object { [int][char]$_ }) -join ","
                $NewValue = '& ([string]::join('''', ( (<OBFUSCATED>) |%{ ( [char][int] $_)})) | % {$_})' -replace '<OBFUSCATED>', $CharArrayString
            }
        }
    }
    End {
        return $NewValue
    }
}
```
