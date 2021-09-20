# Changelog

### 08/09/2021
* Invoke-PSObfuscation.ps1 go live
 
### 09/01/2021
* Updated the Find-Variable function to ignore instances of $true and $false

### 09/03/2021
* Updated the Find-Namespace function to include more class names and compatibility

### 09/19/2021
* Fixed a conflict where Find-Variables would mess with automatic variables
* Fixed a conflict where Find-Variables would not properly replace variables that are associated to parameters in custom functions as well as their parameter deriviate
* Removed functions ConvertTo-OneLine, Format-SocketBeacons, Get-ObfuscatedIpAddress and Find-Listener
* Removed switch parameters IPAddress, Port, Listener
* Added a new generator for Get-ObfuscatedInteger
* Added component support for single line and multi-line comment removal
* Updated functions Find-Cmdlet, Find-Integer and Remove-Aliases to utilize [System.Management.Automation.PSParser] for parsing out components in a payload vs regex
