<#
.SYNOPSIS
    Evalua tecnicas posibles de movimiento lateral desde un usuario hacia un host.
.DESCRIPTION
    Muestra si un usuario puede usar tecnicas como WMI, DCOM, WinRM, PsExec, Pass-the-Hash, Overpass-the-Hash o Pass-the-Ticket.
.PARAMETER FromUser
    Usuario origen (ej: jeff).
.PARAMETER ToHost
    Host destino (ej: web04).
.EXAMPLE
    .\Check-LM.ps1 -FromUser jeff -ToHost web04
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$FromUser,
    
    [Parameter(Mandatory = $true)]
    [string]$ToHost
)

function Get-UserGroups {
    param ([string]$Username)
    try {
        $user = [ADSI]"LDAP://CN=$Username,${((Get-ADUser $Username).DistinguishedName -split ",",2)[1]}"
        $groups = $user.memberOf | ForEach-Object {
            ($_ -split ",")[0] -replace "^CN="
        }
        return $groups
    } catch {
        Write-Warning "No se pudo obtener los grupos de $Username"
        return @()
    }
}

function Is-AdminOnHost {
    param (
        [string]$Username,
        [string]$ComputerName
    )
    try {
        $group = Get-ADGroupMember -Identity "Administrators" -Server $ComputerName -ErrorAction Stop
        return $group.Name -contains $Username
    } catch {
        return $false
    }
}

function Has-SessionOnHost {
    param (
        [string]$Username,
        [string]$ComputerName
    )
    try {
        $sessions = quser /server:$ComputerName 2>$null
        return $sessions -match $Username
    } catch {
        return $false
    }
}

function Check-Techniques {
    param (
        [string]$Username,
        [string]$ComputerName
    )

    $Results = @()

    $groups = Get-UserGroups -Username $Username
    $isAdmin = Is-AdminOnHost -Username $Username -ComputerName $ComputerName
    $hasSession = Has-SessionOnHost -Username $Username -ComputerName $ComputerName

    $Results += [pscustomobject]@{
        Technique = "WMI"
        Available = if ($isAdmin) { "+" } else { "-" }
        Reason    = if ($isAdmin) { "Es admin local" } else { "No es admin local" }
    }

    $Results += [pscustomobject]@{
        Technique = "DCOM"
        Available = if ($isAdmin -and $hasSession) { "+" } elseif ($isAdmin) { "-" } else { "-" }
        Reason    = if ($isAdmin -and $hasSession) {
            "Admin local con sesion activa"
        } elseif ($isAdmin) {
            "Admin local sin sesion activa"
        } else {
            "No es admin local"
        }
    }

    $Results += [pscustomobject]@{
        Technique = "WinRM"
        Available = if ($isAdmin) { "+" } else { "-" }
        Reason    = if ($isAdmin) { "Es admin local" } else { "No es admin local" }
    }

    $Results += [pscustomobject]@{
        Technique = "PsExec"
        Available = if ($isAdmin) { "+" } else { "-" }
        Reason    = if ($isAdmin) { "Puede acceder a ADMIN$" } else { "No tiene acceso a ADMIN$" }
    }

    $Results += [pscustomobject]@{
        Technique = "Pass-the-Hash"
        Available = if ($isAdmin) { "+ (si tiene hash)" } else { "-" }
        Reason    = if ($isAdmin) { "Admin local necesario" } else { "Falta privilegio admin" }
    }

    $Results += [pscustomobject]@{
        Technique = "Overpass-the-Hash"
        Available = if ($groups -match "Domain Users") { "+ (si tiene hash)" } else { "-" }
        Reason    = "Requiere hash NTLM y kerberos"
    }

    $Results += [pscustomobject]@{
        Technique = "Pass-the-Ticket"
        Available = if ($isAdmin) { "+ (si tiene TGT)" } else { "-" }
        Reason    = "Requiere TGT y privilegios sobre SPN"
    }

    return $Results
}

$results = Check-Techniques -Username $FromUser -ComputerName $ToHost

$results | Format-Table -AutoSize
