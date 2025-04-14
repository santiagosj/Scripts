##############################################
# ADEnum.ps1 - Módulo de enumeración AD      #
# Usable en máquinas Windows comprometidas   #
# Autor Intelectual: duckman_42              #
##############################################

# Función base interna para consultas LDAP
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

# Función pública: Enumera usuarios + grupos
function Enum-ADUsers {
    param (
        [switch]$ExpandGroups,
        [switch]$HighlightCritical
    )
    Invoke-LDAPQuery -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -ExpandRelationships:$ExpandGroups -HighlightCritical:$HighlightCritical
}

# Función pública: Enumera grupos + miembros
function Enum-ADGroups {
    param (
        [switch]$ExpandUsers,
        [switch]$HighlightCritical
    )
    Invoke-LDAPQuery -LDAPFilter "(objectClass=group)" -ExpandRelationships:$ExpandUsers -HighlightCritical:$HighlightCritical
}

# Función pública: Enumera usuarios y grupos críticos
function Enum-ADCritical {
    Enum-ADUsers -ExpandGroups -HighlightCritical
    Enum-ADGroups -ExpandUsers -HighlightCritical
}

# Función pública: Relaciones entre usuarios y grupos
function Enum-ADRelationships {
    Write-Host "\nRelaciones Usuario → Grupos:`n" -ForegroundColor Magenta
    $users = Invoke-LDAPQuery -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -ExpandRelationships

    Write-Host "\nRelaciones Grupo → Miembros:`n" -ForegroundColor Magenta
    $groups = Invoke-LDAPQuery -LDAPFilter "(objectClass=group)" -ExpandRelationships
}


# Función publica: Cadena de grupos y miembros anidados
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

# Banner opcional
Write-Host "\n[+] Módulo ADEnum.ps1 cargado. Usa Enum-ADUsers / Enum-ADGroups / Enum-ADCritical / Enum-ADRelationships" -ForegroundColor Gray
