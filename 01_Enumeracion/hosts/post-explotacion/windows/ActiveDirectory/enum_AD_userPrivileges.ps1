param(
    [Parameter(Mandatory=$true)]
    [string]$UserName
)

# Importar PowerView si no está cargado
if (-not (Get-Command Get-DomainUser -ErrorAction SilentlyContinue)) {
    Import-Module "C:.\PowerView.ps1"
}

Write-Host "[*] Grupos del usuario ${UserName}:" -ForegroundColor Cyan
Get-DomainUser -Identity $UserName -Properties memberof | Select-Object -ExpandProperty memberof

Write-Host "[*] Enumerando sesiones activas, shares y roles del usuario ${UserName}..." -ForegroundColor Cyan

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
            if ($session.UserName -like "*${UserName}*") {
                $hasSessions = $true
            }
        }
    } catch {}

    try {
        $admins = Get-NetLocalGroup -ComputerName $computer -GroupName "Administrators" -ErrorAction Stop
        foreach ($admin in $admins) {
            if ($admin.MemberName -like "*${UserName}*") {
                $isAdmin = $true
            }
        }
    } catch {}

    try {
        $rdp = Get-NetLocalGroup -ComputerName $computer -GroupName "Remote Desktop Users" -ErrorAction Stop
        foreach ($member in $rdp) {
            if ($member.MemberName -like "*${UserName}*") {
                $isRDP = $true
            }
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

# Mostrar dónde el usuario actual tiene permisos de administrador local
Write-Host "`n[*] Buscando máquinas donde el usuario actual tiene privilegios de administrador local..." -ForegroundColor Cyan
try {
    $localAdminMachines = Find-LocalAdminAccess
    if ($localAdminMachines) {
        Write-Host "[+] Acceso de administrador local encontrado en:" -ForegroundColor Green
        $localAdminMachines | ForEach-Object { Write-Host "   $_" -ForegroundColor Green }
    } else {
        Write-Host "[-] No se encontraron accesos administrativos locales." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[-] Error al ejecutar Find-LocalAdminAccess" -ForegroundColor Red
}

# Opcional: Exportar a CSV
#$results | Export-Csv -Path "${UserName}_access_report.csv" -NoTypeInformation -Encoding UTF8
