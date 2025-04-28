# AS-REP Roasting - FelixBag Module

## 🧠 Qué es

AS-REP Roasting permite obtener hashes Kerberos de usuarios que tienen deshabilitada la preautenticación. Estos hashes se pueden crackear offline (John, Hashcat).

---

## 🛠️ Requisitos

### PowerShell Script:
- Debes tener PowerShell en una máquina Windows con acceso al DC.
- Usuario con permisos estándar.

### Python Script:
- Python 3 + Impacket instalado
- Acceso de red al Domain Controller (TCP/88)
- Lista de posibles usuarios roastables

---

## 🚀 Uso

### Desde PowerShell en una máquina comprometida:

```powershell
.\Invoke-ASREPRoast.ps1
```
### Desde kali

```bash
python3 asreproast.py yourdomain.local users.txt -dc-ip 10.10.10.5
```
