# 🔥 FelixBag - Kerberoasting

> Extrae hashes de tickets TGS asociados a SPNs configurados en cuentas de dominio. Técnica clásica para escalar privilegios.

---

## 🤔 ¿Qué es Kerberoasting?

Cuando un usuario de dominio solicita un ticket TGS para un SPN (por ejemplo, SQLSvc/acme.local), Kerberos entrega un ticket cifrado con la clave NTLM del servicio. 
Si capturamos ese ticket, podemos crackearlo offline.

---

## 🧠 Requisitos

- Usuario de dominio válido
- [Impacket](https://github.com/fortra/impacket)
- Acceso al puerto 88 del DC

---

## ⚙️ Uso

```bash
python3 kerberoast.py acme.local juanito P@ssw0rd! -dc-ip 10.10.10.5 -output spn_hashes.txt
```
