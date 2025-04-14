# ADEnum.ps1

PowerShell script para la enumeración de Active Directory utilizando clases .NET sin requerir módulos externos. Diseñado para ser ejecutado en entornos comprometidos o para administración defensiva en sistemas Windows.

---

## 🚀 ¿Qué hace este script?

Este script modular te permite realizar:

- Enumeración de usuarios
- Enumeración de grupos
- Enumeración de usuarios y grupos críticos
- Análisis de relaciones entre usuarios y grupos (incluso anidados)

Todo esto desde un solo archivo `.ps1`, ideal para ambientes comprometidos.

---

## 📦 Funciones disponibles

### `Enum-ADUsers`
Lista los usuarios del dominio.

**Opciones:**
- `-ExpandGroups`: Muestra los grupos a los que pertenece cada usuario.
- `-HighlightCritical`: Resalta usuarios críticos como `Administrator`, `krbtgt`, etc.

### `Enum-ADGroups`
Lista los grupos del dominio.

**Opciones:**
- `-ExpandUsers`: Muestra los miembros de cada grupo.
- `-HighlightCritical`: Resalta grupos críticos como `Domain Admins` o `Enterprise Admins`.

### `Enum-ADCritical`
Atajo para listar usuarios y grupos críticos, resaltando los riesgos de privilegios elevados.

### `Enum-ADRelationships`
Muestra todas las relaciones:
- Usuarios → Grupos a los que pertenecen
- Grupos → Miembros

---

## 🛠️ Cómo usar

1. **Cargar el script:**
```powershell
. .\ADEnum.ps1
```

2. **Ejecutar una función:**
```powershell
Enum-ADUsers -ExpandGroups -HighlightCritical
Enum-ADGroups -ExpandUsers
Enum-ADRelationships
```

---

## 🎯 Caso práctico: ¿Resuelve este desafío?

**Desafío:**
> "Start VM Group 2 and log in to CLIENT75 as stephanie. Use the newly developed PowerShell script to enumerate the domain groups, starting with Service Personnel. Unravel the nested groups, then enumerate the attributes for the last direct user member of the nested groups to obtain the flag."

✅ **Sí, el script permite resolver esta consigna**, usando los siguientes pasos:

### ✅ Pasos sugeridos con `ADEnum.ps1`:
1. **Cargar el script:**
```powershell
. .\ADEnum.ps1
```

2. **Identificar miembros del grupo "Service Personnel" y sus subgrupos:**
```powershell
Enum-ADGroups -ExpandUsers
```
Busca el grupo `Service Personnel`, anota sus miembros. Si hay otros grupos dentro, repite manualmente el proceso para esos grupos.

3. **Para cada grupo anidado, obtener los miembros:**
```powershell
# Puedes ejecutar esta línea para ver miembros de un grupo anidado
([ADSI]'LDAP://CN=NestedGroupName,CN=Users,DC=corp,DC=com').member
```

4. **Cuando encuentres el usuario final (no grupo), muestra sus atributos:**
```powershell
$user = [ADSI]'LDAP://CN=FinalUser,CN=Users,DC=corp,DC=com'
$user.Properties
```

Ahí probablemente encuentres el flag en un atributo como `description`, `info` o uno personalizado.

---

## 🧠 Requisitos
- Windows PowerShell (preinstalado en sistemas Windows)
- El sistema debe estar unido a un dominio
- El usuario debe tener privilegios de lectura en el AD (por defecto cualquier usuario del dominio los tiene)

---

## 🔒 Uso ético
Este script está diseñado con fines educativos y administrativos. Úsalo bajo autorización o en entornos controlados (como laboratorios o CTFs).

---

## ✨ Autor
Hecho por [Tu nombre o alias] con colaboración de ChatGPT 🛠️

