# ADEnum.ps1

PowerShell script modular para la enumeración de Active Directory combinando clases .NET con funcionalidades extendidas vía PowerView (si está presente). Diseñado para ser ejecutado en entornos comprometidos o para administración defensiva en sistemas Windows.

---

## 🚀 ¿Qué hace este script?

Este script integral te permite realizar:

- **Enum-ADUsers**: Enumeración de usuarios.
- **Enum-ADGroups**: Enumeración de grupos.
- **Enum-ADCritical**: Listado combinado de usuarios y grupos críticos.
- **Enum-ADRelationships**: Análisis de relaciones usuario → grupo y grupo → miembros.
- **Get-GroupUserChain**: Cadena de pertenencia recursiva de un grupo.
- **Enum-ADUserDeepRecon**: Reconocimiento profundo de un usuario (PowerView).
- **Enum-ADObjectPermissions**: Enumeración de ACLs y privilegios sobre un objeto AD.
- **Funciones adicionales**: Operaciones avanzadas como exportar datos, explorar OU, dominios de confianza, permisos, etc.

---

## 📦 Funciones principales

### Funciones base (.NET puro, sin dependencias externas)

- **Invoke-LDAPQuery**: Función interna que ejecuta consultas LDAP genéricas.

- **Enum-ADUsers** (`-ExpandGroups`, `-HighlightCritical`)
  - Lista todos los usuarios del dominio.
  - Opcional: expande grupos y resalta usuarios críticos (`Administrator`, `krbtgt`).

- **Enum-ADGroups** (`-ExpandUsers`, `-HighlightCritical`)
  - Lista todos los grupos del dominio.
  - Opcional: expande miembros y resalta grupos críticos (`Domain Admins`, `Enterprise Admins`).

- **Enum-ADCritical**
  - Atajo que ejecuta `Enum-ADUsers -ExpandGroups -HighlightCritical` y `Enum-ADGroups -ExpandUsers -HighlightCritical`.

- **Enum-ADRelationships**
  - Muestra relaciones:
    - Usuario → Grupos a los que pertenece.
    - Grupo → Miembros.

- **Get-GroupUserChain** (`-GroupName <NombreGrupo>`)
  - Despliega recursivamente la estructura de pertenencia de un grupo, mostrando usuarios y subgrupos.

### Funciones extendidas (PowerView)

> Solo disponibles si PowerView está importado o presente en el directorio.

- **Enum-ADUserDeepRecon** (`-UserName <usuario>`)
  - Analiza a profundidad un usuario usando PowerView: grupos, sesiones activas, membresía local, shares accesibles, ACLs filesystem, etc.

- **Enum-ADObjectPermissions** (`-TargetName <objeto>`)
  - Enumera ACLs/ACEs de un usuario o grupo en AD.
  - Resalta permisos críticos (`GenericAll`, `WriteDACL`, `ForceChangePassword`, etc.).

---

## ⚙️ Funciones adicionales incluidas

1. ### Get-ADGroupMembers
   - **Responsabilidad:** Obtiene los miembros de un grupo específico.
   - **Uso:** `Get-ADGroupMembers -GroupName "GroupName"`
   - **Descripción:** Devuelve lista de usuarios y subgrupos dentro del grupo indicado.

2. ### Get-ADUserGroups
   - **Responsabilidad:** Obtiene todos los grupos de un usuario.
   - **Uso:** `Get-ADUserGroups -UserName "username"`
   - **Descripción:** Lista recursivamente los grupos a los que pertenece el usuario.

3. ### Get-ADGroupMembership
   - **Responsabilidad:** Relación de pertenencia de un usuario a grupos, incluidos anidados.
   - **Uso:** `Get-ADGroupMembership -UserName "username"`
   - **Descripción:** Analiza recursivamente los grupos del usuario.

4. ### Get-GroupMemberChain
   - **Responsabilidad:** Cadena de pertenencia de grupos de manera recursiva.
   - **Uso:** `Get-GroupMemberChain -GroupName "GroupName"`
   - **Descripción:** Visualiza jerárquicamente conexiones entre usuarios y grupos.

5. ### Get-ADUserProperties
   - **Responsabilidad:** Obtiene propiedades detalladas de un usuario.
   - **Uso:** `Get-ADUserProperties -UserName "username"`
   - **Descripción:** Muestra atributos como nombre, correo, SID, miembro de, etc.

6. ### Get-ADGroupProperties
   - **Responsabilidad:** Obtiene propiedades de un grupo.
   - **Uso:** `Get-ADGroupProperties -GroupName "GroupName"`
   - **Descripción:** Devuelve SID, miembros y atributos del grupo.

7. ### Get-ADDomainInfo
   - **Responsabilidad:** Información general del dominio AD.
   - **Uso:** `Get-ADDomainInfo`
   - **Descripción:** Controladores de dominio, nivel funcional, esquema, etc.

8. ### Get-ADOUStructure
   - **Responsabilidad:** Estructura de Unidades Organizativas (OU).
   - **Uso:** `Get-ADOUStructure`
   - **Descripción:** Lista OUs y su jerarquía.

9. ### Get-ADTrusts
   - **Responsabilidad:** Dominios de confianza.
   - **Uso:** `Get-ADTrusts`
   - **Descripción:** Muestra relaciones de confianza entre dominios.

10. ### Get-ADPermissions
    - **Responsabilidad:** Obtiene ACLs de objetos AD (GenericAll, WriteOwner, etc.).
    - **Uso:** `Get-ADPermissions -ObjectName "ObjectName"`
    - **Descripción:** Identifica permisos sobre usuarios o grupos.

11. ### Export-ADDataToCSV
    - **Responsabilidad:** Exporta datos de AD a CSV.
    - **Uso:** `Export-ADDataToCSV -DataType "Users" -FilePath "C:\ruta\archivo.csv"`
    - **Descripción:** Genera archivo CSV con información extraída para documentación.

---

## 🛠 Cómo usar

1. **Cargar el script**
    ```powershell
    . .\ADEnum.ps1
    ```
2. **Ver ayuda**
    ```powershell
    .\ADEnum.ps1 -Help
    ```
3. **Ejecutar funciones**
    ```powershell
    Enum-ADUsers -ExpandGroups -HighlightCritical
    Enum-ADGroups -ExpandUsers
    Get-GroupUserChain -GroupName "Service Personnel"
    Enum-ADUserDeepRecon -UserName "jdoe"
    Export-ADDataToCSV -DataType "Groups" -FilePath "C:\temp\grupos.csv"
    ```

---

## 🎯 Caso práctico

> "Start VM Group 2 and log in to CLIENT75 as stephanie. Usa el script para enumerar grupos del dominio, inicia con `Service Personnel`, desentraña grupos anidados y luego enumera atributos del último usuario directo para obtener la flag."

✅ **Pasos con `ADEnum.ps1`:**

1. `. .\ADEnum.ps1`
2. `Enum-ADGroups -ExpandUsers` → Localiza `Service Personnel` y anota subgrupos.
3. `Get-GroupUserChain -GroupName "Service Personnel"` → Visualiza cadena completa.
4. Identifica usuario final y ejecuta:
   ```powershell
   Enum-ADUserDeepRecon -UserName "FinalUser"
   ```
5. Revisa `description`, `info` u otro atributo para encontrar la flag.

---

## 🧠 Requisitos

- Windows PowerShell (incluido en Windows).
- Conexión al dominio AD.
- Privilegios de lectura en AD (por defecto cualquier usuario de dominio).

---

## 🔒 Uso ético

Este script es para fines educativos, CTFs y administración defensiva. Úsalo únicamente con autorización o en entornos controlados.

