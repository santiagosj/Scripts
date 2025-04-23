import os
import subprocess
from pathlib import Path
from InquirerPy import inquirer

BASE_PATH = Path(__file__).resolve().parent

PHASES = {
    "Reconocimiento": "00_Reconocimiento",
    "Enumeracion": "01_Enumeracion",
    "Explotacion": "02_Explotacion",
    "PostExplotacion": "03_PostExplotacion",
    "Pivoting": "04_Pivoting",
    "Limpieza": "05_Limpieza",
    "🧨 Modo Metasploit": "06_MSF-Runner"
}

def find_scripts_in_categories(phase_dir):
    """Devuelve un diccionario con categorías y sus scripts encontrados."""
    categorized = {}
    for category_path in sorted(Path(phase_dir).iterdir()):
        if category_path.is_dir():
            scripts = [f for f in category_path.rglob('*') if f.suffix in ['.py', '.sh', '.ps1']]
            if scripts:
                categorized[category_path.name] = scripts
    return categorized

def execute_script(script_path):
    ext = script_path.suffix
    try:
        if ext == '.py':
            subprocess.run(['python3', str(script_path)], check=True)
        elif ext == '.sh':
            subprocess.run(['bash', str(script_path)], check=True)
        elif ext == '.ps1':
            subprocess.run(['pwsh', '-File', str(script_path)], check=True)
        else:
            print(f"[!] Tipo de script no soportado: {ext}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al ejecutar {script_path.name}: {e}")

def launch_msf_runner():
    msf_script = BASE_PATH / "06_MSF-Runner" / "run_msf.py"
    if not msf_script.exists():
        print("[!] No se encontró el script run_msf.py de MSF-Runner.")
        return
    subprocess.run(['python3', str(msf_script)])

def main():
    phase = inquirer.select(
        message="Selecciona la fase del pentest:",
        choices=list(PHASES.keys())
    ).execute()

    if phase == "🧨 Modo Metasploit":
        launch_msf_runner()
        return

    phase_path = BASE_PATH / PHASES[phase]
    categorized_scripts = find_scripts_in_categories(phase_path)

    if not categorized_scripts:
        print("[!] No se encontraron scripts en esta fase.")
        return

    category = inquirer.select(
        message=f"Selecciona una categoría dentro de {phase}:",
        choices=list(categorized_scripts.keys())
    ).execute()

    scripts = categorized_scripts[category]
    script = inquirer.select(
        message="Selecciona el script a ejecutar:",
        choices=[str(s.relative_to(BASE_PATH)) for s in scripts]
    ).execute()

    selected_script = BASE_PATH / script
    print(f"\n[+] Ejecutando: {selected_script}\n")
    execute_script(selected_script)

if __name__ == "__main__":
    main()
