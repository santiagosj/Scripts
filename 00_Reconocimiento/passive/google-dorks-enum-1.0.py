import requests
from bs4 import BeautifulSoup
import urllib.parse

# Configuracion basica
target = input("Ingrese el dominio o palabra clave del objetivo: ")

dorks = {
    "Archivos sensibles": [
        f"site:{target} filetype:pdf",
        f"site:{target} filetype:doc",
        f"site:{target} intitle:index.of"
    ],
    "Subdominios": [
        f"site:{target} -www",
        f"site:*.{target}"
    ],
    "Usuarios en redes sociales": [
        f"site:twitter.com {target}",
        f"site:linkedin.com {target}",
        f"site:facebook.com {target}"
    ],
    "Infraestructura": [
        f"site:{target} inurl:admin",
        f"site:{target} intitle:\"index of /\""
    ],
    "Stack tecnologico": [
        f"site:{target} ext:conf",
        f"site:{target} ext:ini",
        f"site:{target} ext:log"
    ],
    "Vulnerabilidades comunes": [
        f"site:{target} ext:php intitle:phpinfo \"published by the PHP Group\"",
        f"site:{target} inurl:login intext:password",
        f"site:{target} filetype:env"
    ]
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Funcion para buscar en Google
def google_search(query):
    url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        results = []
        for g in soup.find_all('div', class_='BVG0Nb'):
            link = g.find('a')
            if link and link['href']:
                results.append(link['href'])
        return results
    else:
        return ["Error en la solicitud"]

# Ejecucion de Dorks
for categoria, queries in dorks.items():
    print(f"\n[+] {categoria}")
    for query in queries:
        print(f"\nDork: {query}")
        resultados = google_search(query)
        for resultado in resultados:
            print(f" - {resultado}")
