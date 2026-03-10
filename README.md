# 🎯 IP Tracker CLI

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![OSINT](https://img.shields.io/badge/Category-OSINT-red.svg)](https://github.com/topics/osint)

Una herramienta de reconocimiento de red (OSINT) y Threat Intelligence por línea de comandos. Desarrollada en Python puro, sin librerías de terceros (Zero Dependencies).

## 🚀 Características (Features)

* **Rastreo Profundo:** Obtiene país, región, ciudad, coordenadas exactas (Lat/Lon), Organización (ORG) y Proveedor de Internet (ISP).
* **Resolución DNS Integrada:** Acepta tanto direcciones IP como nombres de dominio (Hostnames). El motor resuelve los dominios automáticamente antes de rastrearlos.
* **Exportación de resultados (-o):** Genera reportes estructurados en formatos .csv o .json con marcas de tiempo (timestamps) automáticas para integrar con SIEMs o Excel.
* **Motor Multi-API (--api):** Implementa un Patrón Adaptador soportando múltiples motores de búsqueda (ipwhois vía TLS por defecto, o ipapi para mayor velocidad).
* **Inteligencia de Amenazas (Threat Intel):** Analiza recursivamente el ISP y la ORG contra listas negras (blacklists) personalizables para detectar Datacenters, VPNs o nodos de salida Tor.
* **Cero Dependencias:** Utiliza exclusivamente la biblioteca estándar de Python (urllib, json, csv, socket, ipaddress).
* **UX/UI Ligeramente customizada:** Interfaz de terminal jerarquizada con códigos de color ANSI nativos para alertas críticas y estado de ejecución.
* **Protección del Analista (OpSec):** Bloquea escaneos accidentales a redes locales (LAN/Loopback) e implementa advertencias interactivas antes de exponer la IP del usuario o usar APIs sin cifrado.

## 🛠️ Instalación

Cloná el repositorio en tu máquina local:

``` bash
git clone https://github.com/MatiLeandro/ip-tracker-cli.git
cd ip-tracker-cli
```

*(Opcional pero recomendado para sistemas UNIX)* Dale permisos de ejecución:

``` bash
chmod +x ip_tracker.py
```

## 💻 Uso

El script utiliza el módulo nativo argparse. Para ver el menú completo de ayuda:

``` bash
python3 ip_tracker.py -h
```

### 1. Rastreo Individual (Dominios o IPs)

``` bash
python3 ip_tracker.py -i scanme.nmap.org
python3 ip_tracker.py -i 8.8.8.8
```

### 2. Análisis Masivo y Exportación a CSV
Ideal para procesar listas de IPs extraídas de logs. Generará un archivo tracker_report_YYYYMMDD_HHMMSS.csv.

``` bash
python3 ip_tracker.py -f atacantes.txt -o csv
```

### 3. Cambiar el Motor de API y Exportar a JSON

``` bash
python3 ip_tracker.py -i 1.1.1.1 --api ipapi -o json
```

### 4. Threat Intel con Lista Personalizada y Modo Debug
Inyectá tu propia lista de ISPs sospechosos (ej. mis_isps.txt) y usá -v para ver el JSON crudo de la API.

``` bash
python3 ip_tracker.py -i 8.8.8.8 -b mis_isps.txt -v
```

*(Si no usas -b, el script utilizará una lista robusta interna por defecto).*

Para verificar tu propia huella pública (requiere confirmación interactiva), ejecutá:

``` bash
python3 ip_tracker.py
```

## 🛡️ Mecanismos de Seguridad y OpSec
El motor interceptará configuraciones riesgosas o erróneas en tiempo de ejecución:
* Escaneo de red local: [!] The IP 192.168.1.1 is private or loopback
* Formato inválido: [!] Invalid IP format
* Dominio caído: [!] Unable to resolve hostname
* Advertencia interactiva al usar --api ipapi (HTTP sin TLS).

## 📝 Licencia
Este proyecto está bajo la Licencia MIT.
