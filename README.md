# 🎯 IP Tracker CLI

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Una herramienta de reconocimiento de red (OSINT) por línea de comandos, ligera y desarrollada en Python nativo. No requiere librerías externas ni dependencias pesadas para funcionar.

## 🚀 Características (Features)

* **Rastreo de objetivo:** Obtiene el país, ciudad, y Proveedor de Servicios de Internet (ISP) de cualquier dirección IP pública.
* **Cero Dependencias:** Utiliza exclusivamente la biblioteca estándar de Python.
* **Validación Estricta (Zero Trust):** Incorpora un filtro de seguridad que bloquea automáticamente direcciones IP privadas (LAN), *loopback* y formatos inválidos.
* **Inteligencia de Amenazas (Threat Intel):** Detecta automáticamente si la IP pertenece a un proveedor de nube, hosting o VPN (AWS, Azure, Tor, etc.).
* **Análisis Masivo y Modularidad:** Permite analizar listas de IPs desde un archivo de texto e inyectar tus propias listas negras (blacklists) de ISPs sospechosos.

## 🛠️ Instalación

Cloná el repositorio en tu máquina local:

```bash
git clone [https://github.com/MatiLeandro/ip-tracker-cli.git](https://github.com/MatiLeandro/ip-tracker-cli.git)
cd ip-tracker-cli
```

*(Opcional pero recomendado para sistemas UNIX)* Dale permisos de ejecución:

```bash
chmod +x ip_tracker.py
```

## 💻 Uso

El script utiliza argumentos mediante el módulo `argparse`. Para ver el menú de ayuda, ejecutá:

```bash
python3 ip_tracker.py -h
```

### 1. Rastreo Individual
```bash
python3 ip_tracker.py -i 8.8.8.8
```

### 2. Análisis Masivo (Logs)
```bash
python3 ip_tracker.py -f atacantes.txt
```

### 3. Threat Intel con Lista Personalizada
Si tenés tu propia lista de ISPs sospechosos (ej. `mis_isps.txt`), podés inyectarla con la bandera `-b`:
```bash
python3 ip_tracker.py -i 8.8.8.8 -b mis_isps.txt
```

*(Si no usas `-b`, el script utilizará una lista PoC interna por defecto).*

Para verificar tu propia IP pública (nodo de salida), ejecutá la herramienta sin argumentos:
```bash
python3 ip_tracker.py
```

## 🛡️ Mecanismos de Seguridad
El motor de validación interceptará consultas erróneas a nivel local:
* `python3 ip_tracker.py -i 192.168.1.1` -> `[!] The IP 192.168.1.1 is private or loopback`
* `python3 ip_tracker.py -i test` -> `[!] Invalid IP format: test`

## 📝 Licencia
Este proyecto está bajo la Licencia MIT.
