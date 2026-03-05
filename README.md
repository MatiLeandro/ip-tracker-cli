# 🎯 IP Tracker CLI

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Una herramienta de reconocimiento de red (OSINT) por línea de comandos, ligera y desarrollada en Python nativo. No requiere librerías externas ni dependencias pesadas para funcionar.

## 🚀 Características (Features)

* **Rastreo de objetivo:** Obtiene el país, ciudad, y Proveedor de Servicios de Internet (ISP) de cualquier dirección IP pública.
* **Cero Dependencias:** Utiliza exclusivamente la biblioteca estándar de Python.
* **Validación Estricta (Zero Trust):** Incorpora un filtro de seguridad antes de la petición de red que bloquea automáticamente direcciones IP privadas (LAN), *loopback* y formatos inválidos para evitar fugas de datos.
* **Auto-reconocimiento:** Si se ejecuta sin argumentos, audita y devuelve los datos del nodo de salida público de la red actual.

## 🛠️ Instalación

Cloná el repositorio en tu máquina local:

```bash
git clone [https://github.com/MatiLeandro/ip-tracker-cli.git](https://github.com/MatiLeandro/ip-tracker-cli.git)
cd ip-tracker-cli
```

*(Opcional pero recomendado para sistemas UNIX)* Dale permisos de ejecución para usarlo como un script nativo:

```bash
chmod +x ip_tracker.py
```

## 💻 Uso

Ejecutá el script pasándole una dirección IPv4 pública como argumento:

```bash
python3 ip_tracker.py 8.8.8.8
```

Para verificar tu propia IP pública, ejecutá la herramienta sin argumentos:

```bash
python3 ip_tracker.py
```

## 🛡️ Mecanismos de Seguridad
El motor de validación interceptará consultas erróneas a nivel local:
* `python3 ip_tracker.py 192.168.1.1` -> `[!] The IP 192.168.1.1 is private or loopback`
* `python3 ip_tracker.py test` -> `[!] Invalid IP format: test`

## 📝 Licencia
Este proyecto está bajo la Licencia MIT.
