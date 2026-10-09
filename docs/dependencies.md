# Inventario de dependencias

Comprobado en el entorno Linux local el 2026-10-09. Los nueve paquetes directos de Python aparecen en [`requirements.txt`](../requirements.txt). Los 63 paquetes con versiones fijadas en [`requirements-lock.txt`](../requirements-lock.txt) están instalados en `.venv` con esas versiones exactas. `pip check` no encontró dependencias incompatibles. `pip` está instalado en `.venv`, pero no aparece fijado en el lockfile.

| Paquete directo | Función | En `requirements.txt` | En lockfile | En `.venv` |
|---|---|---|---|---|
| requests 2.34.2 | Solicitudes HTTP a GitHub y OpenRouter | Sí | Sí | Sí |
| pydantic 2.13.5 | Modelos de evidencia e informes | Sí | Sí | Sí |
| pytest 9.1.1 | Pruebas | Sí | Sí | Sí |
| typer 0.27.2 | Interfaz de terminal | Sí | Sí | Sí |
| nbformat 5.11.1 | Creación del notebook | Sí | Sí | Sí |
| nbclient 0.11.0 | Ejecución del notebook | Sí | Sí | Sí |
| jupyter_client 8.10.0 | Gestiona el kernel con cifrado CurveZMQ obligatorio | Sí | Sí | Sí |
| ipykernel 7.4.0 | Kernel de Python del notebook | Sí | Sí | Sí |
| matplotlib 3.11.2 | Gráficos del notebook | Sí | Sí | Sí |

Los otros **54 paquetes Python** son dependencias indirectas. Todos están fijados en el lockfile e instalados en `.venv`, pero ninguno se declara directamente en `requirements.txt`.

`annotated-doc`, `annotated-types`, `asttokens`, `attrs`, `certifi`, `charset-normalizer`, `comm`, `contourpy`, `cycler`, `debugpy`, `executing`, `fastjsonschema`, `fonttools`, `idna`, `iniconfig`, `ipython`, `ipython_pygments_lexers`, `jedi`, `jsonschema`, `jsonschema-specifications`, `jupyter_core`, `kiwisolver`, `markdown-it-py`, `matplotlib-inline`, `mdurl`, `nest-asyncio2`, `numpy`, `packaging`, `parso`, `pexpect`, `pillow`, `platformdirs`, `pluggy`, `prompt_toolkit`, `psutil`, `ptyprocess`, `pure_eval`, `pydantic_core`, `Pygments`, `pyparsing`, `python-dateutil`, `pyzmq`, `referencing`, `rich`, `rpds-py`, `shellingham`, `six`, `stack-data`, `tornado`, `traitlets`, `typing-inspection`, `typing_extensions`, `urllib3`, `wcwidth`.

| Otra dependencia | Función y ubicación | En `requirements.txt` / lockfile | Estado local |
|---|---|---|---|
| Python 3.14.4 | Intérprete anfitrión con `.venv` del proyecto | No / No | Disponible en `.venv` |
| Tkinter y Tcl/Tk 8.6.17 | GUI copiada a `.venv/lib/tkinter-local/` por `support/scripts/install_tkinter.py` | No / No | Instalado; Tcl funciona |
| Git 2.53.0 | Descarga revisiones fijadas | No / No | Disponible en el sistema |
| CodeQL 2.25.5 | Análisis de código; `.tools/codeql/` | No / No | Instalado con paquetes de consultas |
| Syft 1.52.0 | Genera SBOM CycloneDX; `.tools/syft/` | No / No | Instalado localmente |
| Grype 0.119.0 | Busca vulnerabilidades en el SBOM; `.tools/grype/` | No / No | Instalado; caché en `.cache/grype/` |
| Node.js 22.23.3 | Extracción de TypeScript de CodeQL; `.tools/node/` | No / No | Instalado localmente |
| `apt-cache`, `apt-get`, `dpkg-deb` | Instalador local de Tkinter | No / No | Disponibles en el sistema |
| `curl`, `xz`, `tar` y certificados CA | Dev Container e instaladores | No / No | Incluidos en el contenedor; disponibles localmente |
| Pantalla gráfica | Solo GUI; `--no-gui` no la necesita | No / No | `DISPLAY` y `WAYLAND_DISPLAY` configuradas; no se comprobó la ventana |
| Clave API de OpenRouter | Reporter real opcional, sin SDK específico | No / No | Se entrega mediante `OPENROUTER_API_KEY` al ejecutar |

CodeQL, Syft, Grype y Node se instalan mediante [`support/scripts/`](../support/scripts/), no con pip. El Dockerfile de la raíz ejecuta esos instaladores al construir la imagen: las herramientas quedan en `/opt/icc610/.tools` y los paquetes Python en `/opt/icc610/venv`. El proyecto montado conserva su propio caché de Grype. Para la instalación local sin Docker, `.tools/`, `.cache/` y `.venv/` se recrean con los pasos del README y Git los ignora.
