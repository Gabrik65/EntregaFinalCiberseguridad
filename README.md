# Análisis de seguridad de repositorios de GitHub

Este proyecto semestral analiza repositorios públicos de una organización de GitHub. **Miner** descarga revisiones fijadas y ejecuta CodeQL, Syft y Grype. **Analyzer** valida la evidencia, calcula estadísticas y genera un notebook ejecutable. **Visualizer** crea un panel HTML autónomo. **Reporter** analiza el propio repositorio del proyecto, incluido el JavaScript del panel, y genera un informe Markdown/JSON validado, con una simulación determinista o un modelo de OpenRouter.

La organización predeterminada es [NestJS](https://github.com/nestjs) y el límite configurado es **50 repositorios**; para una prueba breve puedes usar 5. Miner selecciona hasta ese límite entre los repositorios públicos no archivados y no forks, ordenados por fecha de actualización, fija sus commits y guarda la selección dentro de la ejecución. En una consulta exploratoria del 9 de octubre de 2026 se observaron 51 repositorios elegibles; la muestra evaluada se limitará a 50. La cantidad puede cambiar antes de la próxima ejecución. La categoría de cada repositorio corresponde al lenguaje principal informado por GitHub. La [especificación P1](docs/Especificación%20del%20proyecto%20P1.txt) exige entre **20 y 50 repositorios**.

## Requisitos

El [inventario de dependencias](docs/dependencies.md) distingue paquetes de Python, herramientas externas, Tkinter y utilidades del sistema.

- **Con Docker:** Docker Engine o Docker Desktop con Compose, acceso a Internet para construir la imagen y espacio suficiente para las herramientas y la base de vulnerabilidades. No es necesario instalar Python, CodeQL, Syft, Grype ni Node.js en el anfitrión.
- **Para la GUI en Linux:** una sesión gráfica X11 activa y la variable `DISPLAY` disponible. La ejecución con `--no-gui` funciona sin pantalla. El Dev Container está pensado principalmente para usarlo desde la terminal.
- **Para la instalación local sin Docker:** Ubuntu 26.04 x86_64, Python 3.14, Git, Internet y espacio suficiente para análisis y bases de datos. El instalador local de Tkinter usa `apt-cache`, `apt-get download` y `dpkg-deb` sin `sudo`.
- **Para Reporter con un modelo real:** una clave de OpenRouter. Sin ella, Reporter usa una simulación identificada explícitamente.

Docker incluye Python 3.14, CodeQL 2.25.5, Syft 1.52.0, Grype 0.119.0, Node.js 22.23.3, Git, Tkinter y las bibliotecas de Python fijadas. Node.js permite la extracción de TypeScript de CodeQL. En la instalación local, Tkinter y sus bibliotecas Tcl/Tk se copian dentro de `.venv/lib/tkinter-local/`, sin instalar la GUI para todo el sistema.

## Configuración con Docker

El [Dockerfile](Dockerfile) construye la imagen. [compose.yaml](compose.yaml) monta este proyecto en `/workspace`, por lo que `runs/`, `results/` y el caché de Grype sobreviven a nuevos contenedores. El Dev Container utiliza el mismo Dockerfile.

Desde la raíz del proyecto en una terminal Linux:

```bash
docker compose build
docker compose run --rm analysis
```

`docker compose build` solo crea la imagen y termina; no abre el programa. El segundo comando abre la GUI normal de `main.py` mediante X11. Compose transmite `DISPLAY` y monta el socket X11. La GUI comienza con un límite de 50 repositorios; cámbialo a 5 antes de pulsar **Ejecutar todo** o **Miner** si quieres una prueba breve. Cuando hay una ejecución activa, cerrar la ventana pide confirmación; si confirmas, la ejecución se interrumpe y puede dejar resultados parciales.

La primera construcción descarga las herramientas y la base de Grype. El instalador ajusta permisos de lectura de las consultas QLX de CodeQL para el usuario de Compose; el preflight comprueba esos permisos antes de analizar. Al iniciar un análisis, el contenedor copia la base inicial al caché persistente del proyecto y la actualiza si es inválida. Los resultados aparecen en `runs/` y `results/` del anfitrión.

Para ejecutar el flujo completo desde la terminal, sin GUI:

```bash
docker compose run --rm analysis python main.py --no-gui --organization nestjs --limit 50 --timeout 900
```

Puedes reemplazar `--limit 50` por `--limit 5` durante el desarrollo. Para abrir una terminal interactiva dentro del contenedor:

```bash
docker compose run --rm analysis bash
```

Las fases también pueden ejecutarse en contenedores separados. Usa el **mismo** directorio `--run` para Miner, Analyzer y Visualizer:

```bash
docker compose run --rm analysis python main.py mine --run runs/nestjs-final --timeout 900
docker compose run --rm analysis python main.py analyze --run runs/nestjs-final
docker compose run --rm analysis python main.py visualize --run runs/nestjs-final
docker compose run --rm analysis python main.py export --run runs/nestjs-final --destination results/nestjs-final
```

Antes de la corrida de 50, comprueba CodeQL con un repositorio TypeScript en una ruta separada. La selección y su commit quedan guardados para repetirla. El instalador entrega las consultas precompiladas legibles para el UID de Compose; el preflight exige al menos **8 GiB** de memoria para el contenedor. CodeQL usa un hilo y 6144 MiB. Si la prueba termina con `codeql=failed`, revisa `runs/codeql-smoke/records/001.json` y los archivos de `runs/codeql-smoke/raw/` antes de iniciar la muestra completa.

```bash
docker compose run --rm analysis python main.py select --organization nestjs --count 1 --output runs/codeql-smoke-selection.json
docker compose run --rm analysis python main.py mine --manifest runs/codeql-smoke-selection.json --run runs/codeql-smoke --timeout 900
docker compose run --rm analysis python -c 'import json; p=json.load(open("runs/codeql-smoke/records/001.json")); print(p["repository"], [(t["tool"],t["status"],t.get("error")) for t in p["tools"]])'
```

Tras comprobar CodeQL, ejecuta la muestra evaluada en `runs/nestjs/` con el límite de 50. Luego ejecuta `analyze`, `visualize` y `export` con esa misma ruta. En el notebook y el panel, las comparaciones por categoría indican cuántos repositorios completaron CodeQL o Grype; fallos y análisis no compatibles siguen en el denominador.

```bash
docker compose run --rm analysis python main.py mine --run runs/nestjs --timeout 900
docker compose run --rm analysis python main.py analyze --run runs/nestjs
docker compose run --rm analysis python main.py visualize --run runs/nestjs
docker compose run --rm analysis python main.py export --run runs/nestjs --destination results/nestjs-evaluated
```

Con `OPENROUTER_API_KEY` y `OPENROUTER_MODEL` configurados según la sección siguiente, genera el informe real en una ruta separada, expórtalo y produce la plantilla del afiche desde las cifras de la corrida evaluada:

```bash
docker compose run --rm analysis python main.py report --source . --run runs/reporter-openrouter --llm openrouter --timeout 900
docker compose run --rm analysis python main.py export --run runs/reporter-openrouter --destination results/reporter-openrouter
docker compose run --rm analysis python main.py poster --run runs/nestjs --reporter-run runs/reporter-openrouter --destination results/presentacion
```

El subcomando `mine` usa [data/run-config.json](data/run-config.json), cuyo límite predeterminado es 50. Reporter analiza este proyecto de forma independiente:

```bash
docker compose run --rm analysis python main.py report --source . --run runs/reporter-simulado --llm simulated
```

Para generar un informe real, configura OpenRouter en la terminal antes de iniciar Docker y usa un **directorio de ejecución nuevo**:

```bash
docker compose run --rm analysis python main.py report --source . --run runs/reporter-openrouter --llm openrouter
```

Compose solo transmite `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` y `GITHUB_TOKEN` si están configuradas en la terminal que lo ejecuta. No se guardan en la imagen. Docker incluye Tkinter, pero no un navegador. Al generar el HTML, la GUI muestra su ruta relativa a la raíz del proyecto. Como Compose monta el proyecto en `/workspace`, esa misma ruta sirve desde el anfitrión Linux.

Si el ID del usuario anfitrión no es 1000, configura `LOCAL_UID` y `LOCAL_GID` con los valores de `id -u` e `id -g` antes de usar Compose, para que los archivos generados pertenezcan a ese usuario. Reconstruye la imagen después de cambiar el Dockerfile, el código instalado en la imagen o las dependencias.

## Configuración local en Ubuntu, sin Docker

Desde la raíz del proyecto:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python support/scripts/install_codeql.py
.venv/bin/python support/scripts/install_scanners.py
.venv/bin/python support/scripts/install_node.py
.venv/bin/python support/scripts/install_tkinter.py
.venv/bin/python main.py update-db
```

El instalador de Tkinter verifica los hashes SHA-256 publicados por APT y copia los archivos necesarios dentro de `.venv` sin pedir permisos de administrador. Si solo usarás `--no-gui`, puedes omitir ese instalador. Las otras herramientas se guardan en `.tools/` y la base de Grype en `.cache/`; Git ignora estos directorios. Puedes recrear el [entorno virtual](https://docs.python.org/3/library/venv.html) con los comandos anteriores.

El Dev Container construye el Dockerfile de la raíz y permite ejecutar los comandos de terminal. No ofrece una sesión gráfica de forma predeterminada. La selección inicial de NestJS consulta la API de GitHub. Si aparece HTTP 403 por el límite de solicitudes, configura `GITHUB_TOKEN` en la terminal antes de iniciar el programa; el token no se guarda en el manifiesto ni se entrega a los escáneres.

## Configuración de OpenRouter

Ejecuta lo siguiente en la **misma terminal Bash** desde la que iniciarás Docker o Python. La clave se lee sin mostrarla ni ponerla en el historial:

```bash
read -rsp 'Clave API de OpenRouter: ' OPENROUTER_API_KEY && echo && export OPENROUTER_API_KEY
export OPENROUTER_MODEL='openai/gpt-4o-mini'
```

La GUI muestra siempre el primer comando en una caja de **solo lectura**; no intenta indicar si la clave ya está configurada. Debes ejecutar el comando en la terminal y luego iniciar o reiniciar la GUI desde esa misma terminal. `OPENROUTER_MODEL` es opcional en la GUI y con `--no-gui`, que usan el modelo predeterminado si falta; el subcomando `report --llm openrouter` requiere `OPENROUTER_MODEL` o `--model`.

El cliente envía a la [API de OpenRouter](https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request) una selección acotada de evidencia y señales de configuración, no los archivos fuente completos. La respuesta se comprueba contra las cifras calculadas y los IDs de evidencia conocidos antes de guardar el informe. No incluyas la clave en el código, argumentos, resultados ni commits. Al terminar, puedes ejecutar `unset OPENROUTER_API_KEY` en esa terminal.

## Uso local con GUI

```bash
.venv/bin/python main.py
```

La organización `nestjs` aparece en una caja de solo lectura y el límite empieza en **50**. Es un límite superior: si hay menos repositorios elegibles, se seleccionan los disponibles.

**Ejecutar todo** inicia Miner → Analyzer → Visualizer y luego Reporter. **Miner** y **Ejecutar todo** usan la misma ruta activa, `runs/nestjs/`. Si coinciden los nombres de repositorio, sus commits y la configuración de las herramientas, Miner verifica y reutiliza los registros existentes y continúa los pendientes; si cambian, reemplaza la ejecución activa. Ya no hay una lista de ejecuciones: la GUI consulta automáticamente esa ruta, también después de cerrarse y volver a abrirse. **Actualizar estado** detecta cambios hechos desde la terminal. **Analyzer** se habilita cuando Miner registró todos los repositorios elegidos, aunque alguna herramienta haya fallado; al ejecutarse verifica los artefactos y genera el notebook. **Visualizer** se habilita cuando existen los datos y el notebook de Analyzer y crea el HTML. **Reporter** está disponible por separado y analiza exclusivamente este proyecto. Solo se inicia una fase a la vez. Cuando el HTML está listo, el registro de la GUI muestra su ruta dentro del proyecto.

## Uso local solo con terminal

Un comando ejecuta el flujo completo sin importar Tkinter:

```bash
.venv/bin/python main.py --no-gui --organization nestjs --limit 50 --timeout 900
```

`--limit 50` es opcional porque es el valor predeterminado. Usa `--limit 5` para una prueba breve. `--timeout` limita cada proceso externo, no toda la ejecución. La primera ejecución consulta GitHub y guarda nombres y commits en `runs/nestjs/manifest.json`. Una ejecución incompleta con el mismo límite y configuración continúa desde esa muestra guardada. Una ejecución completa vuelve a consultar GitHub y reutiliza los registros si coinciden las revisiones.

Para controlar cada fase, usa los subcomandos. El archivo `data/run-config.json` contiene `{"repository_limit": 50}`. Usa nombres nuevos si quieres conservar resultados anteriores:

```bash
.venv/bin/python main.py mine --run runs/nestjs-final --timeout 900
.venv/bin/python main.py analyze --run runs/nestjs-final
.venv/bin/python main.py visualize --run runs/nestjs-final
.venv/bin/python main.py report --source . --run runs/reporter-simulado --timeout 900 --llm simulated
.venv/bin/python main.py export --run runs/nestjs-final --destination results/nestjs-final
.venv/bin/python main.py export --run runs/reporter-simulado --destination results/reporter-simulado
```

Después de configurar la clave y el modelo, usa otra ruta para el informe real:

```bash
.venv/bin/python main.py report --source . --run runs/reporter-openrouter --timeout 900 --llm openrouter
```

Tras una ejecución completa, puedes generar una plantilla de afiche A0 y un guion con las cifras medidas:

```bash
.venv/bin/python main.py poster --run runs/nestjs-final --reporter-run runs/reporter-openrouter --destination results/presentacion
```

Esto escribe `poster-a0.html` y `presentation-script.md`. El afiche físico A0 y su fotografía legible en PDF son tareas de entrega aparte.

## Dónde se guardan los resultados

La GUI y `--no-gui` utilizan una única ruta activa de Miner, `runs/nestjs/`. **Ejecutar todo** y `--no-gui` exportan el HTML y la evidencia de Miner con un nombre único bajo `results/` **antes de ejecutar Reporter**. Si Reporter termina, recibe una exportación separada. Las fases individuales de la GUI conservan su salida en `runs/`; si necesitas una exportación portable, usa el subcomando `export`. Los subcomandos usan las rutas indicadas por `--run` y `--destination`.

| Ruta dentro de una ejecución o exportación | Contenido |
|---|---|
| `manifest.json` | Repositorios, commits, configuración de herramientas y hashes |
| `records/` y `raw/` | Estados por repositorio y evidencia SARIF, SBOM y JSON original de Grype |
| `prepared/` | Datos unificados validados (`data.json`) |
| `reports/analysis.ipynb` | Notebook ejecutado y reproducible |
| `reports/dashboard.html` | Panel HTML autónomo de Miner, sin servidor ni CDN |
| `reports/security-report.md` | Informe de Reporter, si se validó correctamente |
| `logs/` | Metadatos de progreso guardados |
| `work/` | Copias temporales propias, normalmente eliminadas tras verificar la evidencia |

`results/` excluye clones, ejecutables, bases de datos y credenciales. Las exportaciones de Reporter contienen Markdown/JSON y evidencia, sin panel HTML. Los registros originales en `runs/` permanecen disponibles tras exportar. El subcomando `mine` sin `--resume` reemplaza solo una ejecución previa que este programa reconoce como propia en la misma ruta `--run`; usa otra ruta para conservarla.

La auditoría de Reporter copia solo código, pruebas, documentación y configuración permitidos. Su manifiesto registra hashes de los bytes copiados y los archivos de configuración examinados; no incluye `.env`, claves, caches, clones ni `results/`. CodeQL analiza Python y el JavaScript de `visualizer/assets/dashboard.js`; Syft y Grype revisan las dependencias de la misma copia. Si no hay workflows de GitHub, el informe lo indica como limitación. Las observaciones del modelo deben citar IDs presentes en la evidencia; el Markdown añade las rutas, líneas, paquetes y versiones verificadas por Python.

## Abrir el HTML desde la terminal

Usa la ruta exacta que imprime el programa. Por ejemplo:

```bash
DASHBOARD='results/nestjs-YYYYMMDDTHHMMSSZ-xxxxxxxx/reports/dashboard.html'
xdg-open "$DASHBOARD"
```

Antes de exportar, un análisis por fases desde la GUI queda en `runs/nestjs/reports/dashboard.html`. Si usaste subcomandos con `--run`, sustituye esa ruta por la indicada en el comando.

## Reproducibilidad

La selección de NestJS se genera al iniciar Miner y puede variar en otra fecha. Su manifiesto guardado permite reproducir exactamente los repositorios y commits analizados. Analyzer conserva la categoría de lenguaje principal en cada repositorio y hallazgo; el notebook y el HTML muestran también la cobertura para interpretar las comparaciones. CodeQL utiliza ese lenguaje principal, de modo que los lenguajes secundarios pueden quedar fuera del análisis de código. Las ejecuciones anteriores de Fastify, freeCodeCamp y Grafana conservan sus muestras en `runs/`; sus manifiestos sueltos se retiraron de `data/`.

Analyzer exige cifrado CurveZMQ al ejecutar el notebook. Si la instalación de ZeroMQ o el kernel no admiten ese cifrado, la ejecución del notebook se detiene en lugar de abrir una conexión TCP sin cifrar.

La ejecución registra versiones, hashes de herramientas, código de análisis y metadatos de la base de Grype. Los artefactos originales tienen hashes SHA-256; Analyzer y el exportador los verifican antes de utilizarlos. El notebook lee JSON guardado y puede volver a ejecutarse desde su directorio. En Docker, el punto de entrada actualiza la base de Grype si falta o es inválida; en la instalación local puedes usar el subcomando explícito `update-db`.

Para reanudar Miner con el **mismo** manifiesto, configuración, herramientas, base de datos y código de análisis:

```bash
.venv/bin/python main.py mine --run runs/nestjs-final --timeout 900 --resume
```

## Decisiones de diseño

- Las cuatro responsabilidades evaluadas permanecen en `miner/`, `analyzer/`, `visualizer/` y `reporter/`; la infraestructura, GUI, instaladores y pruebas están en `support/`.
- Miner guarda un manifiesto con commits exactos y un estado independiente por herramienta y repositorio. Analyzer verifica hashes antes de producir `prepared/data.json`; Visualizer consume ese archivo y coloca el JavaScript de `visualizer/assets/dashboard.js` dentro del HTML final para que abra sin servidor.
- Reporter crea una copia permitida del proyecto y conserva hashes de los bytes analizados. Sus datos de entrada al modelo son metadatos acotados, cifras calculadas por Python e IDs de evidencia. El informe se guarda como Markdown/JSON; las rutas, líneas, paquetes y versiones se presentan desde la evidencia validada.
- `runs/` conserva ejecuciones y registros originales fuera de Git. `results/` contiene exportaciones portables para la entrega.

La reanudación verifica y conserva los registros guardados, incluso los fallidos; no los reintenta automáticamente. En la GUI y con `--no-gui` se activa de forma automática solo si coinciden los repositorios, commits y configuración. Usa una ruta nueva con los subcomandos si quieres conservar una ejecución anterior al probar código o configuración modificados. Si falla una solicitud a OpenRouter después de guardar el análisis propio, repite `report` con `--resume` y la misma ruta para reutilizar la copia del proyecto.

Comprobaciones locales sin llamar al modelo ni descargar repositorios:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
```

## Limitaciones

- Una prueba con cinco repositorios **no** cumple el mínimo de 20 de la entrega.
- CodeQL analiza los lenguajes compatibles seleccionados sin compilar. Los análisis parciales, fallidos y no compatibles se registran por separado y no equivalen a cero vulnerabilidades.
- Syft inventaría el directorio descargado sin instalar dependencias faltantes. Versiones desconocidas, SBOM vacíos, submódulos omitidos y contenido de Git LFS limitan la cobertura. Grype analiza el SBOM verificado; si Syft falla, Grype se omite.
- Los niveles de alertas de CodeQL y la severidad de dependencias tienen escalas diferentes. Las coincidencias requieren revisión humana; no prueban que una vulnerabilidad sea explotable.
- Reporter usa una simulación si no hay clave de OpenRouter. Una respuesta real del modelo se valida estructuralmente, pero su interpretación también requiere revisión humana. El modelo recibe evidencia acotada, aunque las estadísticas abarcan todos los hallazgos preparados.
- La plantilla digital del afiche no sustituye el afiche físico A0 ni su fotografía en PDF. Consulta la especificación antes de afirmar que la entrega está completa.
