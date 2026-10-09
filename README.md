# Análisis de seguridad de repositorios de NestJS

**Integrante:** Gabriel Valenzuela

## Contextualización

Este proyecto estudia repositorios públicos de la organización NestJS para observar sus componentes de software y las coincidencias con avisos de seguridad conocidos. Se seleccionaron 50 repositorios y se fijó el commit de cada uno. Así, los resultados corresponden a revisiones concretas y pueden consultarse junto con su evidencia original.

La solución también incluye una auditoría independiente de su propio código mediante Reporter, conforme a la [especificación del proyecto](docs/Especificación%20del%20proyecto%20P1.txt).

## Arquitectura

El proyecto tiene cuatro componentes:

- **Miner** selecciona y descarga los repositorios. Para cada uno registra la revisión analizada y ejecuta CodeQL, Syft y Grype, conservando la evidencia y el estado de cada herramienta.
- **Analyzer** valida los artefactos, prepara un dataset común y genera un notebook ejecutado con estadísticas y comparaciones.
- **Visualizer** transforma los datos preparados en un panel HTML interactivo que puede abrirse sin servidor.
- **Reporter** examina este mismo proyecto. Revisa su código, dependencias y configuraciones, y puede generar un informe de seguridad con OpenRouter a partir de evidencia verificable.

Miner → Analyzer → Visualizer forman el flujo de análisis de NestJS. Reporter funciona por separado porque su objeto de estudio es el repositorio de esta solución.

## Ejecución

El Dev Container utiliza el Dockerfile del proyecto. También se puede construir y ejecutar la solución con Docker Compose desde la raíz:

```bash
docker compose build
docker compose run --rm analysis
```

El segundo comando abre la interfaz gráfica cuando hay una sesión X11 disponible. Para ejecutar el flujo principal desde la terminal:

```bash
docker compose run --rm analysis python main.py --no-gui --organization nestjs --limit 50 --timeout 900
```

Las fases pueden ejecutarse por separado. Todas leen y escriben en la misma ruta de ejecución:

```bash
docker compose run --rm analysis python main.py mine --run runs/nestjs --timeout 900
docker compose run --rm analysis python main.py analyze --run runs/nestjs
docker compose run --rm analysis python main.py visualize --run runs/nestjs
docker compose run --rm analysis python main.py export --run runs/nestjs --destination results/nestjs-evaluated
```

El límite predeterminado es de 50 repositorios y está definido en `data/run-config.json`. La ayuda de `main.py` muestra los demás comandos y opciones.

## Resultados cuantitativos

La [exportación de NestJS](results/nestjs-evaluated/) contiene **50 repositorios** con sus commits y registros individuales. Syft identificó **5.748 componentes**. Grype produjo **582 coincidencias** entre componentes y avisos de seguridad; estas coincidencias corresponden a **209 identificadores de aviso distintos**.

| Severidad registrada por Grype | Coincidencias | Porcentaje |
|---|---:|---:|
| Critical | 28 | 4,8 % |
| High | 304 | 52,2 % |
| Medium | 192 | 33,0 % |
| Low | 58 | 10,0 % |
| **Total** | **582** | **100 %** |

La cobertura se conserva por herramienta en los registros. Syft produjo componentes en 49 repositorios y un SBOM vacío en uno. Grype registró coincidencias en 21 repositorios y ninguna coincidencia en los otros 29. Esta exportación no aporta análisis de código completados por CodeQL, por lo que sus cifras no se usan para sacar conclusiones sobre hallazgos de código fuente.

Las cifras proceden de [`prepared/data.json`](results/nestjs-evaluated/prepared/data.json). Una coincidencia con un aviso requiere revisión del componente y su contexto antes de determinar su impacto.

## Análisis de los resultados

Las coincidencias de dependencias se concentran en algunos repositorios. `nestjs/mau-recipes` reúne 203 y `nestjs/terminus` reúne 121: juntos representan **324 de las 582 coincidencias**, equivalentes al **55,7 %** del total observado. Esta concentración permite priorizar la revisión de sus dependencias y archivos de bloqueo.

El paquete `multer` aparece en **125 coincidencias** de la muestra. La repetición de un paquete o un aviso entre repositorios debe interpretarse junto con la versión registrada y el commit analizado; cada coincidencia mantiene una referencia a su evidencia.

El [notebook ejecutado](results/nestjs-evaluated/reports/analysis.ipynb) permite explorar estas cifras y compararlas por lenguaje principal. El [panel HTML](results/nestjs-evaluated/reports/dashboard.html) presenta los datos de forma interactiva. Después de descargar el repositorio, el HTML puede abrirse directamente en un navegador.

## Auditoría del propio proyecto

Reporter analiza este repositorio de manera independiente. Para generar un informe con OpenRouter, configura la clave y el modelo en la misma terminal desde la que ejecutarás Compose:

```bash
read -rsp 'Clave API de OpenRouter: ' OPENROUTER_API_KEY && echo && export OPENROUTER_API_KEY
export OPENROUTER_MODEL='<modelo disponible en tu cuenta>'
docker compose run --rm analysis python main.py report --source . --run runs/reporter-openrouter --llm openrouter
```

La clave se lee desde una variable de entorno y no se guarda en Git. Las observaciones del informe deben estar vinculadas a identificadores de evidencia presentes en la auditoría.

## Evidencia y reproducibilidad

La carpeta [`results/nestjs-evaluated/`](results/nestjs-evaluated/) incluye:

- `manifest.json`: selección de repositorios, commits y configuración.
- `records/`: resultado y estado de cada herramienta por repositorio.
- `raw/`: SBOM y resultados originales conservados.
- `prepared/data.json`: datos utilizados por el notebook y el panel.
- `reports/analysis.ipynb`: análisis ejecutado.
- `reports/dashboard.html`: visualización autónoma.

`runs/` contiene las ejecuciones de trabajo y `results/` sus exportaciones portables. El manifiesto y los hashes permiten relacionar los resultados publicados con los repositorios, revisiones y artefactos utilizados.

## Conclusiones

La muestra de 50 repositorios permitió identificar 5.748 componentes y estudiar 582 coincidencias de dependencias con avisos de seguridad. Más de la mitad de esas coincidencias se concentra en dos repositorios, lo que ofrece un punto de partida concreto para revisar versiones y dependencias.

El proyecto conserva tanto las cifras como la evidencia que las respalda. Esa trazabilidad permite revisar cada observación en su contexto y distinguir entre una coincidencia automatizada y una conclusión de seguridad confirmada.
