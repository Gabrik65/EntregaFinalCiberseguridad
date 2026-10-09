"""Notebook y tablas reproducibles derivados de la evidencia preparada."""

import os
import sys
from collections import Counter
from pathlib import Path



def analysis_tables(data: dict) -> dict:
    """Agrupa la evidencia preparada en tablas deterministas para el notebook."""
    code = [item for item in data["evidence"] if item["kind"] == "code"]
    dependencies = [item for item in data["evidence"] if item["kind"] == "dependency"]
    if len(code) != data["summary"]["code_findings"] or len(dependencies) != data["summary"]["dependency_findings"]:
        raise ValueError("Los totales preparados no coinciden con la evidencia")
    return {
        "code_levels": dict(Counter(item["detail"]["severity"] for item in code)),
        "dependency_severities": dict(Counter(item["detail"]["severity"] for item in dependencies)),
        "rules": dict(Counter(item["detail"]["rule_id"] for item in code)),
        "component_types": dict(Counter(item["detail"]["type"] for item in data["evidence"] if item["kind"] == "component")),
        "affected_packages": dict(Counter(item["detail"]["package_name"] for item in dependencies)),
        "by_repository": {repo["repository"]: {tool["tool"]: tool["count"] for tool in repo["tools"]}
                          for repo in data["repositories"]},
        "by_category": {
            category: {
                "repositories": sum((repo.get("category") or "Sin categoría") == category
                                    for repo in data["repositories"]),
                "code_findings": sum((item.get("category") or "Sin categoría") == category
                                     for item in code),
                "dependency_findings": sum((item.get("category") or "Sin categoría") == category
                                           for item in dependencies),
                "codeql_completed": sum((repo.get("category") or "Sin categoría") == category
                                        and any(tool["tool"] == "codeql" and tool["status"] in
                                                {"success", "success_empty"} for tool in repo["tools"])
                                        for repo in data["repositories"]),
                "grype_completed": sum((repo.get("category") or "Sin categoría") == category
                                       and any(tool["tool"] == "grype" and tool["status"] in
                                               {"success", "success_empty"} for tool in repo["tools"])
                                       for repo in data["repositories"]),
            }
            for category in sorted({repo.get("category") or "Sin categoría"
                                    for repo in data["repositories"]})
        },
    }


def build_notebook(destination: Path, data_path: Path, *, execute=True) -> Path:
    """Crea un notebook que lee el JSON guardado y, opcionalmente, lo ejecuta."""
    import nbformat
    from nbclient import NotebookClient
    from jupyter_client import KernelManager

    relative = os.path.relpath(data_path.resolve(), destination.parent.resolve())
    nb = nbformat.v4.new_notebook()
    nb.metadata["kernelspec"] = {"display_name": "Python 3", "language": "python", "name": "python3"}
    # Markdown explica los resultados; las celdas recalculan los totales principales.
    nb.cells = [
        nbformat.v4.new_markdown_cell("# Análisis de seguridad reproducible\n\nEste notebook lee evidencia guardada; no descarga repositorios ni consulta un modelo de lenguaje."),
        nbformat.v4.new_code_cell(f"from pathlib import Path\nimport json\nfrom collections import Counter\nimport matplotlib.pyplot as plt\nDATA_PATH = Path({relative!r})\ndata = json.loads(DATA_PATH.read_text(encoding='utf-8'))\ndata['summary']"),
        nbformat.v4.new_code_cell("ESTADOS = {'success': 'completado', 'success_empty': 'sin resultados', 'partial': 'parcial', 'failed': 'fallido', 'skipped': 'omitido', 'unsupported': 'no compatible'}\nSEVERIDADES = {'error': 'Error', 'warning': 'Advertencia', 'note': 'Nota', 'none': 'Ninguno', 'critical': 'Crítica', 'high': 'Alta', 'medium': 'Media', 'low': 'Baja', 'unknown': 'Desconocida'}"),
        nbformat.v4.new_markdown_cell("## Cobertura\n\nEl denominador incluye fallos, herramientas omitidas y lenguajes no compatibles."),
        nbformat.v4.new_code_cell("summary = data['summary']\nfor tool, states in summary['coverage'].items():\n    assert sum(states.values()) == summary['repositories']\n    print(tool, {ESTADOS.get(estado, estado): cantidad for estado, cantidad in states.items()})\nprint('Muestra:', summary['repositories'], '/', summary['expected_repositories'])"),
        nbformat.v4.new_markdown_cell("## Alertas de código y coincidencias de dependencias\n\nSus escalas de severidad se muestran por separado. Una coincidencia no demuestra que sea explotable."),
        nbformat.v4.new_code_cell("fig, axes = plt.subplots(1, 2, figsize=(12, 4))\nfor ax, kind, title, total_key in zip(axes, ['code', 'dependency'], ['Niveles SARIF de CodeQL', 'Severidad de dependencias'], ['code_findings', 'dependency_findings']):\n    items = [e for e in data['evidence'] if e['kind'] == kind]\n    assert len(items) == summary[total_key]\n    counts = Counter(e['detail']['severity'] for e in items)\n    if counts:\n        ax.bar([SEVERIDADES.get(str(nivel).lower(), nivel) for nivel in counts], counts.values(), color='#146b57')\n    else:\n        ax.text(.5, .5, 'Sin alertas registradas', ha='center', transform=ax.transAxes)\n    ax.set_title(title)\n    ax.set_ylabel('Coincidencias')\nfig.tight_layout()\nplt.show()"),
        nbformat.v4.new_markdown_cell("## Reglas, paquetes y distribución por repositorio"),
        nbformat.v4.new_code_cell("print('Reglas:', Counter(e['detail']['rule_id'] for e in data['evidence'] if e['kind']=='code').most_common(15))\nprint('Paquetes:', Counter(e['detail']['package_name'] for e in data['evidence'] if e['kind']=='dependency').most_common(15))\nfor repo in data['repositories']:\n    print(repo['repository'], {t['tool']: (ESTADOS.get(t['status'], t['status']), t['count']) for t in repo['tools']})"),
        nbformat.v4.new_markdown_cell("## Comparación por categoría\n\nLos conteos observados se leen junto con la cobertura de cada herramienta; no son tasas de vulnerabilidad."),
        nbformat.v4.new_code_cell("from collections import defaultdict\nby_category = defaultdict(lambda: {'repositorios': 0, 'codeql_completos': 0, 'grype_completos': 0, 'codigo': 0, 'dependencias': 0})\nfor repo in data['repositories']:\n    group = by_category[repo.get('category') or 'Sin categoría']\n    group['repositorios'] += 1\n    for tool in repo['tools']:\n        if tool['tool'] in ('codeql', 'grype') and tool['status'] in ('success', 'success_empty'):\n            group[tool['tool'] + '_completos'] += 1\nfor item in data['evidence']:\n    if item['kind'] in ('code', 'dependency'):\n        by_category[item.get('category') or 'Sin categoría']['codigo' if item['kind'] == 'code' else 'dependencias'] += 1\nfor category, counts in sorted(by_category.items()):\n    print(category, counts)"),
        nbformat.v4.new_markdown_cell("## Patrones observados y cobertura\n\nEstas comparaciones describen hallazgos observados. La cobertura desigual impide interpretarlos como tasas de vulnerabilidad de toda la organización."),
        nbformat.v4.new_code_cell("""from collections import defaultdict
for kind, tool_name, label in [('code', 'codeql', 'alertas de código'),
                               ('dependency', 'grype', 'coincidencias de dependencias')]:
    items = [e for e in data['evidence'] if e['kind'] == kind]
    covered = [r['repository'] for r in data['repositories']
               if any(t['tool'] == tool_name and t['status'] in ('success', 'success_empty')
                      for t in r['tools'])]
    by_repository = Counter(e['repository'] for e in items)
    print(f'{label}: cobertura completa en {len(covered)}/{len(data["repositories"])} repositorios')
    if items:
        name, count = by_repository.most_common(1)[0]
        print(f'  Mayor concentración observada: {name}, {count}/{len(items)} ({count / len(items):.1%}).')
        print('  Repositorios con hallazgos observados:', len(by_repository),
              '(puede incluir resultados parciales).')
    else:
        print('  No hay hallazgos registrados; revisa la cobertura antes de interpretar este resultado.')
rules_to_repositories = defaultdict(set)
for finding in data['evidence']:
    if finding['kind'] == 'code':
        rules_to_repositories[finding['detail']['rule_id']].add(finding['repository'])
repeated = sorted(((rule, len(repositories)) for rule, repositories in rules_to_repositories.items()
                   if len(repositories) > 1), key=lambda pair: (-pair[1], pair[0]))
print('Reglas observadas en más de un repositorio:', repeated[:10])
print('Una regla repetida sugiere un patrón para revisar, no una vulnerabilidad confirmada.')"""),
        nbformat.v4.new_markdown_cell("## Interpretación y límites\n\nLos resultados describen esta muestra y estas revisiones. Un inventario vacío o una herramienta fallida limita la conclusión; no demuestra seguridad."),
        nbformat.v4.new_code_cell("for limitation in data['limitations']:\n    print('-', limitation)\nfor repo in data['repositories']:\n    for tool in repo['tools']:\n        if tool['error'] or tool['warnings']:\n            print(repo['repository'], tool['tool'], tool['error'] or tool['warnings'])"),
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    if execute:
        # Exige CurveZMQ para cifrar los mensajes entre Analyzer y el kernel.
        manager = KernelManager(kernel_name="python3", transport_encryption="required")
        manager.kernel_spec.argv = [sys.executable, "-m", "ipykernel_launcher", "-f", "{connection_file}"]
        NotebookClient(nb, km=manager, timeout=180,
                       resources={"metadata": {"path": str(destination.parent.resolve())}}).execute()
    nbformat.write(nb, destination)
    return destination


def analyze(data: dict, run: Path, *, execute=True):
    """Valida las tablas derivadas y guarda el notebook sobre data.json."""
    analysis_tables(data)
    return build_notebook(run / "reports" / "analysis.ipynb", run / "prepared" / "data.json", execute=execute)
