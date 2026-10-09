"""Valida registros, conserva la procedencia y calcula totales deterministas."""

from collections import Counter
from pathlib import Path

from support.core.models import DependencyFinding, Finding, RepositoryScan
from support.core.storage import fingerprint, read_json, verify_artifacts, write_json


SUCCESS = {"success", "success_empty"}


def prepare_data(run: Path) -> dict:
    """Verifica análisis guardados y calcula totales que consideran la cobertura."""
    run = run.resolve()
    evidence, repositories = {}, []
    manifest = read_json(run / "manifest.json")
    selection = manifest.get("selection", {})
    categories = {item["repository"]: item.get("category")
                  for item in selection.get("repositories", [])}

    def normalize_paths(value, source_root):
        """Quita prefijos temporales de las rutas presentes en la evidencia."""
        if isinstance(value, str) and source_root and value.startswith(source_root + "/"):
            return value[len(source_root) + 1:]
        if isinstance(value, list):
            return [normalize_paths(item, source_root) for item in value]
        if isinstance(value, dict):
            return {key: normalize_paths(item, source_root) for key, item in value.items()}
        return value
    for path in sorted((run / "records").glob("*.json")):
        # Rechaza artefactos ausentes o modificados antes de aceptar un registro.
        raw = read_json(path)
        verify_artifacts(run, raw)
        scan = RepositoryScan.model_validate({k: v for k, v in raw.items() if k != "artifact_hashes"})
        source_root = None
        syft = next(tool for tool in scan.tools if tool.tool == "syft")
        if syft.status in SUCCESS and syft.artifacts:
            document = read_json(run / syft.artifacts[0])
            source_root = document.get("metadata", {}).get("component", {}).get("name")
        category = categories.get(scan.repository)
        repository = {"repository": scan.repository, "category": category, "commit": scan.commit,
                      "source_sha256": scan.source_sha256, "source_error": scan.source_error,
                      "tools": []}
        for tool in scan.tools:
            # Cada herramienta aporta evidencia y un estado independientes.
            items, kind = [], tool.tool
            if tool.tool == "codeql":
                items = [Finding.model_validate(item).model_dump(mode="json")
                         for item in tool.data.get("findings", [])]
                kind = "code"
            elif tool.tool == "grype":
                items = [DependencyFinding.model_validate(item).model_dump(mode="json")
                         for item in tool.data.get("findings", [])]
                kind = "dependency"
            elif tool.status in SUCCESS:
                components = tool.data["components"]
                if len(components) != tool.data["component_count"]:
                    raise ValueError("El número de componentes del SBOM es inconsistente")
                for component in components:
                    if not isinstance(component, dict) or not isinstance(component.get("name"), str):
                        raise ValueError("Componente inválido en el SBOM")
                    items.append(normalize_paths(component, source_root))
                kind = "component"
            if items and tool.status not in SUCCESS | {"partial"}:
                raise ValueError("Una herramienta fallida u omitida no puede registrar hallazgos utilizables")
            if tool.status == "success_empty" and items:
                raise ValueError("Un análisis vacío contiene hallazgos")
            ids = set()
            for item in items:
                item = normalize_paths(item, source_root)
                content = {"repository": scan.repository, "revision": scan.commit or scan.source_sha256,
                           "tool": tool.tool, "kind": kind, "detail": item}
                # Excluye identificadores ligados a rutas temporales del ID estable.
                identity = {**content, "detail": {key: value for key, value in item.items()
                                                  if key not in {"bom-ref", "package_id"}}}
                identifier = f"{kind}-{fingerprint(identity)[:20]}"
                ids.add(identifier)
                reference = item.get("bom-ref") or item.get("package_id")
                entry = evidence.setdefault(identifier, {"id": identifier, "category": category, **identity,
                                            "artifacts": list(tool.artifacts), "source_refs": []})
                if reference and reference not in entry["source_refs"]:
                    entry["source_refs"].append(reference)
            repository["tools"].append({"tool": tool.tool, "status": tool.status,
                                        "version": tool.version, "count": len(ids),
                                        "error": tool.error, "warnings": list(tool.warnings),
                                        "duration_seconds": tool.duration_seconds,
                                        "metadata": {k: tool.data[k] for k in
                                                     ("database", "languages", "missing_versions", "exclusions")
                                                     if k in tool.data}})
        repositories.append(repository)
    if not repositories:
        raise ValueError("No hay registros de repositorios guardados para analizar")
    if len({r["repository"] for r in repositories}) != len(repositories):
        raise ValueError("Hay registros duplicados de repositorios")
    expected = selection.get("requested_count", 1)
    ordered = sorted(evidence.values(), key=lambda item: item["id"])
    summary = {
        "repositories": len(repositories), "expected_repositories": expected,
        "code_findings": sum(item["kind"] == "code" for item in ordered),
        "dependency_findings": sum(item["kind"] == "dependency" for item in ordered),
        "components": sum(item["kind"] == "component" for item in ordered),
        "coverage": {name: dict(sorted(Counter(
            tool["status"] for repo in repositories for tool in repo["tools"] if tool["tool"] == name
        ).items())) for name in ("codeql", "syft", "grype")},
    }
    # Los análisis fallidos siguen en el denominador: su ausencia de hallazgos no equivale a cero.
    limitations = [
        "Las alertas requieren revisión; no son vulnerabilidades explotables confirmadas.",
        "Los niveles SARIF de CodeQL y la severidad de dependencias usan escalas diferentes.",
        "El análisis del directorio no resuelve ni instala versiones faltantes de dependencias.",
        "CodeQL analiza los lenguajes seleccionados sin compilar; no se descargan submódulos Git ni contenido de Git LFS.",
    ]
    if len(repositories) != expected:
        limitations.append(f"Muestra incompleta: se registraron {len(repositories)} de {expected} repositorios solicitados.")
    data = {"schema_version": 1, "organization": selection.get("organization"),
            "summary": summary, "repositories": repositories,
            "evidence": ordered, "limitations": limitations + selection.get("limitations", [])}
    write_json(run / "prepared" / "data.json", data)
    return data
