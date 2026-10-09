"""Presenta respuestas validadas, simuladas o reales, como Markdown legible."""

from pathlib import Path
from typing import Callable

from analyzer.prepare import prepare_data
from support.core.storage import read_json, write_json
from reporter.client import OpenRouterClient
from reporter.project import scan_project
from reporter.prompt import request_report
from reporter.validate import validate_response


def markdown_text(value: str) -> str:
    """Escapa el texto del modelo antes de incluirlo en Markdown."""
    return (str(value).replace("\\", "\\\\").replace("`", "\\`")
            .replace("\r", " ").replace("\n", " ")
            .replace("<", "&lt;").replace(">", "&gt;")
            .replace("[", "\\[").replace("]", "\\]"))


def generate_report(data: dict, destination: Path, *, client=None,
                    project_files: list[dict] | None = None,
                    project_file_limitations: list[str] | None = None) -> Path:
    """Valida la respuesta antes de escribir Markdown o JSON estructurado."""
    raw, payload = request_report(data, client, project_files=project_files,
                                  project_file_limitations=project_file_limitations)
    simulated = getattr(client, "simulated", True)
    response = validate_response(raw, payload, expected_simulated=simulated)
    stats = response.statistics
    lines = ["# Informe de seguridad del proyecto", "",
             ("**GENERADO CON UNA SIMULACIÓN DE MODELO. No se usó inferencia real.**"
              if simulated else "**Generado con un modelo de lenguaje; requiere revisión humana.**"), "",
             response.summary, "", "## Resultados calculados", "",
             f"- Repositorios: {stats.repositories} de {stats.expected_repositories} esperados.",
             f"- Alertas de código: {stats.code_findings}.",
             f"- Coincidencias con vulnerabilidades de dependencias: {stats.dependency_findings}.",
             f"- Componentes inventariados: {stats.components}.", "",
             "## Estado de las herramientas", ""]
    status_labels = {"success": "completado", "success_empty": "sin resultados",
                     "partial": "parcial", "failed": "fallido",
                     "skipped": "omitido", "unsupported": "no compatible"}
    for repo in data["repositories"]:
        lines.append(f"- {markdown_text(repo['repository'])}: " + "; ".join(
            f"{tool['tool']}={status_labels.get(tool['status'], tool['status'])}"
            + (f" ({markdown_text(tool['error'])})" if tool['error'] else "")
            for tool in repo["tools"]))
    lines.extend(["", "## Observaciones para revisar", "",
                  "Estas señales requieren revisión humana; la evidencia citada no confirma por sí sola una vulnerabilidad.", ""])
    evidence = {entry["id"]: entry for entry in payload["evidence"]}
    for item in response.observations:
        lines.append(f"- {markdown_text(item.text)} Evidencia: {', '.join(item.evidence_ids)}.")
        for identifier in item.evidence_ids:
            entry = evidence[identifier]
            detail = entry["detail"]
            if entry["kind"] == "code":
                reference = f"{detail['file']}:{detail['start_line']} · regla {detail['rule_id']}"
            elif entry["kind"] == "dependency":
                reference = (f"{detail['package_name']} {detail['package_version']} · "
                             f"{detail['vulnerability_id']}")
            else:
                reference = f"{detail['file']} · " + "; ".join(detail.get("signals") or ["sin señal automática"])
            lines.append(f"  - `{identifier}`: {markdown_text(reference)}")
        if item.recommendation:
            lines.append(f"  Mitigación sugerida: {markdown_text(item.recommendation)}")
    lines.extend(["", "## Limitaciones", ""])
    lines.extend(f"- {markdown_text(item)}" for item in response.limitations)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(destination.with_suffix(".json"), response.model_dump(mode="json"))
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def run_report(source: Path, run: Path, config: dict, *, client: OpenRouterClient | None = None,
               resume: bool = False, keep_work: bool = False,
               progress: Callable[[str], None] | None = None) -> Path:
    """Analiza el proyecto y escribe el informe tras validar la evidencia."""
    if not resume:
        # Al reanudar, reutiliza la copia verificada sin repetir el análisis.
        scan_options = {"progress": progress} if progress else {}
        scan_project(source, run, config, keep_work=keep_work, **scan_options)
    if progress:
        progress("Reporter: preparando la evidencia del proyecto")
    data = prepare_data(run)
    project_manifest = read_json(run / "manifest.json")
    if "snapshot" not in project_manifest:
        raise ValueError("La ejecución de Reporter no tiene una copia del proyecto")
    # Comprueba que las señales apunten a los mismos bytes de la copia guardada.
    for entry in project_manifest["project_files"]:
        detail = entry["detail"]
        if project_manifest["snapshot"]["files"].get(detail["file"]) != detail["sha256"]:
            raise ValueError("La evidencia de archivos difiere de la copia guardada")
    if progress:
        progress("Reporter: generando y validando el informe")
    path = generate_report(data, run / "reports/security-report.md", client=client,
                           project_files=project_manifest["project_files"],
                           project_file_limitations=project_manifest["project_file_limitations"])
    write_json(run / "reports/report-provenance.json",
               {"provider": "openrouter" if client else "simulated",
                "model": client.model if client else None,
                "source_sha256": project_manifest["snapshot"]["source_sha256"]})
    return path
