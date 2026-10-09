"""Coordina el análisis completo sin depender de Tkinter."""

import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from analyzer.notebook import analyze
from analyzer.prepare import prepare_data
from support.core.storage import fingerprint, read_json
from support.core.export import export_run
from miner.pipeline import ROOT, mine, select_repositories, tool_configuration
from reporter.client import OpenRouterClient
from reporter.generate import run_report
from visualizer.dashboard import generate_html


# OPENROUTER_MODEL reemplaza este modelo predeterminado en la GUI.
DEFAULT_MODEL = "openai/gpt-4o-mini"


@dataclass(frozen=True)
class RunOutcome:
    """Rutas y estado de Reporter devueltos después de exportar los resultados."""
    dashboard: Path
    export: Path
    reporter_report: Path | None
    reporter_error: str | None


@dataclass(frozen=True)
class SavedRun:
    """Estado de una ejecución de Miner consultable desde una nueva ventana."""
    path: Path
    organization: str
    completed: int
    total: int
    analyzed: bool
    visualized: bool


def saved_run(path: Path) -> SavedRun | None:
    """Lee la ejecución activa sin recorrer ni elegir entre carpetas históricas."""
    if not path.is_dir() or path.is_symlink() or not (path / ".run-owner.json").is_file():
        return None
    try:
        manifest = read_json(path / "manifest.json")
        selection = manifest["selection"]
        repositories = selection["repositories"]
        total = len(repositories)
        if not total or selection["requested_count"] != total:
            return None
        progress = read_json(path / "logs/progress.json") if (path / "logs/progress.json").is_file() else {}
        completed = progress.get("completed", 0)
        if not isinstance(completed, int) or isinstance(completed, bool) or not 0 <= completed <= total:
            return None
        if progress and progress.get("total") != total:
            return None
        # La marca de avance y todos los registros son necesarios para declarar completo a Miner.
        expected_records = {f"{i:03d}.json" for i in range(1, total + 1)}
        if completed == total and {record.name for record in (path / "records").glob("*.json")} != expected_records:
            completed = total - 1
        return SavedRun(path, selection["organization"], completed, total,
                        (path / "prepared/data.json").is_file()
                        and (path / "reports/analysis.ipynb").is_file(),
                        (path / "reports/dashboard.html").is_file())
    except (OSError, ValueError, KeyError, TypeError):
        return None


def require_complete_miner(run: Path, *, root: Path = ROOT) -> SavedRun:
    """Rechaza ejecuciones incompletas antes de consumir sus datos guardados."""
    if run.resolve().parent != (root / "runs").resolve():
        raise ValueError("La ejecución de Miner debe estar en runs/")
    item = saved_run(run)
    if item is None:
        raise ValueError("No se encontró una ejecución guardada y válida de Miner")
    if item.completed != item.total:
        raise ValueError(f"Miner solo registró {item.completed}/{item.total} repositorios")
    manifest = read_json(run / "manifest.json")
    for index, selected in enumerate(manifest["selection"]["repositories"], 1):
        record = read_json(run / "records" / f"{index:03d}.json")
        if (record.get("repository") != selected["repository"]
                or record.get("commit") != selected.get("commit")
                or record.get("config_sha256") != manifest["config_sha256"]):
            raise ValueError(f"El registro {index} no coincide con el manifiesto de Miner")
    return item


def same_revisions(previous: dict, current: dict) -> bool:
    """Compara los repositorios por nombre y commit, sin depender del orden de GitHub."""
    try:
        if previous["organization"].casefold() != current["organization"].casefold():
            return False

        def commits(selection: dict) -> dict[str, str] | None:
            repositories = selection["repositories"]
            result = {item["repository"].casefold(): (item["commit"], item.get("category"))
                      for item in repositories}
            if len(result) != len(repositories) or not all(commit for commit, _ in result.values()):
                return None
            return result

        old, new = commits(previous), commits(current)
        return old is not None and old == new
    except (AttributeError, KeyError, TypeError):
        return False


def mine_current(organization: str, limit: int, progress: Callable[[str], None], *,
                 root: Path = ROOT, timeout: int = 900) -> tuple[Path, dict]:
    """Usa una ruta fija; reanuda solo cuando selección y configuración coinciden."""
    organization = organization.strip()
    if not re.fullmatch(r"[A-Za-z0-9-]+", organization):
        raise ValueError("Ingresa una organización válida de GitHub")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("El límite de repositorios debe estar entre 1 y 50")
    run = root / "runs" / organization.lower()
    progress("Miner: comprobando CodeQL, Syft, Grype y la base de vulnerabilidades")
    config = tool_configuration(timeout=timeout)
    # Una ejecución incompleta conserva su muestra fijada aunque GitHub haya avanzado.
    resume_selection = None
    if run.is_dir() and not run.is_symlink():
        try:
            owner = read_json(run / ".run-owner.json")
            stored = read_json(run / "manifest.json")
            previous = stored["selection"]
            state = saved_run(run)
            if (state is not None and state.completed < state.total
                    and isinstance(owner, dict)
                    and isinstance(owner.get("id"), str)
                    and re.fullmatch(r"[0-9a-f]{32}", owner["id"])
                    and stored["config_sha256"] == fingerprint(config)
                    and previous["organization"].casefold() == organization.casefold()
                    and previous.get("repository_limit") == limit):
                resume_selection = previous
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
    if resume_selection is not None:
        progress("Miner: reanudando registros pendientes de la muestra guardada")
        mine(resume_selection, run, config, resume=True, progress=progress)
        return run, config
    progress("Miner: obteniendo repositorios públicos de GitHub")
    selection = select_repositories(organization, limit)
    if not selection["repositories"]:
        raise ValueError(f"No se encontraron repositorios públicos elegibles para {organization}")
    progress(f"Miner: {len(selection['repositories'])} repositorios seleccionados (límite: {limit})")
    resume = False
    if run.is_dir() and not run.is_symlink():
        try:
            owner = read_json(run / ".run-owner.json")
            stored = read_json(run / "manifest.json")
            previous = stored["selection"]
            resume = (isinstance(owner, dict) and isinstance(owner.get("id"), str)
                      and re.fullmatch(r"[0-9a-f]{32}", owner["id"]) is not None
                      and stored["config_sha256"] == fingerprint(config)
                      and same_revisions(previous, selection))
            if resume:
                selection = previous
        except (OSError, ValueError, KeyError, TypeError):
            pass
    if resume:
        progress("Miner: reanudando registros guardados con la misma selección y configuración")
    mine(selection, run, config, resume=resume, progress=progress)
    progress(f"Miner: registros guardados en {run}")
    return run, config


def mine_phase(organization: str, limit: int, progress: Callable[[str], None], *,
               root: Path = ROOT, timeout: int = 900) -> Path:
    """Procesa o reanuda la única ejecución activa de Miner."""
    run, _ = mine_current(organization, limit, progress, root=root, timeout=timeout)
    return run


def analyze_phase(run: Path, progress: Callable[[str], None], *, root: Path = ROOT) -> Path:
    """Verifica evidencia de Miner y genera los datos y el notebook."""
    require_complete_miner(run, root=root)
    progress("Analyzer: validando evidencia y calculando estadísticas")
    data = prepare_data(run)
    progress("Analyzer: generando y ejecutando el notebook")
    path = analyze(data, run, execute=True)
    progress(f"Analyzer: notebook guardado en {path}")
    return path


def visualize_phase(run: Path, progress: Callable[[str], None], *, root: Path = ROOT) -> Path:
    """Genera HTML desde la salida guardada por Analyzer."""
    state = require_complete_miner(run, root=root)
    if not state.analyzed:
        raise ValueError("Ejecuta Analyzer antes de Visualizer")
    data = read_json(run / "prepared/data.json")
    progress("Visualizer: creando el panel HTML autónomo")
    path = generate_html(data, run / "reports/dashboard.html")
    progress(f"Visualizer: panel guardado en {path.relative_to(root)}")
    return path


def reporter_phase(progress: Callable[[str], None], *, root: Path = ROOT,
                   timeout: int = 900) -> Path:
    """Analiza el proyecto propio, sin consumir hallazgos de Miner o Analyzer."""
    identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run = root / "runs" / f"reporter-{identifier}"
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    model = os.environ.get("OPENROUTER_MODEL", "").strip() or DEFAULT_MODEL
    client = OpenRouterClient(model=model) if key else None
    progress(f"Reporter: analizando este proyecto ({'OpenRouter: ' + model if client else 'simulado'})")
    path = run_report(root, run, tool_configuration(timeout=timeout), client=client, progress=progress)
    progress(f"Reporter: informe guardado en {path}")
    return path


def run_analysis(organization: str, limit: int, progress: Callable[[str], None],
                 dashboard_ready: Callable[[Path], None], *, root: Path = ROOT,
                 timeout: int = 900) -> RunOutcome:
    """Procesa la ruta activa, analiza, visualiza, informa y exporta."""
    # Miner usa una ruta fija; Reporter y la exportación conservan rutas propias.
    identifier = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    name = organization.strip().lower()
    reporter_run = root / "runs" / f"reporter-{identifier}"
    export = root / "results" / f"{name}-{identifier}"

    miner_run, config = mine_current(organization, limit, progress, root=root, timeout=timeout)

    # La preparación verifica los artefactos guardados antes de calcular estadísticas.
    progress("Analyzer: validando evidencia y calculando estadísticas")
    data = prepare_data(miner_run)
    progress("Analyzer: generando y ejecutando el notebook")
    analyze(data, miner_run, execute=True)

    progress("Visualizer: creando el panel HTML autónomo")
    dashboard = generate_html(data, miner_run / "reports/dashboard.html")
    dashboard_ready(dashboard)

    # Exporta antes de Reporter: su fallo o interrupción no oculta el HTML terminado.
    progress("Resultados: exportando evidencia portable")
    export_run(miner_run, export)
    dashboard = export / "reports/dashboard.html"
    dashboard_ready(dashboard)
    progress(f"Resultados: análisis disponible en {dashboard.relative_to(root)}")

    # Reporter examina este proyecto de forma independiente.
    report_path = None
    report_error = None
    try:
        key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        model = os.environ.get("OPENROUTER_MODEL", "").strip() or DEFAULT_MODEL
        client = OpenRouterClient(model=model) if key else None
        progress(f"Reporter: analizando este proyecto ({'OpenRouter: ' + model if client else 'simulado'})")
        report_path = run_report(root, reporter_run, config, client=client, progress=progress)
        progress(f"Reporter: informe guardado en {report_path}")
        export_run(reporter_run, root / "results" / f"reporter-{identifier}")
    except (OSError, ValueError, RuntimeError) as error:
        report_error = str(error)
        progress(f"Reporter: no pudo terminar: {report_error}")
    return RunOutcome(dashboard=dashboard, export=export,
                      reporter_report=report_path, reporter_error=report_error)
