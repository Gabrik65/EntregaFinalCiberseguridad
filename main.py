"""Coordina la selección, extracción, análisis, visualización y generación de informes."""

from functools import wraps
from pathlib import Path
import sys

import typer
import typer.rich_utils as rich_utils
from typer.core import TyperCommand, TyperGroup

from analyzer.prepare import prepare_data
from analyzer.notebook import analyze
from support.core.storage import read_json, write_json
from support.core.config import repository_limit
from support.interface.runner import run_analysis
from miner.grype import GrypeRunner
from reporter.client import OpenRouterClient
from miner.pipeline import ROOT, mine as run_miner, select_repositories, tool_configuration
from reporter.generate import run_report
from visualizer.dashboard import generate_html

def spanish_help(value: str) -> str:
    """Traduce los rótulos que Typer agrega automáticamente a la ayuda."""
    for original, translated in (
        ("Usage:", "Uso:"), ("Options", "Opciones"), ("Commands", "Comandos"),
        ("Arguments", "Argumentos"), ("Show this message and exit.", "Muestra esta ayuda y sale."),
        ("[default:", "[predeterminado:"), ("[OPTIONS]", "[OPCIONES]"),
        ("COMMAND", "COMANDO"), ("[ARGS]", "[ARGUMENTOS]"),
    ):
        value = value.replace(original, translated)
    return value


# Typer imprime las secciones con Rich antes de devolver el texto de ayuda.
rich_utils.ARGUMENTS_PANEL_TITLE = "Argumentos"
rich_utils.OPTIONS_PANEL_TITLE = "Opciones"
rich_utils.COMMANDS_PANEL_TITLE = "Comandos"
rich_utils.DEFAULT_STRING = "[predeterminado: {}]"
rich_utils.RICH_HELP = "Usa [blue]'{command_path} {help_option}'[/] para ver la ayuda."


class SpanishHelp:
    """Traduce la sintaxis y la descripción automática de --help."""

    def get_usage(self, context):
        """Muestra la sintaxis de uso con rótulos en español."""
        return spanish_help(super().get_usage(context))

    def get_help_option(self, context):
        """Traduce la opción de ayuda creada por Typer."""
        option = super().get_help_option(context)
        if option is not None:
            option.help = "Muestra esta ayuda y sale."
        return option


class SpanishCommand(SpanishHelp, TyperCommand):
    """Presenta la ayuda automática de un subcomando en español."""


class SpanishGroup(SpanishHelp, TyperGroup):
    """Presenta la ayuda automática del comando principal en español."""


# Typer permite ejecuciones por terminal; sin argumentos se abre la interfaz Tk.
app = typer.Typer(add_completion=False, no_args_is_help=True, cls=SpanishGroup)


def guarded(function):
    """Muestra errores operativos esperados sin la traza de Python."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        """Convierte excepciones esperadas en errores con código de salida distinto de cero."""
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, RuntimeError) as error:
            typer.echo(f"Error: {error}", err=True)
            raise typer.Exit(code=1) from None
    return wrapped


@app.callback(invoke_without_command=True)
@guarded
def entry(ctx: typer.Context, no_gui: bool = typer.Option(False, "--no-gui",
              help="Ejecuta todo el flujo en esta terminal sin Tkinter."),
          organization: str = typer.Option("nestjs", help="Organización de GitHub para --no-gui."),
          limit: int = typer.Option(repository_limit(), min=1, max=50, help="Cantidad máxima de repositorios para --no-gui."),
          timeout: int = typer.Option(900, min=1, help="Tiempo máximo por proceso para --no-gui.")):
    """Ejecuta el flujo completo sin GUI o delega en el subcomando elegido."""
    if ctx.invoked_subcommand is not None:
        if no_gui:
            raise ValueError("--no-gui no se puede combinar con un subcomando")
        return
    if not no_gui:
        raise ValueError("Usa --no-gui para el flujo completo o elige un subcomando")
    outcome = run_analysis(organization, limit, typer.echo,
                           lambda path: typer.echo(f"Panel disponible: {path}"), timeout=timeout)
    typer.echo(f"Resultados portables: {outcome.export}")
    if outcome.reporter_error:
        typer.echo(f"Reporter no terminó: {outcome.reporter_error}", err=True)
        raise typer.Exit(code=1)


def configuration(path: Path | None, timeout: int):
    """Lee rutas opcionales y registra una configuración reproducible de herramientas."""
    values = read_json(path) if path else {}
    allowed = {"codeql", "syft", "grype"}
    if set(values) - allowed:
        raise ValueError("La configuración solo acepta rutas para codeql, syft y grype")
    return tool_configuration(timeout=timeout, **{k: Path(v) for k, v in values.items()})


def run_manifest(manifest_path: Path, settings_path: Path) -> dict:
    """Selecciona un prefijo determinista sin alterar la muestra congelada."""
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("El manifiesto de repositorios debe ser un objeto JSON")
    limit = repository_limit(settings_path)
    repositories = manifest.get("repositories")
    if (not isinstance(repositories, list) or not repositories or isinstance(limit, bool)
            or not isinstance(limit, int) or limit < 1):
        raise ValueError("repository_limit debe ser positivo y el manifiesto no puede estar vacío")
    selected = {**manifest, "repositories": repositories[:limit],
                "requested_count": min(limit, len(repositories)), "repository_limit": limit}
    if limit < len(repositories):
        selected["development_subset_of"] = len(repositories)
    return selected


@app.command(cls=SpanishCommand)
@guarded
def select(organization: str = "nestjs", count: int = typer.Option(repository_limit(), min=1, max=50),
           output: Path = ROOT / "data/nestjs-manifest.json"):
    """Selecciona repositorios públicos y fija sus revisiones exactas."""
    if output.exists():
        raise ValueError("El manifiesto ya existe; elige otra ruta para conservar la muestra")
    manifest = select_repositories(organization, count)
    write_json(output, manifest)
    typer.echo(f"Seleccionados {len(manifest['repositories'])}/{count}: {output}")


@app.command("mine", cls=SpanishCommand)
@guarded
def mine_command(manifest: Path | None = None,
                 run: Path = ROOT / "runs/nestjs", timeout: int = typer.Option(300, min=1),
                 tools: Path | None = None, run_config: Path = ROOT / "data/run-config.json",
                 resume: bool = False, keep_work: bool = False):
    """Ejecuta los tres analizadores; reemplaza una ejecución propia salvo al reanudarla."""
    if manifest is not None:
        selected = run_manifest(manifest, run_config)
        source = str(manifest)
    elif resume:
        selected = read_json(run / "manifest.json")["selection"]
        source = str(run / "manifest.json")
    else:
        limit = repository_limit(run_config)
        selected = select_repositories("nestjs", limit)
        source = "GitHub: nestjs"
    if not selected["repositories"]:
        raise ValueError("No se encontraron repositorios públicos elegibles")
    typer.echo(f"Procesando {len(selected['repositories'])} repositorios desde {source}")
    run_miner(selected, run, configuration(tools, timeout), resume=resume, keep_work=keep_work)
    typer.echo(f"Registros guardados de {len(selected['repositories'])} repositorios: {run}")


@app.command("analyze", cls=SpanishCommand)
@guarded
def analyze_command(run: Path = ROOT / "runs/nestjs", execute: bool = True):
    """Valida registros y genera datos preparados y un notebook ejecutable."""
    typer.echo(str(analyze(prepare_data(run), run, execute=execute)))


@app.command("visualize", cls=SpanishCommand)
@guarded
def visualize_command(run: Path = ROOT / "runs/nestjs"):
    """Genera el panel desde los datos guardados por Analyzer."""
    data = read_json(run / "prepared/data.json")
    typer.echo(str(generate_html(data, run / "reports/dashboard.html")))


@app.command("report", cls=SpanishCommand)
@guarded
def report_command(source: Path = ROOT, run: Path = ROOT / "runs/reporter",
                   timeout: int = typer.Option(300, min=1), tools: Path | None = None,
                   keep_work: bool = False, llm: str = "simulated", model: str | None = None,
                   resume: bool = False):
    """Analiza este proyecto y genera un informe validado, simulado o con OpenRouter."""
    if llm not in {"simulated", "openrouter"}:
        raise ValueError("--llm debe ser simulated u openrouter")
    client = OpenRouterClient(model=model) if llm == "openrouter" else None
    path = run_report(source, run, configuration(tools, timeout), client=client,
                      resume=resume, keep_work=keep_work)
    typer.echo(f"Informe {llm.upper()}: {path}")


@app.command("update-db", cls=SpanishCommand)
@guarded
def update_database(timeout: int = typer.Option(300, min=1)):
    """Actualiza explícitamente la base de vulnerabilidades antes de una ejecución."""
    runner = GrypeRunner.preflight(timeout=timeout)
    typer.echo(str(runner.database_status(update=True)))


@app.command("export", cls=SpanishCommand)
@guarded
def export_command(run: Path = typer.Option(...), destination: Path = typer.Option(...)):
    """Exporta evidencias e informes sin herramientas, bases de datos ni clones."""
    from support.core.export import export_run
    typer.echo(str(export_run(run, destination)))


@app.command("poster", cls=SpanishCommand)
@guarded
def poster_command(run: Path = typer.Option(...), destination: Path = typer.Option(...),
                   reporter_run: Path | None = None):
    """Genera la plantilla de afiche A0 y el guion breve desde una ejecución."""
    from visualizer.poster import write_poster
    reporter_mode = "pending"
    if reporter_run is not None:
        reporter_mode = read_json(reporter_run / "reports/report-provenance.json")["provider"]
    write_poster(prepare_data(run), destination, reporter_mode=reporter_mode)
    typer.echo(str(destination))


if __name__ == "__main__":
    # Importa Tk solo para la GUI; los subcomandos funcionan sin entorno gráfico.
    if len(sys.argv) == 1:
        try:
            from support.interface.tk_runtime import prepare
            prepare()
            from support.interface.app import launch
            launch()
        except ModuleNotFoundError as error:
            if error.name not in {"tkinter", "_tkinter"}:
                raise
            typer.echo("Falta Tkinter local. Ejecuta: .venv/bin/python support/scripts/install_tkinter.py", err=True)
            raise SystemExit(1) from None
        except RuntimeError as error:
            typer.echo(f"No se pudo abrir la interfaz: {error}", err=True)
            raise SystemExit(1) from None
    else:
        app()
