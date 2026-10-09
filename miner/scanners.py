"""Ejecuta CodeQL, Syft y Grype y registra resultados coherentes."""

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from time import monotonic

from support.core.models import ToolResult
from miner.codeql import CODEQL_EXECUTABLE, NO_BUILD_LANGUAGES, CodeQLError, CodeQLRunner
from miner.grype import GrypeRunner, LOCAL_GRYPE, parse_grype
from support.core.process import ScannerError
from miner.sarif import SarifError, parse_sarif
from miner.syft import LOCAL_SYFT, SyftError, SyftRunner


def analyze_codeql(checkout, output_root, languages=("python",), *, runner=None,
                   executable=None, timeout=1800, work_root=None):
    """Analiza el código y conserva SARIF y resultados por lenguaje."""
    started = monotonic()
    version = runner.version if runner else None
    results, findings, artifacts = [], [], []
    try:
        checkout, output_root = Path(checkout).resolve(), Path(output_root).resolve()
        if not checkout.is_dir():
            raise ValueError("No existe el directorio de código fuente")
        if output_root.is_relative_to(checkout):
            raise ValueError("Guarda los artefactos fuera del directorio de código fuente")
        selected = tuple(sorted(set(languages)))
        if not selected:
            return ToolResult(tool="codeql", status="unsupported", error="No se seleccionaron lenguajes compatibles")
        runner = runner or CodeQLRunner.preflight(executable or CODEQL_EXECUTABLE, timeout=timeout)
        version = runner.version
        output_root.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(prefix="codeql-", dir=output_root))
        work_root = Path(work_root).resolve() if work_root else run_root / "work"
        for language in selected:
            # Un lenguaje no compatible permanece visible, sin contarse como cero alertas.
            if language not in runner.available_languages or language not in NO_BUILD_LANGUAGES:
                results.append({"language": language, "status": "unsupported",
                                "error": "Extractor no disponible o herramientas de compilación desactivadas"})
                continue
            sarif = run_root / f"{language}.sarif"
            try:
                database = runner.create_database(language, checkout, work_root / "databases")
                runner.analyze_database(
                    database, language, sarif, work_root / f"{language}-analysis",
                )
                parsed = parse_sarif(sarif, checkout)
                findings.extend(item.model_dump(mode="json") for item in parsed)
                results.append({"language": language,
                                "status": "success" if parsed else "success_empty"})
            except (CodeQLError, SarifError, OSError) as error:
                results.append({"language": language, "status": "failed", "error": str(error)})
            if sarif.is_file():
                artifacts.append(str(sarif))
            if results[-1]["status"] == "failed":
                # Conserva diagnósticos de fallos sin conservar la base temporal.
                for log in work_root.rglob("*.log"):
                    if log.is_file():
                        saved_log = run_root / "diagnostics" / log.relative_to(work_root)
                        saved_log.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(log, saved_log)
                        if str(saved_log) not in artifacts:
                            artifacts.append(str(saved_log))
        completed = sum(item["status"] in {"success", "success_empty"} for item in results)
        # Un éxito parcial conserva hallazgos válidos e identifica lenguajes fallidos.
        if completed == len(results):
            status = "success" if findings else "success_empty"
        elif completed:
            status = "partial"
        elif all(item["status"] == "unsupported" for item in results):
            status = "unsupported"
        else:
            status = "failed"
        error = "; ".join(f"{item['language']}: {item['error']}" for item in results if item.get("error"))
        return ToolResult(
            tool="codeql", status=status, version=version, error=error or None,
            duration_seconds=monotonic() - started, artifacts=tuple(artifacts),
            data={"languages": results, "findings": findings},
        )
    except (CodeQLError, OSError, ValueError) as error:
        return ToolResult(tool="codeql", status="failed", version=version,
                          duration_seconds=monotonic() - started, error=str(error))


def analyze_syft(checkout, output_root, *, runner=None, executable=None, timeout=300):
    """Produce un SBOM validado sin requerir organización ni commit."""
    started = monotonic()
    version = runner.version if runner else None
    try:
        checkout, output_root = Path(checkout).resolve(), Path(output_root).resolve()
        if not checkout.is_dir():
            raise ValueError("No existe el directorio de código fuente")
        if output_root.is_relative_to(checkout):
            raise ValueError("Guarda los artefactos fuera del directorio de código fuente")
        runner = runner or SyftRunner.preflight(executable or LOCAL_SYFT, timeout=timeout)
        version = runner.version
        output_root.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(prefix="syft-", dir=output_root))
        generated = runner.generate(checkout, run_root / "sbom.cdx.json")
        raw = generated.path.read_bytes()
        # El hash del SBOM vincula la entrada de Grype con la salida exacta de Syft.
        document = json.loads(raw)
        components = document.get("components", [])
        if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in components):
            raise SyftError("Componente inválido en el SBOM")
        missing_versions = sum(not item.get("version") for item in components)
        warnings = []
        if not components:
            warnings.append("No se identificaron componentes; esto no demuestra ausencia de dependencias")
        if missing_versions:
            warnings.append(f"{missing_versions} componentes no tienen versión identificada")
        return ToolResult(
            tool="syft", status="success" if components else "success_empty", version=version,
            artifacts=(str(generated.path),), warnings=tuple(warnings),
            duration_seconds=monotonic() - started,
            data={"component_count": len(components), "components": components,
                  "missing_versions": missing_versions,
                  "sbom_sha256": hashlib.sha256(raw).hexdigest(),
                  "exclusions": list(getattr(runner, "exclusions", ()))},
        )
    except (SyftError, OSError, ValueError, subprocess.SubprocessError) as error:
        return ToolResult(tool="syft", status="failed", version=version,
                          duration_seconds=monotonic() - started, error=str(error))


def analyze_grype(sbom: ToolResult, output_root: Path, *, runner=None,
                  executable=LOCAL_GRYPE, timeout=300) -> ToolResult:
    """Analiza solo un SBOM verificado de Syft y conserva el JSON de Grype."""
    started = monotonic()
    if sbom.tool != "syft" or sbom.status not in {"success", "success_empty"}:
        return ToolResult(tool="grype", status="skipped", error="Syft no produjo un SBOM utilizable")
    version = runner.version if runner else None
    database, artifacts = {}, ()
    output = None
    try:
        if len(sbom.artifacts) != 1:
            raise ValueError("Se esperaba exactamente un artefacto SBOM")
        source = Path(sbom.artifacts[0])
        if hashlib.sha256(source.read_bytes()).hexdigest() != sbom.data["sbom_sha256"]:
            raise ValueError("El SBOM cambió después de la validación de Syft")
        runner = runner or GrypeRunner.preflight(executable, timeout=timeout)
        version = runner.version
        database = runner.database_status()
        output_root = Path(output_root).resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(prefix="grype-", dir=output_root))
        output = run_root / "vulnerabilities.json"
        document = runner.scan(source, output)
        artifacts = (str(output),)
        findings = parse_grype(document)
        return ToolResult(
            tool="grype", status="success" if findings else "success_empty", version=version,
            duration_seconds=monotonic() - started, artifacts=artifacts, warnings=sbom.warnings,
            data={"findings": [item.model_dump(mode="json") for item in findings],
                  "database": database, "component_count": sbom.data["component_count"],
                  "sbom_sha256": sbom.data["sbom_sha256"]},
        )
    except (ScannerError, OSError, ValueError, KeyError) as error:
        return ToolResult(
            tool="grype", status="failed", version=version, error=str(error),
            duration_seconds=monotonic() - started,
            artifacts=(str(output),) if output is not None and output.is_file() else artifacts,
            warnings=sbom.warnings, data={"database": database},
        )
