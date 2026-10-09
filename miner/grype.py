"""Ejecución de Grype e interpretación de su evidencia JSON."""

import os
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from support.core.models import DependencyFinding
from support.core.paths import PROJECT_ROOT, TOOLS_ROOT
from support.core.process import ScannerError, json_object, run_tool

LOCAL_GRYPE = TOOLS_ROOT / "grype" / "grype"
GRYPE_CACHE = Path(os.environ.get("ICC610_GRYPE_CACHE_DIR", PROJECT_ROOT / ".cache" / "grype")).expanduser()


class GrypeError(ScannerError):
    """Grype devolvió un resultado o estado de base de datos inutilizable."""


def parse_grype(document: dict) -> tuple[DependencyFinding, ...]:
    """Conserva datos de vulnerabilidades, paquetes, correcciones y avisos."""
    matches = document.get("matches")
    if not isinstance(matches, list):
        raise GrypeError("La salida de Grype debe incluir un arreglo matches")
    findings = []
    try:
        for match in matches:
            vulnerability, package = match["vulnerability"], match["artifact"]
            fix = vulnerability.get("fix") or {}
            references = [vulnerability.get("dataSource", "")]
            references.extend(vulnerability.get("urls") or [])
            references.extend(item["link"] for item in vulnerability.get("advisories") or [])
            findings.append(DependencyFinding(
                vulnerability_id=vulnerability["id"],
                namespace=vulnerability.get("namespace", ""),
                package_id=package.get("id", ""), package_name=package["name"],
                package_version=package["version"], package_type=package["type"],
                purl=package.get("purl", ""), severity=vulnerability["severity"],
                fixed_versions=tuple(fix.get("versions") or []),
                fix_state=fix.get("state") or "unknown",
                references=tuple(sorted(set(value for value in references if value))),
                locations=tuple(item["path"] for item in package.get("locations") or []),
            ))
    except (KeyError, TypeError, AttributeError, ValidationError):
        raise GrypeError("Coincidencia de vulnerabilidad inválida en la salida de Grype") from None
    return tuple(findings)


@dataclass(frozen=True)
class GrypeRunner:
    """Ejecuta Grype con una base local administrada explícitamente."""
    version: str
    executable: Path = LOCAL_GRYPE
    timeout: int = 300
    cache_dir: Path = GRYPE_CACHE

    def run(self, arguments: list[str]) -> str:
        """Desactiva las actualizaciones y fuentes externas durante el análisis."""
        return run_tool(self.executable, arguments, timeout=self.timeout, environment={
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            "GRYPE_DB_AUTO_UPDATE": "false",
            "GRYPE_DB_CACHE_DIR": str(self.cache_dir.resolve()),
            "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
        })

    @classmethod
    def preflight(cls, executable=LOCAL_GRYPE, *, timeout=300, cache_dir=None):
        """Comprueba que Grype se ejecute e informe una versión válida."""
        provisional = cls("", Path(executable), timeout, cache_dir or cls.__dataclass_fields__["cache_dir"].default)
        version = json_object(provisional.run(["version", "-o", "json"])).get("version")
        if not isinstance(version, str) or not version:
            raise GrypeError("Grype no informó su versión")
        return cls(version, provisional.executable, timeout, provisional.cache_dir)

    def database_status(self, *, update=False) -> dict:
        """Lee los metadatos de la base y la actualiza solo si se solicita."""
        if update:
            self.run(["db", "update"])
        status = json_object(self.run(["db", "status", "-o", "json"]))
        if status.get("error") or status.get("valid") is not True:
            raise GrypeError("La base de vulnerabilidades de Grype no es válida")
        return status

    def scan(self, sbom: Path, destination: Path) -> dict:
        """Analiza el SBOM guardado y lee la salida JSON original de Grype."""
        self.run([f"sbom:{sbom.resolve()}", "-o", "json", "--file", str(destination.resolve())])
        return json_object(destination.read_text(encoding="utf-8"))
