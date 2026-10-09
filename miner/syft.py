"""Ejecuta Syft y guarda un SBOM CycloneDX JSON."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from support.core.paths import TOOLS_ROOT

LOCAL_SYFT = TOOLS_ROOT / "syft" / "syft"


class SyftError(RuntimeError):
    """Syft falló o devolvió un SBOM inutilizable."""


@dataclass(frozen=True)
class GeneratedSBOM:
    """Ruta y metadatos de un documento CycloneDX validado."""
    path: Path
    component_count: int
    generated_at: datetime


def _run(
    arguments: list[str], timeout: int = 300, *, executable: Path = LOCAL_SYFT,
) -> str:
    """Ejecuta Syft en un proceso aislado y normaliza los errores."""
    from support.core.process import ScannerError, run_tool

    try:
        return run_tool(
            executable, arguments, timeout=timeout,
            environment={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
        )
    except ScannerError as error:
        raise SyftError(str(error)) from error


def count_components(path: Path) -> int:
    """Valida el documento CycloneDX y cuenta sus componentes."""
    document = json.loads(path.read_bytes())
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise SyftError("Syft no produjo un JSON CycloneDX")
    components = document.get("components", [])
    if not isinstance(components, list):
        raise SyftError("La salida de Syft contiene un arreglo de componentes inválido")
    return len(components)


@dataclass(frozen=True)
class SyftRunner:
    """Genera un SBOM sin incluir cachés ni directorios de trabajo."""
    version: str
    executable: Path = LOCAL_SYFT
    timeout: int = 300
    exclusions: tuple[str, ...] = (
        "**/.git/**", "**/.venv/**", "**/venv/**", "**/.tools/**",
        "**/__pycache__/**", "**/runs/**", "**/.cache/**",
    )

    @classmethod
    def preflight(
        cls, executable: Path = LOCAL_SYFT, *, timeout: int = 300,
        exclusions: tuple[str, ...] | None = None,
    ) -> SyftRunner:
        """Comprueba el ejecutable local de Syft antes de analizar un repositorio."""
        if timeout < 1:
            raise SyftError("El tiempo máximo debe ser positivo")
        try:
            version = json.loads(_run(
                ["version", "-o", "json"], timeout=30, executable=executable,
            ))["version"]
        except (ValueError, KeyError, TypeError):
            raise SyftError("Syft devolvió una respuesta de versión inválida") from None
        if not isinstance(version, str) or not version:
            raise SyftError("Syft no informó su versión")
        return cls(
            version, executable, timeout,
            exclusions if exclusions is not None else cls.__dataclass_fields__["exclusions"].default,
        )

    def generate(self, checkout: Path, destination: Path) -> GeneratedSBOM:
        """Escribe en un archivo temporal y publica solo un SBOM validado."""
        checkout = checkout.expanduser().resolve()
        destination = destination.expanduser().resolve()
        if not checkout.is_dir():
            raise SyftError("No existe el directorio de código fuente")
        if destination.is_relative_to(checkout):
            raise SyftError("Guarda el SBOM fuera del directorio analizado")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix=".syft-", suffix=".cdx.json", dir=destination.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
        try:
            arguments = ["scan", f"dir:{checkout}"]
            for pattern in self.exclusions:
                arguments.extend(["--exclude", pattern])
            arguments.extend(["-o", f"cyclonedx-json={temporary}"])
            _run(arguments, self.timeout, executable=self.executable)
            count = count_components(temporary)
            temporary.replace(destination)
            return GeneratedSBOM(destination, count, datetime.now(timezone.utc))
        finally:
            temporary.unlink(missing_ok=True)
