"""Contratos validados para resultados y hallazgos guardados."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class OutputModel(BaseModel):
    """Rechaza campos desconocidos e impide modificar registros validados."""
    model_config = ConfigDict(extra="forbid", frozen=True)


class Finding(OutputModel):
    """Alerta de CodeQL con una ubicación relativa al repositorio."""
    rule_id: str = Field(min_length=1)
    message: str = Field(min_length=1)
    severity: Literal["error", "warning", "note", "none"] = "warning"
    file: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    security_severity: float | None = Field(
        default=None, ge=0, le=10, exclude_if=lambda value: value is None,
    )
    cwes: tuple[str, ...] = Field(default=(), exclude_if=lambda value: not value)

    @field_validator("file")
    @classmethod
    def validate_file(cls, value: str) -> str:
        """Bloquea rutas absolutas y recorridos antes de guardar evidencia."""
        normalized = value.replace("\\", "/")
        if normalized.startswith("/") or ":" in normalized or ".." in normalized.split("/"):
            raise ValueError("Las rutas de hallazgos deben ser relativas al repositorio.")
        return normalized


def finding_key(finding: Finding) -> tuple[object, ...]:
    """Devuelve los campos que identifican una alerta de código repetida."""
    return (
        finding.file,
        finding.start_line,
        finding.rule_id,
        finding.severity,
        finding.message,
    )


class ToolResult(OutputModel):
    """Estado, artefactos y datos de una herramienta para un repositorio."""
    tool: Literal["codeql", "syft", "grype"]
    status: Literal["success", "success_empty", "partial", "failed", "skipped", "unsupported"]
    version: str | None = None
    duration_seconds: float = Field(default=0, ge=0)
    artifacts: tuple[str, ...] = ()
    error: str | None = None
    warnings: tuple[str, ...] = ()
    data: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def consistent_status(self):
        """Exige una causa para análisis incompletos y ninguna para los exitosos."""
        if self.status in {"partial", "failed", "skipped", "unsupported"}:
            if not self.error:
                raise ValueError("Los análisis incompletos requieren una causa")
        elif self.error is not None:
            raise ValueError("Los análisis exitosos no pueden contener un error")
        return self


class DependencyFinding(OutputModel):
    """Coincidencia de Grype vinculada con una dependencia y posibles correcciones."""
    vulnerability_id: str = Field(min_length=1)
    namespace: str = ""
    package_id: str = ""
    package_name: str = Field(min_length=1)
    package_version: str
    package_type: str
    purl: str = ""
    severity: str = Field(min_length=1)
    fixed_versions: tuple[str, ...] = ()
    fix_state: str = "unknown"
    references: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()


class RepositoryScan(OutputModel):
    """Registro de repositorio con resultados de cada herramienta obligatoria."""
    repository: str
    url: str
    commit: str | None = None
    source_sha256: str | None = None
    working_tree_dirty: bool | None = None
    source_error: str | None = None
    config_sha256: str
    tools: tuple[ToolResult, ...]

    @model_validator(mode="after")
    def complete_tools(self):
        """Evita que una herramienta ausente desaparezca del cálculo de cobertura."""
        if sorted(item.tool for item in self.tools) != ["codeql", "grype", "syft"]:
            raise ValueError("Cada repositorio debe registrar las tres herramientas")
        return self
