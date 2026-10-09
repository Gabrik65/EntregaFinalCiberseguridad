"""Valida la estructura y los vínculos con la evidencia antes de generar un informe."""

import json
from pydantic import Field, StrictBool, StrictInt
from support.core.models import OutputModel


class Statistics(OutputModel):
    """Totales numéricos esperados de la evidencia preparada por Python."""
    repositories: StrictInt
    expected_repositories: StrictInt
    code_findings: StrictInt
    dependency_findings: StrictInt
    components: StrictInt
    coverage: dict[str, dict[str, StrictInt]]


class Observation(OutputModel):
    """Afirmación del modelo vinculada con al menos un ID de evidencia conocido."""
    text: str = Field(min_length=1)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    recommendation: str | None = None


class ReportResponse(OutputModel):
    """Estructura JSON estricta aceptada de ambos clientes de Reporter."""
    simulated: StrictBool
    summary: str = Field(min_length=1)
    statistics: Statistics
    observations: tuple[Observation, ...]
    limitations: tuple[str, ...]


def validate_response(raw: str, payload: dict, *, expected_simulated: bool = True) -> ReportResponse:
    """Rechaza respuestas inválidas, cifras cambiadas y referencias inventadas."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 120000:
        raise ValueError("La respuesta del informe está vacía o excede el tamaño permitido")
    # Rechaza claves JSON duplicadas, además de JSON inválido o truncado.
    def unique_pairs(pairs):
        """Impide que claves JSON duplicadas sobrescriban valores anteriores."""
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("La respuesta JSON contiene una clave duplicada")
            result[key] = value
        return result
    response = ReportResponse.model_validate(json.loads(raw, object_pairs_hook=unique_pairs))
    if response.simulated is not expected_simulated:
        raise ValueError("El indicador de simulación no coincide con el cliente elegido")
    if response.statistics.model_dump() != payload["statistics"]:
        raise ValueError("Las estadísticas de la respuesta difieren de los valores calculados")
    allowed = {item["id"] for item in payload["evidence"]}
    if any(identifier not in allowed for observation in response.observations for identifier in observation.evidence_ids):
        raise ValueError("La respuesta cita evidencia desconocida")
    if not set(payload["limitations"]).issubset(response.limitations):
        raise ValueError("La respuesta omite limitaciones presentes en la entrada")
    return response
