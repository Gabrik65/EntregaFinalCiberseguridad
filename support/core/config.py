"""Configuración compartida de la muestra evaluada."""

from pathlib import Path

from support.core.paths import PROJECT_ROOT
from support.core.storage import read_json


def repository_limit(path: Path = PROJECT_ROOT / "data/run-config.json") -> int:
    """Lee y valida el límite usado por GUI, CLI y Miner."""
    settings = read_json(path)
    if not isinstance(settings, dict) or set(settings) != {"repository_limit"}:
        raise ValueError("La configuración de ejecución solo debe contener repository_limit")
    limit = settings["repository_limit"]
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 50:
        raise ValueError("repository_limit debe estar entre 1 y 50")
    return limit
