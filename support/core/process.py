"""Procesos de análisis con tiempo limitado, aislados y sin credenciales."""

import json
import os
import subprocess
import tempfile
from pathlib import Path


class ScannerError(RuntimeError):
    """Fallo de ejecución cuyo mensaje se puede guardar de forma segura."""


def run_tool(
    executable: Path,
    arguments: list[str],
    *,
    timeout: int = 300,
    environment: dict[str, str] | None = None,
) -> str:
    """Ejecuta una herramienta con límite de tiempo y entorno aislado."""
    if timeout < 1:
        raise ScannerError("El tiempo máximo debe ser positivo")
    executable = executable.expanduser().resolve()
    allowed = {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.update(environment or {})

    with tempfile.TemporaryDirectory(prefix="reporter-scanner-") as temporary:
        env.update(HOME=temporary, USERPROFILE=temporary, XDG_CONFIG_HOME=temporary)
        try:
            result = subprocess.run(
                [str(executable), *arguments], check=True, capture_output=True,
                text=True, encoding="utf-8", timeout=timeout, cwd=temporary,
                env=env, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"{executable.name} superó los {timeout} segundos") from None
        except subprocess.CalledProcessError as error:
            # No expone stderr sin filtrar: podría contener código o secretos.
            raise ScannerError(f"{executable.name} terminó con código {error.returncode}") from None
        except (OSError, UnicodeError):
            raise ScannerError(f"No se puede ejecutar {executable.name} o leer su salida") from None
    return result.stdout


def json_object(raw: str) -> dict:
    """Exige una salida JSON de tipo objeto antes de leer sus campos."""
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise ScannerError("La herramienta devolvió un JSON inválido") from None
    if not isinstance(value, dict):
        raise ScannerError("La herramienta debe devolver un objeto JSON")
    return value
