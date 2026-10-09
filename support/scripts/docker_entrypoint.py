"""Inicia comandos del contenedor con una base de Grype utilizable y persistente."""

import os
import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path("/workspace")


def scanning_command(arguments: list[str]) -> bool:
    """Permite comandos de lectura aunque la base de datos no esté disponible."""
    if len(arguments) < 2 or Path(arguments[1]).name != "main.py":
        return False
    options = arguments[2:]
    return not options or options[0] in {"mine", "report", "--no-gui"}


def prepare_database() -> None:
    """Prepara el caché inicial y actualiza solo una base ausente o inválida."""
    sys.path.insert(0, str(PROJECT_ROOT))
    from miner.grype import GRYPE_CACHE, GrypeRunner

    cache = GRYPE_CACHE
    cache.mkdir(parents=True, exist_ok=True)
    if not any(cache.iterdir()):
        seed = Path(os.environ.get("ICC610_GRYPE_SEED_DIR", "/opt/icc610/grype-seed"))
        if not seed.is_dir():
            raise RuntimeError("La imagen Docker no contiene una base inicial de Grype")
        shutil.copytree(seed, cache, dirs_exist_ok=True)
    runner = GrypeRunner.preflight(cache_dir=cache)
    try:
        runner.database_status()
    except (OSError, ValueError, RuntimeError):
        print("La base de Grype no está disponible o caducó; se actualizará ahora.", flush=True)
        runner.database_status(update=True)


def main() -> None:
    """Sustituye este proceso por el comando solicitado tras preparar el entorno."""
    command = sys.argv[1:] or ["python", "main.py", "--no-gui"]
    if scanning_command(command):
        prepare_database()
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
