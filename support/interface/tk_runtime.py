"""Carga los archivos de Tkinter del entorno virtual del proyecto."""

import ctypes
import os
import sys
from pathlib import Path


def local_tk_directory() -> Path:
    """Devuelve el directorio local creado por install_tkinter.py."""
    return Path(sys.prefix) / "lib" / "tkinter-local"


def prepare(directory: Path | None = None) -> None:
    """Carga las bibliotecas Tcl/Tk antes de importar el paquete Python local."""
    root = (directory or local_tk_directory()).resolve()
    python = root / "python"
    tcl = root / "lib/libtcl8.6.so"
    tk = root / "lib/libtk8.6.so"
    scripts = (root / "tcl8.6", root / "tk8.6")
    if not all(path.exists() for path in (python / "tkinter", tcl, tk, *scripts)):
        raise RuntimeError(
            "Falta Tkinter local. Ejecuta: .venv/bin/python support/scripts/install_tkinter.py"
        )
    # Las rutas absolutas resuelven las dependencias Tcl/Tk sin cambiar la
    # configuración del sistema ni requerir permisos de administrador.
    try:
        ctypes.CDLL(str(tcl), mode=ctypes.RTLD_GLOBAL)
        ctypes.CDLL(str(tk), mode=ctypes.RTLD_GLOBAL)
    except OSError as error:
        raise RuntimeError(f"No se pudieron cargar las bibliotecas Tcl/Tk locales: {error}") from None
    os.environ["TCL_LIBRARY"] = str(scripts[0])
    os.environ["TK_LIBRARY"] = str(scripts[1])
    if str(python) not in sys.path:
        sys.path.insert(0, str(python))
