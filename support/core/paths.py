"""Rutas del proyecto y herramientas compartidas por analizadores y contenedores."""

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOLS_ROOT = Path(os.environ.get("ICC610_TOOLS_DIR", PROJECT_ROOT / ".tools")).expanduser()
