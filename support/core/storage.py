"""Guardado atómico y limpieza limitada a directorios propios de una ejecución."""

import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path


def fingerprint(value) -> str:
    """Calcula el hash de un JSON con orden estable de claves."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def sha256_file(path: Path) -> str:
    """Calcula el hash por partes para no cargar archivos grandes en memoria."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value) -> Path:
    """Escribe JSON de forma atómica para evitar registros incompletos."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".saving-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def read_json(path: Path):
    """Lee JSON UTF-8 de un manifiesto, registro o informe guardado."""
    return json.loads(path.read_text(encoding="utf-8"))


def initialize_run(root: Path) -> Path:
    """Crea una ejecución con marca de propiedad y directorios estándar."""
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=False)
    write_json(root / ".run-owner.json", {"id": uuid.uuid4().hex})
    for directory in ("raw", "records", "prepared", "reports", "logs", "work"):
        (root / directory).mkdir()
    return root


def initialize_or_replace_run(root: Path) -> Path:
    """Inicia una ejecución y reemplaza solo una anterior propiedad del programa."""
    root = root.expanduser().absolute()
    if root.is_symlink():
        raise ValueError("El directorio de ejecución no puede ser un enlace simbólico")
    if root.exists():
        expected_directories = {"raw", "records", "prepared", "reports", "logs", "work"}
        allowed_entries = expected_directories | {".run-owner.json", "manifest.json"}
        if not root.is_dir() or {path.name for path in root.iterdir()} - allowed_entries:
            raise ValueError("El directorio existente contiene archivos ajenos a la estructura de ejecución")
        if any(not (root / name).is_dir() or (root / name).is_symlink()
               for name in expected_directories):
            raise ValueError("El directorio existente no es una ejecución propia válida")
        marker = root / ".run-owner.json"
        if marker.is_symlink() or not marker.is_file():
            raise ValueError("El directorio existente no pertenece a este programa")
        owner = read_json(marker)
        if (not isinstance(owner, dict) or not isinstance(owner.get("id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", owner["id"])):
            raise ValueError("El directorio existente tiene una marca de propiedad inválida")
        shutil.rmtree(root)
    return initialize_run(root)


def own_directory(run: Path, prefix: str) -> Path:
    """Crea trabajo temporal vinculado con la marca de propiedad de la ejecución."""
    marker = read_json(run / ".run-owner.json")
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=run / "work"))
    write_json(path / ".owned.json", marker)
    return path


def verify_artifacts(run: Path, record: dict) -> None:
    """Comprueba que cada artefacto exista dentro de la ejecución y tenga el hash esperado."""
    from support.core.models import RepositoryScan

    scan = RepositoryScan.model_validate({k: v for k, v in record.items() if k != "artifact_hashes"})
    expected = {path for tool in scan.tools for path in tool.artifacts}
    if set(record.get("artifact_hashes", {})) != expected:
        raise ValueError("El inventario de artefactos no coincide con el resultado guardado")
    for relative, digest in record["artifact_hashes"].items():
        path = (run / relative).resolve()
        if not path.is_relative_to(run.resolve()) or not path.is_file():
            raise ValueError("Falta un artefacto o está fuera de la ejecución")
        if sha256_file(path) != digest:
            raise ValueError(f"El hash del artefacto no coincide: {relative}")


def cleanup_work(run: Path, workspace: Path, saved_record: Path) -> None:
    """Elimina trabajo temporal propio solo tras verificar la evidencia guardada."""
    run = run.resolve()
    workspace = workspace.absolute()
    if workspace.is_symlink() or workspace.resolve().parent != run / "work":
        raise ValueError("El destino de limpieza no es un espacio propio directo de la ejecución")
    if read_json(workspace / ".owned.json") != read_json(run / ".run-owner.json"):
        raise ValueError("La propiedad del destino de limpieza no coincide")
    if not saved_record.resolve().is_relative_to(run / "records"):
        raise ValueError("La limpieza requiere un registro guardado en esta ejecución")
    record = read_json(saved_record)
    verify_artifacts(run, record)
    shutil.rmtree(workspace)
