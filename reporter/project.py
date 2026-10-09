"""Datos acotados y sin secretos sobre los archivos de configuración del proyecto."""

import hashlib
import os
import re
from pathlib import Path
from typing import Callable

from support.core.models import RepositoryScan
from support.core.storage import (cleanup_work, fingerprint, initialize_run, own_directory,
                          sha256_file, write_json)
from miner.pipeline import STATUS_LABELS, git_run, save_scan, scan_source


MAX_FILE_BYTES = 128 * 1024
CONFIGURATION_FILES = (
    Path(".gitignore"), Path(".dockerignore"), Path("compose.yaml"),
    Path("requirements.txt"), Path("requirements-lock.txt"),
    Path("pyproject.toml"), Path("Dockerfile"),
    Path(".devcontainer/devcontainer.json"),
)
ACTION_REFERENCE = re.compile(r"\buses:\s*([^\s#]+)")


def project_file_evidence(source: Path) -> tuple[list[dict], list[str]]:
    """Expone rutas, hashes y señales estructurales, nunca el contenido de archivos."""
    root = source.resolve()
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    workflows += sorted((root / ".github/workflows").glob("*.yaml"))
    evidence, limitations = [], []
    if not workflows:
        limitations.append("No se encontraron workflows de GitHub en el proyecto analizado.")
    for name in CONFIGURATION_FILES:
        if name != Path("pyproject.toml") and not (root / name).is_file():
            limitations.append(f"No se encontró el archivo de configuración {name.as_posix()} en la copia analizada.")
    for path in [*(root / name for name in CONFIGURATION_FILES), *workflows]:
        # Solo se leen archivos permitidos y pequeños para acotar los metadatos.
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        relative = path.relative_to(root).as_posix()
        if path.stat().st_size > MAX_FILE_BYTES:
            limitations.append(f"Se omitió {relative} porque supera el límite de lectura.")
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            limitations.append(f"Se omitió {relative} porque no es texto UTF-8.")
            continue
        signals = []
        if relative.startswith(".github/workflows/"):
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                if re.match(r"pull_request_target\s*:", stripped):
                    signals.append(f"Línea {number}: se configuró el evento pull_request_target")
                if re.match(r"permissions\s*:\s*write-all\b", stripped):
                    signals.append(f"Línea {number}: se configuraron permisos write-all")
                match = ACTION_REFERENCE.search(stripped)
                if match and not match.group(1).startswith(("./", "docker://")):
                    reference = match.group(1).rsplit("@", 1)
                    if len(reference) != 2 or not re.fullmatch(r"[a-fA-F0-9]{40}", reference[1]):
                        signals.append(f"Línea {number}: la acción externa no está fijada a un commit SHA-1")
        if relative.endswith("Dockerfile"):
            for number, line in enumerate(lines, 1):
                if re.match(r"\s*FROM\s+\S+:latest\b", line, re.IGNORECASE):
                    signals.append(f"Línea {number}: la imagen base usa la etiqueta latest")
        if relative == ".devcontainer/devcontainer.json":
            for number, line in enumerate(lines, 1):
                if re.search(r'"privileged"\s*:\s*true', line):
                    signals.append(f"Línea {number}: está activado el modo privilegiado")
        digest = sha256_file(path)
        identifier = hashlib.sha256(f"{relative}\0{digest}".encode()).hexdigest()[:20]
        evidence.append({"id": f"project-file-{identifier}", "kind": "project_file",
                         "detail": {"file": relative, "sha256": digest, "signals": signals}})
    limitations.append("La revisión de configuración registra señales estructurales que requieren interpretación humana.")
    return evidence, limitations


PROJECT_FILES = frozenset({"main.py", "Dockerfile", "compose.yaml", "README.md", "AGENTS.md",
                           "pytest.ini", "requirements.txt", "requirements-lock.txt",
                           ".gitignore", ".dockerignore", "data/run-config.json"})
PROJECT_DIRECTORIES = frozenset({"miner", "analyzer", "visualizer", "reporter", "support",
                                 "docs", "agents", ".devcontainer", ".github"})
SOURCE_EXTENSIONS = frozenset({".py", ".js", ".json", ".md", ".txt", ".yaml", ".yml", ".toml"})


def snapshot_paths(source: Path):
    """Enumera solo código y configuración versionable del proyecto."""
    for relative in sorted(PROJECT_FILES):
        path = source / relative
        if path.is_file() and not path.is_symlink():
            yield path
    for directory in sorted(PROJECT_DIRECTORIES):
        base = source / directory
        if not base.is_dir() or base.is_symlink():
            continue
        for current, directories, names in os.walk(base, followlinks=False):
            directories[:] = sorted(name for name in directories
                                    if name not in {"__pycache__", ".pytest_cache", ".ipynb_checkpoints"}
                                    and not (Path(current) / name).is_symlink())
            for name in sorted(names):
                path = Path(current) / name
                if path.suffix in SOURCE_EXTENSIONS and path.is_file() and not path.is_symlink():
                    yield path


def snapshot_project(source: Path, destination: Path) -> dict:
    """Copia el proyecto de forma estable, sin secretos ni archivos generados."""
    source, destination = source.resolve(), destination.resolve()
    files = {}
    for path in snapshot_paths(source):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not path.resolve().is_relative_to(source):
                raise ValueError(f"Archivo fuera del proyecto: {relative}")
            contents = stream.read()
            after = os.fstat(stream.fileno())
        current = path.lstat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or (after.st_size, after.st_mtime_ns, after.st_ino) != (current.st_size, current.st_mtime_ns, current.st_ino):
            raise ValueError(f"El archivo cambió durante la copia: {relative}")
        target.write_bytes(contents)
        files[relative.as_posix()] = hashlib.sha256(contents).hexdigest()
    try:
        commit = git_run(["-C", str(source), "rev-parse", "HEAD"])
    except ValueError:
        commit = None
    try:
        dirty = bool(git_run(["-C", str(source), "status", "--porcelain"]))
    except ValueError:
        dirty = None
    return {"commit": commit, "working_tree_dirty": dirty, "source_sha256": fingerprint(files),
            "files": files, "omitted": [], "included_directories": sorted(PROJECT_DIRECTORIES)}


def scan_project(source: Path, run: Path, config: dict, *, keep_work=False,
                 progress: Callable[[str], None] | None = None) -> Path:
    """Analiza la copia y guarda un registro verificado para Reporter."""
    run = initialize_run(run)
    workspace = own_directory(run, "own-project-")
    if progress:
        progress("Reporter: creando una copia estable del proyecto")
    metadata = snapshot_project(source, workspace / "source")
    project_files, project_file_limitations = project_file_evidence(workspace / "source")
    write_json(run / "manifest.json", {"source": str(source.resolve()), "snapshot": metadata,
                                       "project_files": project_files,
                                       "project_file_limitations": project_file_limitations,
                                       "config": config, "config_sha256": fingerprint(config)})
    scan_progress = (lambda detail: progress(f"Reporter [local/EntregaFinal]: {detail}")) if progress else None
    scan_options = {"progress": scan_progress} if scan_progress else {}
    tools = scan_source(workspace / "source", run / "raw" / "project", ("python", "javascript"), config,
                        work_root=workspace / "codeql", **scan_options)
    scan = RepositoryScan(repository="local/EntregaFinal", url="local", config_sha256=fingerprint(config),
                          tools=tools, **{key: metadata[key] for key in
                                        ("commit", "working_tree_dirty", "source_sha256")})
    record = run / "records" / "001.json"
    save_scan(run, record, scan)
    if progress:
        progress("Reporter [local/EntregaFinal]: " + ", ".join(
            f"{tool.tool}={STATUS_LABELS.get(tool.status, tool.status)}" for tool in tools))
    if not keep_work:
        cleanup_work(run, workspace, record)
    return run
