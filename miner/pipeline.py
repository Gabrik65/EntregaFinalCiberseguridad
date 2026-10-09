"""Selección pública, análisis de revisiones fijadas y registros reanudables."""

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

from support.core.models import RepositoryScan, ToolResult
from support.core.config import repository_limit
from support.core.paths import PROJECT_ROOT, TOOLS_ROOT
from support.core.storage import (cleanup_work, fingerprint, initialize_or_replace_run, own_directory,
                          read_json, sha256_file, verify_artifacts, write_json)
from miner.codeql import CODEQL_EXECUTABLE, select_supported_languages
from miner.grype import GrypeRunner, LOCAL_GRYPE
from miner.scanners import analyze_codeql, analyze_grype, analyze_syft
from miner.syft import LOCAL_SYFT

ROOT = PROJECT_ROOT
STATUS_LABELS = {"success": "completado", "success_empty": "sin resultados",
                 "partial": "parcial", "failed": "fallido",
                 "skipped": "omitido", "unsupported": "no compatible"}


def tool_configuration(*, codeql=CODEQL_EXECUTABLE, syft=LOCAL_SYFT,
                       grype=LOCAL_GRYPE, timeout=300) -> dict:
    """Registra rutas, hashes, base de datos y código para poder reanudar."""
    if timeout < 1:
        raise ValueError("El tiempo máximo debe ser positivo")
    tools = {}
    for name, path in (("codeql", codeql), ("syft", syft), ("grype", grype)):
        path = Path(path).expanduser().resolve()
        tools[name] = {"executable": str(path),
                       "sha256": sha256_file(path) if path.is_file() else None}
    db = {}
    try:
        db = GrypeRunner.preflight(grype, timeout=timeout).database_status()
    except (RuntimeError, OSError, ValueError) as error:
        db = {"unavailable": str(error)}
    # Solo el código de las herramientas afecta la reanudación, no el HTML ni el informe.
    modules = ["support/core/models.py", "support/core/paths.py", "support/core/storage.py", "support/core/process.py", "miner/pipeline.py",
               "miner/codeql.py", "miner/scanners.py", "miner/sarif.py", "miner/syft.py",
               "miner/grype.py"]
    node = TOOLS_ROOT / "node/bin/node"
    return {"tools": tools, "timeout": timeout, "database": db,
            "node_sha256": sha256_file(node) if node.is_file() else None,
            "scanner_code": {name: sha256_file(ROOT / name) for name in modules},
            "language_policy": "github-primary-language-no-build"}


def github_get(session: requests.Session, path: str):
    """Solicita un recurso de la API de GitHub con tiempo limitado."""
    response = session.get(f"https://api.github.com/{path}", timeout=30)
    if response.status_code != 200:
        raise ValueError(f"GitHub respondió con HTTP {response.status_code} para {path.split('?')[0]}")
    return response.json()


def select_repositories(organization="nestjs", count=None, *, session=None) -> dict:
    """Selecciona repositorios públicos y fija sus commits con pocas consultas a GitHub."""
    if count is None:
        count = repository_limit()
    if (not re.fullmatch(r"[A-Za-z0-9-]+", organization) or isinstance(count, bool)
            or not isinstance(count, int) or not 1 <= count <= 50):
        raise ValueError("Organización o cantidad de repositorios inválida")
    client = session or requests.Session()
    client.headers.update({"Accept": "application/vnd.github+json"})
    if os.environ.get("GITHUB_TOKEN"):
        client.headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    candidates = []
    try:
        for page in range(1, 101):
            batch = github_get(client, f"orgs/{organization}/repos?type=public&per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("GitHub devolvió una lista de repositorios inválida")
            candidates.extend(item for item in batch if not item.get("private")
                              and not item.get("archived") and not item.get("fork"))
            if len(batch) < 100:
                break
        else:
            raise ValueError("Se alcanzó el límite de páginas de repositorios")
        # El orden estable deja los nombres en ascenso si coinciden las fechas.
        candidates.sort(key=lambda item: item["full_name"].casefold())
        candidates.sort(key=lambda item: item["updated_at"], reverse=True)
        selected = []
        for item in candidates[:count]:
            full_name = item["full_name"]
            if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", full_name):
                raise ValueError("GitHub devolvió un nombre de repositorio inseguro")
            error = None
            try:
                commit = github_get(client, f"repos/{full_name}/commits/{item['default_branch']}")["sha"]
            except (requests.RequestException, ValueError, KeyError) as exc:
                commit, error = None, str(exc)
            # El listado de la organización ya entrega el lenguaje principal.
            primary = item.get("language")
            top = [primary] if isinstance(primary, str) and primary else []
            selected.append({"repository": full_name,
                             "url": f"https://github.com/{full_name}.git",
                             "commit": commit, "updated_at": item["updated_at"],
                             "category": primary or "Sin lenguaje principal",
                             "languages": list(select_supported_languages(tuple(top))),
                             "github_languages": top, "selection_error": error})
    finally:
        if session is None:
            client.close()
    return {"schema_version": 1, "organization": organization, "requested_count": len(selected),
            "repository_limit": count,
            "created_at": datetime.now(timezone.utc).isoformat(), "repositories": selected,
            "limitations": []}


def git_run(arguments, *, timeout=300) -> str:
    """Ejecuta Git sin hooks, preguntas ni configuración global del usuario."""
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "SYSTEMROOT"}}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_LFS_SKIP_SMUDGE="1")
    try:
        result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *arguments],
                                check=True, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise ValueError(f"Git superó los {timeout} segundos") from None
    except (subprocess.CalledProcessError, OSError):
        raise ValueError("Falló Git; no se pudo preparar la revisión") from None
    return result.stdout.strip()


def prepare_checkout(item: dict, workspace: Path, timeout: int) -> Path:
    """Descarga la revisión pública fijada en el manifiesto a un espacio propio."""
    name = item["repository"]
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", name):
        raise ValueError("Identidad de repositorio inválida")
    commit = item.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError(item.get("selection_error") or "No hay un commit fijado disponible")
    expected_url = f"https://github.com/{name}.git"
    if item["url"] != expected_url:
        raise ValueError("Solo se permite el repositorio público indicado en el manifiesto")
    checkout = workspace / "source"
    git_run(["init", "-q", str(checkout)], timeout=timeout)
    git_run(["-C", str(checkout), "remote", "add", "origin", expected_url], timeout=timeout)
    git_run(["-C", str(checkout), "fetch", "--depth=1", "origin", commit], timeout=timeout)
    git_run(["-C", str(checkout), "checkout", "--detach", "FETCH_HEAD"], timeout=timeout)
    if git_run(["-C", str(checkout), "rev-parse", "HEAD"]) != commit:
        raise ValueError("La revisión descargada difiere del manifiesto")
    return checkout


def scan_source(checkout: Path, output: Path, languages: tuple[str, ...], config: dict, *,
                work_root=None, progress: Callable[[str], None] | None = None):
    """Ejecuta CodeQL, crea un SBOM con Syft y lo analiza con Grype."""
    timeout, tools = config["timeout"], config["tools"]
    if progress:
        progress("CodeQL: analizando el código fuente")
    codeql = analyze_codeql(checkout, output, languages,
                           executable=Path(tools["codeql"]["executable"]), timeout=timeout, work_root=work_root)
    if progress:
        progress("Syft: generando un SBOM")
    syft = analyze_syft(checkout, output, executable=Path(tools["syft"]["executable"]), timeout=timeout)
    if progress:
        progress("Grype: analizando el SBOM")
    grype = analyze_grype(syft, output, executable=Path(tools["grype"]["executable"]), timeout=timeout)
    return codeql, syft, grype


def save_scan(run: Path, path: Path, scan: RepositoryScan) -> None:
    """Guarda el análisis con rutas relativas y hashes SHA-256 verificados."""
    record = scan.model_dump(mode="json")
    hashes = {}
    for tool in record["tools"]:
        relative_paths = []
        for artifact in tool["artifacts"]:
            absolute = Path(artifact).resolve()
            relative = absolute.relative_to(run.resolve()).as_posix()
            hashes[relative] = sha256_file(absolute)
            relative_paths.append(relative)
        tool["artifacts"] = relative_paths
    record["artifact_hashes"] = hashes
    write_json(path, record)
    verify_artifacts(run, read_json(path))


def mine(manifest: dict, run: Path, config: dict, *, resume=False, keep_work=False,
         progress: Callable[[str], None] | None = None):
    """Procesa cada repositorio fijado y guarda el estado incluso si falla."""
    run = run.expanduser().absolute()
    digest = fingerprint(config)
    if resume:
        run = run.resolve()
        stored = read_json(run / "manifest.json")
        if stored["selection"] != manifest or stored["config_sha256"] != digest:
            raise ValueError("Reanudar requiere el mismo manifiesto, configuración, herramientas y base de datos")
    else:
        run = initialize_or_replace_run(run)
        write_json(run / "manifest.json", {"selection": manifest, "config": config, "config_sha256": digest})

    for index, item in enumerate(manifest["repositories"], 1):
        message = f"Miner [{index}/{len(manifest['repositories'])}] {item['repository']}"
        if progress:
            progress(message + ": preparando el análisis")
        else:
            print(message, flush=True)
        path = run / "records" / f"{index:03d}.json"
        if resume and path.exists():
            previous = read_json(path)
            if (previous["repository"] != item["repository"] or previous["commit"] != item["commit"]
                    or previous["config_sha256"] != digest):
                raise ValueError("La identidad del registro guardado difiere del análisis solicitado")
            verify_artifacts(run, previous)
            if progress:
                progress(message + ": resultado guardado verificado")
            else:
                print("  Resultado guardado verificado", flush=True)
            continue
        workspace = own_directory(run, f"repo-{index:03d}-")
        source_error = None
        try:
            if progress:
                progress(message + ": descargando el commit fijado")
            checkout = prepare_checkout(item, workspace, config["timeout"])
            scan_progress = (lambda detail: progress(f"{message}: {detail}")) if progress else None
            scan_options = {"progress": scan_progress} if scan_progress else {}
            results = scan_source(checkout, run / "raw" / f"{index:03d}", tuple(item["languages"]),
                                  config, work_root=workspace / "codeql", **scan_options)
        except (OSError, ValueError) as error:
            source_error = str(error)
            results = tuple(ToolResult(tool=name, status="skipped", error=source_error)
                            for name in ("codeql", "syft", "grype"))
        scan = RepositoryScan(repository=item["repository"], url=item["url"], commit=item.get("commit"),
                              config_sha256=digest, source_error=source_error, tools=results)
        save_scan(run, path, scan)
        statuses = ", ".join(f"{tool.tool}={STATUS_LABELS.get(tool.status, tool.status)}"
                             for tool in results)
        if progress:
            progress(message + ": " + statuses)
        else:
            print("  " + statuses, flush=True)
        # Solo elimina copias temporales propias tras guardar y verificar la evidencia.
        write_json(run / "logs" / "progress.json", {"completed": index, "total": len(manifest["repositories"])})
        if not keep_work:
            cleanup_work(run, workspace, path)
    return run
