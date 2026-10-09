"""Exporta evidencia e informes portables."""

import shutil
from pathlib import Path

from support.core.storage import initialize_run, read_json, verify_artifacts, write_json
from analyzer.prepare import prepare_data
from visualizer.dashboard import generate_html


def export_run(run: Path, destination: Path) -> Path:
    """Copia evidencia verificada sin clones, ejecutables ni cachés."""
    run = run.resolve()
    data = prepare_data(run)
    destination = initialize_run(destination)
    shutil.copy2(run / "manifest.json", destination / "manifest.json")
    # Comprueba cada hash antes de exportar un resultado.
    for record_path in sorted((run / "records").glob("*.json")):
        record = read_json(record_path)
        verify_artifacts(run, record)
        shutil.copy2(record_path, destination / "records" / record_path.name)
        for relative in record["artifact_hashes"]:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(run / relative, target)
    for name in ("prepared", "reports", "logs"):
        shutil.copytree(run / name, destination / name, dirs_exist_ok=True)
    prepare_data(destination)
    if "selection" in read_json(run / "manifest.json"):
        generate_html(data, destination / "reports/dashboard.html")
    write_json(destination / "export.json", {"format": 1, "contains": ["evidence", "records", "reports"],
                                            "excludes": ["clones", "tool binaries", "CodeQL databases", "credentials"]})
    return destination
