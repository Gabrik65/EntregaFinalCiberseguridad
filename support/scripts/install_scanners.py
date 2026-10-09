"""Instala ejecutables fijados de Anchore para Linux x86_64 y verifica sus hashes."""

import hashlib
import json
import os
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASES = {
    "syft": ("1.52.0", "caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d"),
    "grype": ("0.119.0", "3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b"),
}


def install(name: str) -> None:
    """Descarga una herramienta, verifica sus hashes y la instala localmente."""
    version, expected = RELEASES[name]
    target = ROOT / ".tools" / name
    if target.exists():
        print(f"Se conserva {target}; verifica la instalación antes del análisis.", flush=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    filename = f"{name}_{version}_linux_amd64.tar.gz"
    base = f"https://github.com/anchore/{name}/releases/download/v{version}"

    with tempfile.TemporaryDirectory(dir=target.parent, prefix=f"{name}-install-") as temporary:
        staging = Path(temporary)
        archive = staging / filename
        with urllib.request.urlopen(f"{base}/{filename}", timeout=60) as response:
            with archive.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"{name}: el hash del archivo no coincide")
        with urllib.request.urlopen(f"{base}/{name}_{version}_checksums.txt", timeout=30) as response:
            checksums = response.read().decode()
        if not any(line.split() == [expected, filename] for line in checksums.splitlines()):
            raise RuntimeError(f"{name}: el hash publicado no coincide")
        with tarfile.open(archive) as bundle:
            bundle.extractall(staging / "unpacked", filter="data")
        binary = staging / "unpacked" / name
        binary.chmod(0o755)
        (staging / "unpacked").rename(target)
    (target / "installation.json").write_text(json.dumps({
        "version": version, "url": f"{base}/{filename}", "sha256": expected,
    }, indent=2) + "\n")
    print(f"{name} {version} instalado; hash verificado", flush=True)


if __name__ == "__main__":
    if os.name != "posix" or os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        raise SystemExit("Este instalador requiere Linux x86_64")
    for tool in RELEASES:
        install(tool)
