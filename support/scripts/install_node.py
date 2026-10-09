"""Instala la versión fijada de Node.js requerida por CodeQL para TypeScript."""

import hashlib
import json
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = "v22.23.3"
SHA256 = "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de"
FILENAME = f"node-{VERSION}-linux-x64.tar.xz"
URL = f"https://nodejs.org/dist/{VERSION}/{FILENAME}"


def main():
    """Instala y verifica Node.js local para el extractor TypeScript de CodeQL."""
    target = ROOT / ".tools/node"
    if target.exists():
        raise SystemExit("El directorio de Node ya existe y no se sobrescribirá")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix="node-install-") as directory:
        staging = Path(directory)
        archive = staging / FILENAME
        with urllib.request.urlopen(URL, timeout=60) as response, archive.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
            raise RuntimeError("El hash del archivo de Node no coincide")
        with urllib.request.urlopen(f"https://nodejs.org/dist/{VERSION}/SHASUMS256.txt", timeout=30) as response:
            checksums = response.read().decode()
        if not any(line.split() == [SHA256, FILENAME] for line in checksums.splitlines()):
            raise RuntimeError("El hash publicado de Node no coincide")
        with tarfile.open(archive) as bundle:
            bundle.extractall(staging, filter="data")
        (staging / f"node-{VERSION}-linux-x64").rename(target)
    (target / "installation.json").write_text(json.dumps({"version": VERSION, "url": URL, "sha256": SHA256}, indent=2))
    print(f"Node {VERSION} instalado; SHA-256 verificado", flush=True)


if __name__ == "__main__":
    main()
