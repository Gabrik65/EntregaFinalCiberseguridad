"""Instala localmente el paquete oficial fijado para Linux; no requiere token de GitHub."""

import hashlib
import json
import os
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "2.25.5"
SHA256 = "24717f939f1bef659f893ff4a9c99ba8c056fbaca9640f877c4dc74cf96486d7"
URL = (
    "https://github.com/github/codeql-action/releases/download/"
    f"codeql-bundle-v{VERSION}/codeql-bundle-linux64.tar.gz"
)
ROOT = Path(__file__).resolve().parents[2]


def make_bundle_readable(directory: Path) -> None:
    """Permite que el usuario no privilegiado de Compose lea consultas QLX."""
    for current, directories, files in os.walk(directory, followlinks=False):
        current_path = Path(current)
        current_path.chmod(current_path.stat().st_mode | stat.S_IROTH | stat.S_IXOTH)
        for name in directories:
            path = current_path / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | stat.S_IROTH | stat.S_IXOTH)
        for name in files:
            path = current_path / name
            if not path.is_symlink():
                mode = path.stat().st_mode
                path.chmod(mode | stat.S_IROTH | (stat.S_IXOTH if mode & 0o111 else 0))


def main() -> None:
    """Descarga CodeQL y verifica los dos hashes esperados."""
    if (
        os.name != "posix"
        or os.uname().sysname != "Linux"
        or os.uname().machine != "x86_64"
    ):
        raise SystemExit("Este instalador requiere Linux x86_64.")
    tools = ROOT / ".tools"
    tools.mkdir(exist_ok=True)
    target = tools / "codeql"
    if target.exists():
        raise SystemExit(
            "El directorio local de CodeQL ya existe y no se sobrescribirá."
        )
    with tempfile.TemporaryDirectory(prefix="codeql-install-", dir=tools) as temporary:
        staging = Path(temporary)
        archive = staging / "bundle.tar.gz"
        digest = hashlib.sha256()
        with (
            urllib.request.urlopen(URL, timeout=60) as response,
            archive.open("wb") as output,
        ):
            downloaded = 0
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
                downloaded += len(chunk)
                if downloaded % (100 * 1024 * 1024) == 0:
                    print(f"Descargados {downloaded // (1024 * 1024)} MiB", flush=True)
        if digest.hexdigest() != SHA256:
            raise SystemExit("El hash del paquete no coincide; se canceló la instalación.")
        with urllib.request.urlopen(URL + ".checksum.txt", timeout=30) as response:
            published = response.read().decode().split()[0]
        if published != SHA256:
            raise SystemExit("El hash publicado difiere del hash fijado.")
        print("SHA-256 coincide con los hashes fijado y publicado.", flush=True)
        with tarfile.open(archive) as bundle:
            bundle.extractall(staging, filter="data")
        (staging / "codeql").rename(target)
        make_bundle_readable(target)
    (tools / "codeql-installation.json").write_text(
        json.dumps({"version": VERSION, "url": URL, "sha256": SHA256}, indent=2) + "\n"
    )
    print(f"CodeQL {VERSION} instalado: {target / 'codeql'}", flush=True)


if __name__ == "__main__":
    main()
