"""Instala Tkinter de Ubuntu dentro del entorno virtual, sin sudo."""

import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
from support.interface.tk_runtime import local_tk_directory, prepare


PACKAGES = ("python3.14-tk", "libtcl8.6", "libtk8.6")


def package_metadata(name: str) -> tuple[str, str]:
    """Lee la versión y el hash esperados desde los metadatos APT de Ubuntu."""
    policy = subprocess.check_output(["apt-cache", "policy", name], text=True)
    match = re.search(r"^\s*Candidate:\s*(\S+)", policy, re.MULTILINE)
    if match is None or match.group(1) == "(none)":
        raise RuntimeError(f"No se encontró un paquete candidato de Ubuntu para {name}")
    version = match.group(1)
    listing = subprocess.check_output(["apt-cache", "show", name], text=True)
    for paragraph in listing.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line)
        if fields.get("Version") == version and fields.get("SHA256"):
            return version, fields["SHA256"]
    raise RuntimeError(f"No se encontraron metadatos SHA-256 para {name} {version}")


def download_package(name: str, directory: Path) -> dict:
    """Descarga un paquete .deb sin permisos de administrador y verifica su hash."""
    version, digest = package_metadata(name)
    package_dir = directory / name
    package_dir.mkdir()
    try:
        subprocess.run(["apt-get", "download", f"{name}={version}"], cwd=package_dir, check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"No se pudo descargar {name}; revisa APT y la conexión de red") from None
    archives = list(package_dir.glob("*.deb"))
    if len(archives) != 1:
        raise RuntimeError(f"Se esperaba un paquete descargado para {name}")
    actual = hashlib.sha256(archives[0].read_bytes()).hexdigest()
    if actual != digest:
        raise RuntimeError(f"El hash no coincide para {name}")
    try:
        subprocess.run(["dpkg-deb", "-x", str(archives[0]), str(directory / "extracted")], check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"No se pudo extraer el paquete verificado {name}") from None
    return {"version": version, "sha256": digest}


def install() -> Path:
    """Guarda la extensión Python, las bibliotecas y los scripts Tcl en .venv."""
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("Activa el entorno virtual del proyecto antes de instalar Tkinter")
    if sys.version_info[:2] != (3, 14) or platform.machine() != "x86_64":
        raise RuntimeError("Este instalador de Tkinter requiere Ubuntu x86_64 y Python 3.14")
    target = local_tk_directory()
    if target.exists():
        raise RuntimeError(f"Tkinter local ya existe: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="tkinter-install-") as temporary:
        work = Path(temporary)
        packages = {name: download_package(name, work) for name in PACKAGES}
        extracted = work / "extracted" / "usr"
        stage = target.parent / f".tkinter-install-{uuid.uuid4().hex}"
        try:
            python = stage / "python"
            python.mkdir(parents=True)
            shutil.copytree(extracted / "lib/python3.14/tkinter", python / "tkinter")
            extensions = list((extracted / "lib/python3.14/lib-dynload").glob("_tkinter*.so"))
            if len(extensions) != 1:
                raise RuntimeError("El paquete Python no contiene exactamente una extensión Tkinter")
            shutil.copy2(extensions[0], python / extensions[0].name)
            libraries = stage / "lib"
            libraries.mkdir()
            for name in ("libtcl8.6.so", "libtk8.6.so"):
                shutil.copy2(extracted / "lib/x86_64-linux-gnu" / name, libraries / name)
            for name in ("tcl8.6", "tk8.6"):
                shutil.copytree(extracted / "share/tcltk" / name, stage / name)
            (stage / "installation.json").write_text(
                json.dumps({"source": "Ubuntu APT", "packages": packages}, indent=2) + "\n",
                encoding="utf-8",
            )
            # Tcl() comprueba la extensión y los scripts Tcl sin necesitar una pantalla.
            prepare(stage)
            import tkinter
            interpreter = tkinter.Tcl()
            interpreter.eval("info patchlevel")
            stage.rename(target)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    return target


if __name__ == "__main__":
    print(f"Tkinter local instalado: {install()}")
