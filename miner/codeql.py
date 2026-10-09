"""Selección segura de lenguajes y creación de bases de datos de CodeQL."""

from __future__ import annotations

import json
import os
import stat
import re
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from support.core.paths import TOOLS_ROOT

CODEQL_EXECUTABLE = TOOLS_ROOT / "codeql" / "codeql"
CODEQL_TIMEOUT = 1800
CODEQL_THREADS = 1
CODEQL_RAM_MB = 6144
CODEQL_MIN_CONTAINER_BYTES = 8 * 1024 ** 3
MINIMUM_CODEQL_VERSION = (2, 25, 5)


def available_container_memory() -> int | None:
    """Obtiene el límite de memoria del contenedor o la RAM física total."""
    for name in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            value = Path(name).read_text().strip()
            if value != "max":
                limit = int(value)
                if limit < 1 << 60:
                    return limit
        except (OSError, ValueError):
            continue
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None

GITHUB_TO_CODEQL = {
    "C": "cpp",
    "C++": "cpp",
    "C#": "csharp",
    "Go": "go",
    "Java": "java",
    "Kotlin": "java",
    "JavaScript": "javascript",
    "TypeScript": "javascript",
    "Vue": "javascript",
    "Python": "python",
    "Ruby": "ruby",
    "Rust": "rust",
    "Swift": "swift",
}

NO_BUILD_LANGUAGES = frozenset({"cpp", "javascript", "python", "ruby"})


class CodeQLError(RuntimeError):
    """Fallo de CodeQL depurado para mostrarlo en la terminal."""


class CodeQLConfigurationError(CodeQLError):
    """CodeQL está ausente, incompleto o no es compatible."""


class CodeQLDatabaseError(CodeQLError):
    """No se pudo crear de forma segura la base de un repositorio."""


class CodeQLAnalysisError(CodeQLError):
    """Las consultas de seguridad fallaron o no produjeron SARIF."""


def select_supported_languages(top_languages: tuple[str, ...]) -> tuple[str, ...]:
    """Relaciona los lenguajes de GitHub con extractores únicos de CodeQL."""
    selected: list[str] = []
    for language in top_languages:
        codeql_language = GITHUB_TO_CODEQL.get(language)
        if codeql_language and codeql_language not in selected:
            selected.append(codeql_language)
    return tuple(selected)


def _parse_version(version: str) -> tuple[int, int, int] | None:
    """Interpreta una versión de CodeQL de tres partes para comprobar el mínimo."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


@dataclass(frozen=True)
class CodeQLRunner:
    """Ejecuta una versión fijada de CodeQL en un proceso aislado."""

    executable: Path
    available_languages: frozenset[str]
    version: str
    timeout: int = CODEQL_TIMEOUT

    @classmethod
    def preflight(
        cls,
        executable: Path = CODEQL_EXECUTABLE,
        *,
        timeout: int = CODEQL_TIMEOUT,
    ) -> CodeQLRunner:
        """Valida la instalación local y detecta sus extractores."""
        executable = executable.expanduser().resolve()
        if timeout < 1:
            raise CodeQLConfigurationError("El tiempo máximo de CodeQL debe ser positivo.")
        memory = available_container_memory()
        if memory is not None and memory < CODEQL_MIN_CONTAINER_BYTES:
            raise CodeQLConfigurationError("CodeQL requiere al menos 8 GiB de memoria para el contenedor.")
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise CodeQLConfigurationError(
                "Falta el ejecutable de CodeQL o no tiene permisos de ejecución."
            )
        if not (executable.parent / "qlpacks").is_dir():
            raise CodeQLConfigurationError(
                "La instalación local de CodeQL no contiene paquetes de consultas."
            )
        # Las consultas precompiladas pueden traer modo 0600 en el bundle oficial.
        # Compose ejecuta CodeQL con otro UID; comprueba la lectura antes de clonar.
        qlpacks = executable.parent / "qlpacks"
        for current, directories, files in os.walk(qlpacks, followlinks=False):
            current_path = Path(current)
            if current_path.stat().st_mode & (stat.S_IROTH | stat.S_IXOTH) != (stat.S_IROTH | stat.S_IXOTH):
                raise CodeQLConfigurationError(f"CodeQL no permite atravesar {current_path}")
            for name in files:
                path = current_path / name
                if path.suffix == ".qlx" and not path.is_symlink() and not path.stat().st_mode & stat.S_IROTH:
                    raise CodeQLConfigurationError(f"El usuario de Compose no puede leer {path}")

        provisional = cls(executable, frozenset(), "", min(timeout, 60))
        with tempfile.TemporaryDirectory(prefix="reporter-codeql-preflight-") as temp:
            workspace = Path(temp)
            version_data = provisional._json(
                ["version", "--format=json"],
                workspace,
            )
            language_data = provisional._json(
                ["resolve", "languages", "--format=json"],
                workspace,
            )

        version = (
            version_data.get("version") if isinstance(version_data, dict) else None
        )
        parsed = _parse_version(version) if isinstance(version, str) else None
        if parsed is None or parsed < MINIMUM_CODEQL_VERSION:
            raise CodeQLConfigurationError("Se requiere CodeQL 2.25.5 o una versión posterior.")

        if not isinstance(language_data, dict) or not language_data:
            raise CodeQLConfigurationError(
                "CodeQL devolvió información inválida o vacía sobre sus extractores."
            )

        return cls(
            executable=executable,
            available_languages=frozenset(language_data),
            version=version,
            timeout=timeout,
        )

    @staticmethod
    def environment(workspace: Path) -> dict[str, str]:
        """Crea un entorno mínimo sin credenciales."""
        allowed = {
            "PATH",
            "LANG",
            "LC_ALL",
            "JAVA_HOME",
            "DOTNET_ROOT",
            "GOROOT",
            "RUSTUP_HOME",
            "SYSTEMROOT",
        }
        environment = {
            key: value for key, value in os.environ.items() if key in allowed
        }

        home = workspace / "home"
        temporary = workspace / "tmp"
        cache = workspace / "cache"
        for directory in (home, temporary, cache):
            directory.mkdir(parents=True, exist_ok=True)

        node_directory = TOOLS_ROOT / "node" / "bin"
        if (node_directory / "node").is_file():
            environment["PATH"] = str(node_directory) + os.pathsep + environment.get("PATH", "")

        environment.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "TMPDIR": str(temporary),
                "TMP": str(temporary),
                "TEMP": str(temporary),
                "XDG_CACHE_HOME": str(cache),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "CODEQL_EXTRACTOR_CPP_AUTOINSTALL_DEPENDENCIES": "false",
                "CODEQL_ALLOW_INSTALLATION_ANYWHERE": "true",
            }
        )
        return environment

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        """Termina el grupo de procesos para que ningún extractor siga tras el límite."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    def _run(
        self,
        arguments: list[str],
        workspace: Path,
        *,
        capture_output: bool = False,
    ) -> str:
        """Ejecuta CodeQL con tiempo limitado y registros en un espacio aislado."""
        workspace = workspace.resolve()
        logs = workspace / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        stdout_path = logs / "stdout.log"
        stderr_path = logs / "stderr.log"
        command = [
            str(self.executable),
            *arguments,
            f"--common-caches={workspace / 'cache'}",
            f"--logdir={logs}",
        ]

        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    command,
                    cwd=workspace,
                    env=self.environment(workspace),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                try:
                    process.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    self._terminate(process)
                    raise CodeQLDatabaseError(
                        f"CodeQL superó los {self.timeout} segundos."
                    ) from None
                except BaseException:
                    self._terminate(process)
                    raise

                if process.returncode:
                    raise CodeQLDatabaseError(
                        f"CodeQL terminó con estado {process.returncode}."
                    )
        except OSError as error:
            raise CodeQLDatabaseError(
                "No se pudo iniciar CodeQL; revisa el ejecutable y el espacio de trabajo."
            ) from error

        if not capture_output:
            return ""

        try:
            if stdout_path.stat().st_size > 4 * 1024 * 1024:
                raise CodeQLConfigurationError(
                    "La salida de configuración de CodeQL fue demasiado grande."
                )
            return stdout_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise CodeQLConfigurationError(
                "No se pudo leer la salida de configuración de CodeQL."
            ) from error

    def _json(self, arguments: list[str], workspace: Path) -> object:
        """Decodifica como JSON las respuestas de configuración de CodeQL."""
        try:
            return json.loads(self._run(arguments, workspace, capture_output=True))
        except (ValueError, UnicodeError) as error:
            raise CodeQLConfigurationError(
                "CodeQL devolvió un JSON de configuración inválido."
            ) from error
        except CodeQLDatabaseError as error:
            raise CodeQLConfigurationError(str(error)) from error

    def create_database(self, language: str, checkout: Path, database_root: Path) -> Path:
        """Crea la base en un directorio temporal y luego la publica."""
        if language not in self.available_languages:
            raise CodeQLDatabaseError(f"El extractor de {language} no está disponible.")
        if language not in NO_BUILD_LANGUAGES:
            raise CodeQLDatabaseError(f"{language} no tiene una política aprobada sin compilación.")
        checkout = checkout.resolve()
        if not checkout.is_dir():
            raise CodeQLDatabaseError("El repositorio clonado no está disponible.")

        database_root.mkdir(parents=True, exist_ok=True)
        destination = database_root / language
        if destination.exists() or destination.is_symlink():
            raise CodeQLDatabaseError("El destino de la base ya existe; usa otro directorio de ejecución.")

        staging = Path(tempfile.mkdtemp(prefix=f".{language}-", dir=database_root))
        database = staging / "database"
        workspace = staging / "work"
        try:
            self._run(
                ["database", "create", str(database.resolve()), f"--language={language}",
                 f"--source-root={checkout}", "--build-mode=none",
                 f"--threads={CODEQL_THREADS}", f"--ram={CODEQL_RAM_MB}"],
                workspace,
            )
            if not database.is_dir():
                raise CodeQLDatabaseError(f"No se creó la base de datos de {language}.")
            shutil.rmtree(workspace, ignore_errors=True)
            staging.rename(destination)
            return destination / "database"
        except CodeQLError:
            raise
        except OSError as error:
            shutil.rmtree(staging, ignore_errors=True)
            raise CodeQLDatabaseError("No se pudieron completar los archivos de la base de CodeQL.") from error

    def analyze_database(
        self,
        database: Path,
        language: str,
        sarif_output: Path,
        workspace: Path,
    ) -> Path:
        """Ejecuta la suite security-extended incluida y produce SARIF 2.1.0."""
        query_pack = self.executable.parent / "qlpacks" / "codeql"
        suites = sorted(
            query_pack.glob(
                f"{language}-queries/*/codeql-suites/{language}-security-extended.qls"
            )
        )
        if len(suites) != 1:
            raise CodeQLAnalysisError(
                f"La suite de consultas de seguridad de {language} no está disponible."
            )

        sarif_output.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._run(
                [
                    "database",
                    "analyze",
                    str(database.resolve()),
                    str(suites[0].resolve()),
                    "--format=sarifv2.1.0",
                    f"--output={sarif_output.resolve()}",
                    f"--threads={CODEQL_THREADS}",
                    f"--ram={CODEQL_RAM_MB}",
                ],
                workspace,
            )
        except CodeQLDatabaseError as error:
            raise CodeQLAnalysisError(
                f"Falló el análisis de seguridad de {language}: {error}"
            ) from error

        if not sarif_output.is_file():
            raise CodeQLAnalysisError(
                f"El análisis de {language} no produjo un archivo SARIF."
            )
        return sarif_output
