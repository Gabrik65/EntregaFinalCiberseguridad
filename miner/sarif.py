"""Convierte SARIF 2.1.0 de CodeQL al modelo de hallazgos de Miner."""

import json
import re
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from pydantic import ValidationError

from support.core.models import Finding, finding_key


class SarifError(RuntimeError):
    """Error de lectura depurado; los hallazgos inválidos no desaparecen sin aviso."""


def _object(value):
    """Exige un objeto SARIF en un límite del esquema."""
    if not isinstance(value, dict):
        raise SarifError("Se esperaba un objeto SARIF")
    return value


def _array(value):
    """Exige un arreglo SARIF en un límite del esquema."""
    if not isinstance(value, list):
        raise SarifError("Se esperaba un arreglo SARIF")
    return value


def _index(items: list, index):
    """Resuelve un índice SARIF sin aceptar booleanos ni valores fuera de rango."""
    if type(index) is not int or index < 0 or index >= len(items):
        raise SarifError("Referencia inválida a un arreglo SARIF")
    return _object(items[index])


def _text(message: dict, rule: dict, driver: dict) -> str:
    """Resuelve mensajes directos o referenciados y sustituye argumentos SARIF."""
    message = _object(message)
    value = message.get("text", message.get("markdown"))
    if value is None and "id" in message:
        table = _object(rule.get("messageStrings", {}))
        definition = table.get(message["id"])
        if definition is None:
            definition = _object(driver.get("globalMessageStrings", {})).get(
                message["id"]
            )
        definition = _object(definition)
        value = definition.get("text", definition.get("markdown"))
    if not isinstance(value, str) or not value.strip():
        raise SarifError("Falta el mensaje del hallazgo o es inválido")
    arguments = _array(message.get("arguments", []))
    if any(not isinstance(arg, str) for arg in arguments):
        raise SarifError("Argumentos inválidos del mensaje SARIF")

    def substitute(match):
        """Sustituye un marcador de posición con argumentos validados."""
        index = int(match.group(1))
        if index >= len(arguments):
            raise SarifError("Referencia inválida a un argumento del mensaje SARIF")
        return arguments[index]

    if arguments:
        value = re.sub(r"\{(\d+)\}", substitute, value)
    return value


def _rule(result: dict, run: dict) -> tuple[str, dict, dict]:
    """Resuelve la regla del resultado entre las tablas del controlador y extensiones."""
    tool = _object(run.get("tool"))
    driver = _object(tool.get("driver"))
    reference = _object(result.get("rule", {}))
    component = driver
    if "toolComponent" in reference:
        component_ref = _object(reference["toolComponent"])
        if "index" in component_ref:
            component = _index(
                _array(tool.get("extensions", [])), component_ref["index"]
            )
        elif component_ref.get("name") != driver.get("name"):
            raise SarifError("Referencia no compatible a un componente de herramienta SARIF")
    rules = _array(component.get("rules", []))
    identifier = result.get("ruleId", reference.get("id"))
    index = result.get("ruleIndex", reference.get("index"))
    if (
        "ruleId" in result and "id" in reference and result["ruleId"] != reference["id"]
    ) or (
        "ruleIndex" in result
        and "index" in reference
        and result["ruleIndex"] != reference["index"]
    ):
        raise SarifError("Hay referencias contradictorias a reglas SARIF")
    rule = _index(rules, index) if index is not None else {}
    if rule and identifier is not None and rule.get("id") != identifier:
        raise SarifError("Hay identificadores contradictorios de reglas SARIF")
    if identifier is None:
        identifier = rule.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise SarifError("Falta el identificador de regla del hallazgo")
    if not rule:
        matches = [
            _object(candidate)
            for candidate in rules
            if _object(candidate).get("id") == identifier
        ]
        if len(matches) > 1:
            raise SarifError("El identificador de regla SARIF es ambiguo")
        rule = matches[0] if matches else {}
    return identifier, rule, component


def _path(location: dict, run: dict, root: Path) -> str:
    """Resuelve URI SARIF a rutas dentro del repositorio analizado."""
    artifacts = _array(run.get("artifacts", []))
    bases = _object(run.get("originalUriBaseIds", {}))
    root_uri = root.resolve().as_uri() + "/"

    def resolve(
        item: dict, seen_bases: frozenset[str], seen_artifacts: frozenset[int]
    ) -> str:
        """Sigue URI base y referencias de artefactos mientras detecta ciclos."""
        item = _object(item)
        if "index" in item:
            index = item["index"]
            artifact = _index(artifacts, index)
            if index in seen_artifacts:
                raise SarifError("Referencia cíclica a un artefacto SARIF")
            linked_location = dict(_object(artifact.get("location")))
            # CodeQL anota la ubicación del artefacto con su índice en la tabla.
            if linked_location.get("index") == index and "uri" in linked_location:
                linked_location.pop("index")
            linked = resolve(linked_location, seen_bases, seen_artifacts | {index})
            if "uri" not in item:
                return linked
            supplied = resolve(
                {key: value for key, value in item.items() if key != "index"},
                seen_bases,
                seen_artifacts,
            )
            if supplied != linked:
                raise SarifError("Hay ubicaciones contradictorias de un artefacto SARIF")
            return supplied
        uri = item.get("uri", "")
        if not isinstance(uri, str):
            raise SarifError("URI inválida de un artefacto SARIF")
        uri = uri.replace("\\", "/")
        base = root_uri
        if "uriBaseId" in item:
            base_id = item["uriBaseId"]
            if not isinstance(base_id, str) or base_id in seen_bases:
                raise SarifError("URI base SARIF inválida o cíclica")
            if base_id == "%SRCROOT%" and base_id not in bases:
                # CodeQL omite la raíz absoluta del código fuente en el SARIF portable.
                base = root_uri
            elif base_id not in bases:
                raise SarifError("No se pudo resolver la URI base SARIF")
            else:
                base = resolve(
                    _object(bases[base_id]), seen_bases | {base_id}, seen_artifacts
                )
        return urljoin(base, uri)

    uri = resolve(location, frozenset(), frozenset())
    parsed = urlsplit(uri)
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        raise SarifError("La ubicación del hallazgo no es un archivo local de código fuente")
    if parsed.query or parsed.fragment:
        raise SarifError("La URI del archivo incluye una consulta o fragmento inesperado")
    decoded = unquote(parsed.path)
    if "\x00" in decoded:
        raise SarifError("La ruta del hallazgo contiene un carácter inválido")
    try:
        path = Path(decoded).resolve()
        relative = path.relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        raise SarifError("La ubicación del hallazgo está fuera del repositorio") from None
    if relative == ".":
        raise SarifError("El hallazgo no identifica un archivo de código fuente")
    return relative


def parse_sarif(path: Path, checkout: Path) -> tuple[Finding, ...]:
    """Valida el SARIF de CodeQL y lo convierte en hallazgos estables."""
    try:
        with path.open(encoding="utf-8-sig") as stream:
            document = _object(json.load(stream))
        if document.get("version") != "2.1.0":
            raise SarifError("Se esperaba SARIF versión 2.1.0")
        runs = _array(document.get("runs"))
        if not runs:
            raise SarifError("SARIF no contiene ejecuciones de análisis")
        findings = []
        for raw_run in runs:
            run = _object(raw_run)
            _object(_object(run.get("tool")).get("driver"))
            for invocation in _array(run.get("invocations", [])):
                invocation = _object(invocation)
                if (
                    "executionSuccessful" in invocation
                    and type(invocation["executionSuccessful"]) is not bool
                ):
                    raise SarifError("Estado inválido de una ejecución SARIF")
                if invocation.get("executionSuccessful") is False:
                    raise SarifError(
                        "SARIF indica que una ejecución de análisis no terminó correctamente"
                    )
            for raw_result in _array(run.get("results", [])):
                result = _object(raw_result)
                identifier, rule, component = _rule(result, run)
                message = _text(result.get("message"), rule, component)
                level = result.get(
                    "level",
                    _object(rule.get("defaultConfiguration", {})).get(
                        "level", "warning"
                    ),
                )
                properties = _object(rule.get("properties", {}))
                tags = _array(properties.get("tags", []))
                if any(not isinstance(tag, str) for tag in tags):
                    raise SarifError("Etiquetas inválidas de una regla SARIF")
                cwes = tuple(sorted({
                    tag.rsplit("/", 1)[-1].upper()
                    for tag in tags
                    if re.fullmatch(r"(?:external/)?cwe/cwe-\d+", tag, re.IGNORECASE)
                }))
                security_severity = properties.get("security-severity")
                if isinstance(security_severity, bool):
                    raise SarifError("Severidad de seguridad inválida")
                locations = _array(result.get("locations", []))
                if not locations:
                    raise SarifError("El hallazgo no tiene ubicación en el código fuente")
                # Conserva todas las ubicaciones principales sin descartar las adicionales.
                for raw_location in locations:
                    physical = _object(_object(raw_location).get("physicalLocation"))
                    artifact = _object(physical.get("artifactLocation"))
                    if not artifact or (
                        "uri" not in artifact and "index" not in artifact
                    ):
                        raise SarifError("El hallazgo no tiene archivo de código fuente")
                    region = _object(physical.get("region"))
                    line, column = region.get("startLine"), region.get("startColumn")
                    if type(line) is not int or (
                        column is not None and type(column) is not int
                    ):
                        raise SarifError("El hallazgo tiene una posición inválida")
                    findings.append(
                        Finding(
                            rule_id=identifier,
                            message=message,
                            severity=level,
                            file=_path(artifact, run, checkout),
                            start_line=line,
                            security_severity=security_severity,
                            cwes=cwes,
                        )
                    )
        return tuple(sorted(findings, key=finding_key))
    except SarifError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, ValidationError):
        raise SarifError("No se pudieron leer o validar los resultados SARIF de CodeQL") from None
