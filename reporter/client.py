"""Contrato del cliente y una implementación simulada explícita."""

import json
import os
import re
from typing import Protocol

import requests


class LLMClient(Protocol):
    """Interfaz mínima compartida por el cliente simulado y el real."""

    def generate(self, instructions: str, payload: dict) -> str:
        """Devuelve una respuesta JSON para validarla después."""
        ...


class SimulatedLLMClient:
    """Simulación determinista sin red, credenciales ni inferencia del modelo."""

    simulated = True

    def generate(self, instructions: str, payload: dict) -> str:
        """Crea observaciones deterministas solo a partir de la evidencia recibida."""
        observations = []
        for evidence in payload["evidence"]:
            detail = evidence["detail"]
            if evidence["kind"] == "code":
                text = f"Revisar la alerta {detail['rule_id']} en {detail['file']}:{detail['start_line']}."
            elif evidence["kind"] == "dependency":
                text = (f"Revisar {detail['vulnerability_id']} asociada con "
                        f"{detail['package_name']} {detail['package_version']}.")
            else:
                if not detail["signals"]:
                    continue
                text = f"Revisar {detail['file']}: {'; '.join(detail['signals'])}."
            observations.append({"text": text, "evidence_ids": [evidence["id"]]})
        incomplete = any(tool["status"] not in {"success", "success_empty"}
                         for repo in payload["repositories"] for tool in repo["tools"])
        summary = "Resumen determinista de resultados; se requiere revisión humana."
        if incomplete:
            summary += " Algunas herramientas fallaron, se omitieron o tuvieron cobertura parcial."
        elif not observations:
            summary += " No se registraron alertas; esto no garantiza la ausencia de vulnerabilidades."
        return json.dumps({"simulated": True, "summary": summary,
                           "statistics": payload["statistics"], "observations": observations,
                           "limitations": payload["limitations"]}, ensure_ascii=False)


class OpenRouterClient:
    """Usa OpenRouter sin registrar credenciales ni cuerpos de respuesta."""

    simulated = False
    endpoint = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, *, model: str | None = None, api_key: str | None = None,
                 timeout: int = 120):
        """Lee credenciales de argumentos o variables de entorno sin guardarlas."""
        self.model = (model if model is not None else os.environ.get("OPENROUTER_MODEL", "")).strip()
        self.api_key = (api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY", "")).strip()
        self.timeout = timeout
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY es necesaria para usar Reporter con un modelo real")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:+-]*", self.model):
            raise ValueError("Configura un ID de modelo válido con --model u OPENROUTER_MODEL")
        if timeout < 1:
            raise ValueError("El tiempo máximo de OpenRouter debe ser positivo")

    def generate(self, instructions: str, payload: dict) -> str:
        """Solicita una respuesta JSON y devuelve el texto del modelo para validarlo."""
        try:
            response = requests.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                json={"model": self.model,
                      "messages": [{"role": "system", "content": instructions},
                                   {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
                      "response_format": {"type": "json_object"},
                      "temperature": 0, "max_tokens": 8192},
                timeout=self.timeout,
            )
        except requests.RequestException:
            raise RuntimeError("Falló la solicitud a OpenRouter; revisa la conexión y el tiempo máximo") from None
        try:
            if response.status_code != 200:
                raise RuntimeError(f"OpenRouter respondió con HTTP {response.status_code}")
            document = response.json()
            content = document["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("OpenRouter devolvió una respuesta vacía o que no es texto")
            return content
        except (KeyError, IndexError, TypeError, requests.exceptions.JSONDecodeError):
            raise ValueError("OpenRouter devolvió una respuesta inválida") from None
        finally:
            response.close()
