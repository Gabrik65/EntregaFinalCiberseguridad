"""Comprueba el límite de procesos de la instalación fijada de Syft."""

import json
import subprocess
from pathlib import Path

import pytest

from miner.syft import SyftError, SyftRunner


@pytest.fixture
def runner():
    return SyftRunner("1.52.0")


def fake_scan(monkeypatch, payload):
    def run(command, **kwargs):
        assert command[2].startswith("dir:")
        assert kwargs["timeout"] == 300
        assert "GITHUB_TOKEN" not in kwargs["env"]
        output = next(arg.split("=", 1)[1] for arg in command if arg.startswith("cyclonedx-json="))
        Path(output).write_bytes(payload)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", run)


@pytest.mark.parametrize("components,count", [([{"name": "requests"}], 1), ([], 0), (None, 0)])
def test_preserves_original_bytes(monkeypatch, tmp_path, runner, components, count):
    source = tmp_path / "source"
    source.mkdir()
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    if components is not None:
        document["components"] = components
    raw = (json.dumps(document, indent=3) + "\n").encode()
    fake_scan(monkeypatch, raw)
    generated = runner.generate(source, tmp_path / "out" / "result.json")
    assert generated.component_count == count
    assert generated.path.read_bytes() == raw
    assert generated.generated_at.utcoffset().total_seconds() == 0


@pytest.mark.parametrize("raw", [
    b"not json", b"{}", b"[]",
    b'{"bomFormat":"CycloneDX","components":null}',
    b'{"bomFormat":"CycloneDX","components":{}}',
])
def test_invalid_output_keeps_old_artifact(monkeypatch, tmp_path, runner, raw):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "old.json"
    destination.write_bytes(b"original")
    fake_scan(monkeypatch, raw)
    with pytest.raises((SyftError, ValueError)):
        runner.generate(source, destination)
    assert destination.read_bytes() == b"original"
    assert not list(tmp_path.glob(".syft-*"))


@pytest.mark.parametrize("error,expected", [
    (subprocess.CalledProcessError(2, ["syft"], stderr="scan failed"), SyftError),
    (subprocess.TimeoutExpired(["syft"], 300), SyftError),
    (FileNotFoundError("missing"), SyftError),
])
def test_process_failure(monkeypatch, tmp_path, runner, error, expected):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(subprocess, "run", fail)
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(expected):
        runner.generate(source, tmp_path / "out.json")
    assert not (tmp_path / "out.json").exists()


def test_missing_executable(monkeypatch):
    def fail(*args, **kwargs):
        raise FileNotFoundError("Syft not installed")
    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(SyftError):
        SyftRunner.preflight()
