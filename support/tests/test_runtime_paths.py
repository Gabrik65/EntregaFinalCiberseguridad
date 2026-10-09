"""Comprueba rutas y puntos de fallo de ejecución sin usar la red."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import main
from support.core.models import RepositoryScan, ToolResult
from support.core.storage import fingerprint, initialize_run, read_json, write_json
from reporter.client import OpenRouterClient
from miner.pipeline import mine, save_scan
from reporter.project import project_file_evidence


ROOT = Path(__file__).resolve().parents[2]
RUN_CONFIG = ROOT / "data/run-config.json"


def nestjs_selection(count=50):
    return {"organization": "nestjs", "requested_count": count, "repository_limit": count,
            "repositories": [
                {"repository": f"nestjs/example-{index}", "category": "TypeScript",
                 "url": f"https://github.com/nestjs/example-{index}.git",
                 "commit": f"{index:040x}", "languages": ["javascript"]}
                for index in range(count)]}


def test_saved_manifest_uses_limit_as_upper_bound(tmp_path):
    manifest = tmp_path / "manifest.json"
    write_json(manifest, nestjs_selection(2))
    selected = main.run_manifest(manifest, RUN_CONFIG)
    assert selected["organization"] == "nestjs"
    assert selected["requested_count"] == len(selected["repositories"]) == 2
    assert selected["repository_limit"] == 50
    assert all(item["category"] == "TypeScript" for item in selected["repositories"])


@pytest.mark.parametrize("limit", [0, 51, True, 5.0, "5"])
def test_run_manifest_rejects_invalid_limits(tmp_path, limit):
    settings = tmp_path / "run-config.json"
    manifest = tmp_path / "manifest.json"
    write_json(settings, {"repository_limit": limit})
    write_json(manifest, nestjs_selection(2))

    with pytest.raises(ValueError, match="repository_limit"):
        main.run_manifest(manifest, settings)


def test_cli_passes_only_configured_repositories_to_miner(tmp_path, monkeypatch):
    captured = {}

    def fake_mine(selection, run, config, **options):
        captured.update(selection=selection, run=run, config=config, options=options)

    monkeypatch.setattr(main, "configuration", lambda *_: {"timeout": 1})
    monkeypatch.setattr(main, "run_miner", fake_mine)
    monkeypatch.setattr(main, "select_repositories", lambda org, count: nestjs_selection(count))
    monkeypatch.setattr(main, "prepare_data", lambda *_: pytest.fail("Miner ran the Analyzer"))
    run = tmp_path / "new-run"

    result = CliRunner().invoke(main.app, ["mine", "--run", str(run)])

    assert result.exit_code == 0, result.output
    assert len(captured["selection"]["repositories"]) == 50
    assert captured["selection"]["organization"] == "nestjs"
    assert captured["run"] == run
    assert "Procesando 50 repositorios" in result.output


def test_visualizer_reads_saved_analyzer_data(tmp_path, monkeypatch):
    run = tmp_path / "run"
    write_json(run / "prepared/data.json", {"summary": {"repositories": 1}})
    monkeypatch.setattr(main, "prepare_data", lambda *_: pytest.fail("Visualizer ran the Analyzer"))

    def fake_html(data, destination):
        assert data["summary"]["repositories"] == 1
        destination.parent.mkdir(parents=True)
        destination.write_text("<html></html>")
        return destination

    monkeypatch.setattr(main, "generate_html", fake_html)
    result = CliRunner().invoke(main.app, ["visualize", "--run", str(run)])

    assert result.exit_code == 0, result.output
    assert (run / "reports/dashboard.html").is_file()


def test_cli_replaces_existing_owned_run_when_starting_new_mine(tmp_path, monkeypatch):
    run = initialize_run(tmp_path / "existing-run")
    marker = (run / ".run-owner.json").read_bytes()
    (run / "reports/previous.txt").write_text("old result")
    monkeypatch.setattr(main, "configuration", lambda *_: {"timeout": 1})
    monkeypatch.setattr(main, "select_repositories", lambda org, count: nestjs_selection(count))

    def unavailable(*_args, **_kwargs):
        raise ValueError("Offline test checkout")

    monkeypatch.setattr("miner.pipeline.prepare_checkout", unavailable)
    monkeypatch.setattr(main, "prepare_data", lambda *_: {"summary": {"repositories": 50}})

    result = CliRunner().invoke(main.app, ["mine", "--run", str(run)])

    assert result.exit_code == 0, result.output
    assert (run / ".run-owner.json").read_bytes() != marker
    assert not (run / "reports/previous.txt").exists()
    assert len(list((run / "records").glob("*.json"))) == 50
    assert len(read_json(run / "manifest.json")["selection"]["repositories"]) == 50


def test_cli_refuses_to_replace_unowned_directory(tmp_path, monkeypatch):
    run = tmp_path / "other-files"
    run.mkdir()
    sentinel = run / "keep.txt"
    sentinel.write_text("owned by user")
    monkeypatch.setattr(main, "configuration", lambda *_: {"timeout": 1})
    monkeypatch.setattr(main, "select_repositories", lambda org, count: nestjs_selection(count))

    result = CliRunner().invoke(main.app, ["mine", "--run", str(run)])

    assert result.exit_code == 1
    assert sentinel.read_text() == "owned by user"


def test_cli_refuses_to_replace_symlinked_run(tmp_path, monkeypatch):
    target = initialize_run(tmp_path / "owned-run")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    marker = (target / ".run-owner.json").read_bytes()
    monkeypatch.setattr(main, "configuration", lambda *_: {"timeout": 1})
    monkeypatch.setattr(main, "select_repositories", lambda org, count: nestjs_selection(count))

    result = CliRunner().invoke(main.app, ["mine", "--run", str(link)])

    assert result.exit_code == 1
    assert link.is_symlink()
    assert (target / ".run-owner.json").read_bytes() == marker


def test_resume_keeps_existing_run_directory(tmp_path):
    run = initialize_run(tmp_path / "run")
    selection = {"repositories": []}
    configuration = {"timeout": 1}
    write_json(run / "manifest.json", {"selection": selection,
                                        "config_sha256": fingerprint(configuration)})
    marker = (run / ".run-owner.json").read_bytes()

    assert mine(selection, run, configuration, resume=True) == run
    assert (run / ".run-owner.json").read_bytes() == marker


def test_resume_rejects_changed_evidence_before_scanning(tmp_path, monkeypatch):
    run = initialize_run(tmp_path / "run")
    configuration = {"timeout": 1}
    repository = {"repository": "nestjs/example", "commit": "a" * 40}
    selection = {"repositories": [repository]}
    write_json(run / "manifest.json", {"selection": selection,
                                        "config_sha256": fingerprint(configuration)})
    artifact = run / "raw" / "result.json"
    write_json(artifact, {"findings": []})
    scan = RepositoryScan(
        repository=repository["repository"],
        url="https://github.com/nestjs/example.git",
        commit=repository["commit"],
        config_sha256=fingerprint(configuration),
        tools=(ToolResult(tool="codeql", status="success_empty", artifacts=(str(artifact),)),
               ToolResult(tool="syft", status="skipped", error="Not run"),
               ToolResult(tool="grype", status="skipped", error="Not run")),
    )
    save_scan(run, run / "records/001.json", scan)
    artifact.write_text('{"findings":["changed"]}', encoding="utf-8")
    monkeypatch.setattr("miner.pipeline.prepare_checkout", lambda *_: pytest.fail("Unexpected checkout"))

    with pytest.raises(ValueError, match="hash del artefacto no coincide"):
        mine(selection, run, configuration, resume=True)


def test_openrouter_requires_credentials_without_making_request(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr("reporter.client.requests.post", lambda *_, **__: pytest.fail("Unexpected request"))

    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        OpenRouterClient(model="example/model")


@pytest.mark.parametrize("status,document,error", [
    (429, {}, "HTTP 429"),
    (200, {"choices": []}, "respuesta inválida"),
    (200, {"choices": [{"message": {"content": ""}}]}, "respuesta vacía"),
])
def test_openrouter_rejects_bad_responses_and_closes_them(
    monkeypatch, status, document, error
):
    class Response:
        status_code = status
        closed = False

        def json(self):
            return document

        def close(self):
            self.closed = True

    response = Response()
    monkeypatch.setattr("reporter.client.requests.post", lambda *_, **__: response)
    client = OpenRouterClient(model="example/model", api_key="test-key")

    with pytest.raises((ValueError, RuntimeError), match=error) as raised:
        client.generate("instructions", {"evidence": []})

    assert "test-key" not in str(raised.value)
    assert response.closed


def test_project_file_evidence_reports_signals_without_file_contents(tmp_path):
    source = tmp_path / "source"
    workflow = source / ".github/workflows/scan.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: pull_request_target\njobs:\n  scan:\n    uses: actions/checkout@v4\n")
    (source / ".env").write_text("SECRET=private-value")
    evidence, _ = project_file_evidence(source)

    assert [entry["detail"]["file"] for entry in evidence] == [
        ".github/workflows/scan.yml"
    ]
    assert any("no está fijada a un commit SHA-1" in signal
               for signal in evidence[0]["detail"]["signals"])
    assert "private-value" not in json.dumps(evidence)
