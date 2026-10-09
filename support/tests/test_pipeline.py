"""Pruebas sin red de análisis, procedencia, limpieza y modelo simulado."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from support.core.models import RepositoryScan, ToolResult
from support.core.storage import cleanup_work, fingerprint, initialize_run, own_directory, read_json, sha256_file, write_json
from analyzer.prepare import prepare_data
from analyzer.notebook import analysis_tables
from miner.grype import GrypeError, parse_grype
from reporter.client import SimulatedLLMClient
from reporter.prompt import build_payload, request_report
from main import app
from miner.pipeline import mine, save_scan, select_repositories
from reporter.generate import generate_report, run_report
from reporter.project import snapshot_project
from miner.scanners import analyze_codeql, analyze_grype
from reporter.validate import validate_response
from visualizer.dashboard import generate_html


def sarif():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [
        {"id": "py/test", "properties": {"security-severity": "8.1", "tags": ["external/cwe/cwe-079"]}}
    ]}}, "results": [{"ruleIndex": 0, "message": {"text": "Review user input"},
                      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                            "region": {"startLine": 2}}}]}]}]}


@pytest.fixture
def dataset(tmp_path):
    run = initialize_run(tmp_path / "run")
    write_json(run / "manifest.json", {"selection": {"requested_count": 1}})
    evidence = run / "raw" / "result.sarif"
    write_json(evidence, sarif())
    code = {"rule_id": "py/test", "message": "Review user input", "severity": "warning",
            "file": "app.py", "start_line": 2}
    results = (
        ToolResult(tool="codeql", status="success", artifacts=(str(evidence),), data={"findings": [code, code]}),
        ToolResult(tool="syft", status="success_empty", data={"components": [], "component_count": 0}),
        ToolResult(tool="grype", status="failed", error="Database unavailable"),
    )
    scan = RepositoryScan(repository="acme/example", url="https://github.com/acme/example",
                          commit="a" * 40, config_sha256="config", tools=results)
    save_scan(run, run / "records/001.json", scan)
    return run, prepare_data(run)


def test_partial_codeql_keeps_evidence_and_separate_security_score(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    class Runner:
        version = "2.25.5"
        available_languages = {"python", "rust"}
        def create_database(self, *args):
            return tmp_path / "database"
        def analyze_database(self, database, language, output, workspace):
            write_json(output, sarif())
    result = analyze_codeql(source, tmp_path / "raw", ("python", "rust"), runner=Runner())
    assert result.status == "partial"
    assert [r["status"] for r in result.data["languages"]] == ["success", "unsupported"]
    assert Path(result.artifacts[0]).is_file()
    assert result.data["findings"][0]["severity"] == "warning"
    assert result.data["findings"][0]["security_severity"] == 8.1
    assert result.data["findings"][0]["cwes"] == ["CWE-079"]


def test_codeql_uses_unique_directories_and_rejects_output_inside_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    result = analyze_codeql(source, source / "out")
    assert result.status == "failed"
    assert "fuera del directorio" in result.error


def test_grype_preserves_advisories_package_and_fix_information():
    doc = {"matches": [{"vulnerability": {"id": "GHSA-test", "severity": "High",
            "namespace": "github:python", "fix": {"state": "fixed", "versions": ["2.0"]},
            "dataSource": "https://example.test/advisory"},
            "artifact": {"name": "package", "version": "1.0", "type": "python", "purl": "pkg:pypi/package@1.0"}}]}
    result, = parse_grype(doc)
    assert result.fixed_versions == ("2.0",)
    assert result.vulnerability_id == "GHSA-test"
    assert result.references == ("https://example.test/advisory",)
    assert parse_grype({"matches": []}) == ()


@pytest.mark.parametrize("value", [{}, {"matches": None}, {"matches": [{}]}])
def test_grype_invalid_output_is_not_empty_success(value):
    with pytest.raises(GrypeError):
        parse_grype(value)


def test_grype_skips_failed_syft_and_rejects_modified_sbom(tmp_path):
    failed = ToolResult(tool="syft", status="failed", error="Scanner failed")
    assert analyze_grype(failed, tmp_path).status == "skipped"
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}")
    valid = ToolResult(tool="syft", status="success_empty", artifacts=(str(sbom),),
                       data={"sbom_sha256": sha256_file(sbom), "component_count": 0})
    sbom.write_text('{"changed":true}')
    result = analyze_grype(valid, tmp_path)
    assert result.status == "failed" and "cambió" in result.error


def test_deduplication_keeps_failed_tool_in_denominator(dataset):
    run, data = dataset
    assert data["summary"]["code_findings"] == 1
    assert data["summary"]["coverage"]["grype"] == {"failed": 1}
    assert len(data["evidence"]) == 1
    (run / "raw/result.sarif").write_text("tampered")
    with pytest.raises(ValueError, match="hash"):
        prepare_data(run)


def test_category_reaches_analyzer_and_visualizer(dataset, tmp_path):
    run, _ = dataset
    write_json(run / "manifest.json", {"selection": {
        "organization": "nestjs", "requested_count": 1,
        "repositories": [{"repository": "acme/example", "category": "JavaScript"}]}})
    data = prepare_data(run)
    assert data["organization"] == "nestjs"
    assert data["repositories"][0]["category"] == "JavaScript"
    assert data["evidence"][0]["category"] == "JavaScript"
    assert analysis_tables(data)["by_category"]["JavaScript"] == {
        "repositories": 1, "code_findings": 1, "dependency_findings": 0,
        "codeql_completed": 1, "grype_completed": 0}
    html = generate_html(data, tmp_path / "dashboard.html").read_text()
    assert 'id="category"' in html
    assert 'category-code' in html


def test_simulated_report_mentions_failure_and_uses_known_evidence(dataset):
    run, data = dataset
    raw, payload = request_report(data)
    response = validate_response(raw, payload)
    assert response.simulated is True
    assert "fallaron" in response.summary
    assert response.observations[0].evidence_ids == (data["evidence"][0]["id"],)
    output = generate_report(data, run / "reports/report.md")
    assert "SIMULACIÓN" in output.read_text()
    assert "grype=fallido" in output.read_text()


def test_report_orchestrator_reuses_snapshot_and_records_provenance(dataset, tmp_path):
    run, _ = dataset
    write_json(run / "manifest.json", {
        "snapshot": {"source_sha256": "abc", "files": {}},
        "project_files": [], "project_file_limitations": [],
    })
    report = run_report(tmp_path, run, {}, resume=True)
    assert report.is_file()
    assert not (run / "reports/dashboard.html").exists()
    assert read_json(run / "reports/report-provenance.json") == {
        "provider": "simulated", "model": None, "source_sha256": "abc"}


@pytest.mark.parametrize("response", ["", " ", "{", "[]", '{"simulated":true}'])
def test_invalid_llm_response_is_rejected(dataset, response):
    with pytest.raises(ValueError):
        validate_response(response, build_payload(dataset[1]))


@pytest.mark.parametrize("mutation", ["reference", "count", "missing_limitations", "string_count", "duplicate_key"])
def test_llm_cannot_change_evidence_or_totals(dataset, mutation):
    payload = build_payload(dataset[1])
    doc = json.loads(SimulatedLLMClient().generate("", payload))
    if mutation == "reference": doc["observations"][0]["evidence_ids"] = ["invented"]
    if mutation == "count": doc["statistics"]["code_findings"] = 99
    if mutation == "missing_limitations": doc["limitations"] = []
    if mutation == "string_count": doc["statistics"]["code_findings"] = "1"
    raw = json.dumps(doc)
    if mutation == "duplicate_key": raw = raw.replace('"simulated": true', '"simulated": false, "simulated": true')
    with pytest.raises(ValueError):
        validate_response(raw, payload)


def test_rejected_report_does_not_overwrite_previous_output(dataset):
    run, data = dataset
    output = run / "reports/report.md"
    output.write_text("previous")
    client = SimpleNamespace(generate=lambda *_: "invalid")
    with pytest.raises(ValueError):
        generate_report(data, output, client=client)
    assert output.read_text() == "previous"


def test_context_limit_is_explicit_and_never_changes_statistics(dataset):
    payload = build_payload(dataset[1], max_findings=0)
    assert payload["evidence"] == []
    assert payload["statistics"]["code_findings"] == 1
    assert "omite 1" in payload["limitations"][-1]


def test_dashboard_cannot_execute_repository_text(dataset):
    run, data = dataset
    data["limitations"].append('</script><img src=x onerror=alert(1)>')
    data["limitations"].append('__DASHBOARD_JS__')
    html = generate_html(data, run / "reports/index.html").read_text()
    assert '</script><img' not in html
    assert '\\u003c/script\\u003e' in html
    assert 'https://cdn' not in html
    assert html.count('const data=JSON.parse') == 1
    assert '"__DASHBOARD_JS__"' in html


def test_cleanup_requires_saved_intact_evidence_and_ownership(dataset, tmp_path):
    run, _ = dataset
    workspace = own_directory(run, "repo-")
    (workspace / "keep").write_text("x")
    (run / "raw/result.sarif").write_text("tampered")
    with pytest.raises(ValueError, match="hash"):
        cleanup_work(run, workspace, run / "records/001.json")
    assert workspace.exists()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError):
        cleanup_work(run, outside, run / "records/001.json")
    assert outside.exists()


def test_cleanup_removes_only_owned_workspace(dataset):
    run, _ = dataset
    workspace = own_directory(run, "repo-")
    cleanup_work(run, workspace, run / "records/001.json")
    assert not workspace.exists()
    assert (run / "raw/result.sarif").exists()


def test_resume_refuses_changed_configuration(tmp_path):
    run = initialize_run(tmp_path / "run")
    manifest = {"repositories": []}
    write_json(run / "manifest.json", {"selection": manifest, "config_sha256": "old"})
    with pytest.raises(ValueError, match="Reanudar"):
        mine(manifest, run, {"timeout": 3}, resume=True)


def test_public_selection_filters_before_count_and_pins_commits():
    def repository(name, date, **flags):
        return {"full_name": f"acme/{name}", "updated_at": date, "default_branch": "main", **flags}
    records = [repository("z", "2026-01-01"), repository("a", "2026-01-01"),
               repository("fork", "2026-02-01", fork=True), repository("old", "2026-02-01", archived=True)]
    class Session:
        headers = {}
        def get(self, url, timeout):
            value = records if "/orgs/" in url else ({"sha": "a"*40} if "/commits/" in url else {"Python": 20})
            return SimpleNamespace(status_code=200, json=lambda: value)
    result = select_repositories("acme", 2, session=Session())
    assert [r["repository"] for r in result["repositories"]] == ["acme/a", "acme/z"]
    assert all(r["commit"] == "a"*40 for r in result["repositories"])


def test_public_selection_treats_count_as_upper_bound():
    class Session:
        headers = {}

        def get(self, url, timeout):
            if "/orgs/" in url:
                value = [{"full_name": "acme/one", "updated_at": "2026-01-01",
                          "default_branch": "main"}]
            elif "/commits/" in url:
                value = {"sha": "a" * 40}
            else:
                value = {"Python": 10}
            return SimpleNamespace(status_code=200, json=lambda: value)

    result = select_repositories("acme", 5, session=Session())
    assert result["repository_limit"] == 5
    assert result["requested_count"] == 1
    assert len(result["repositories"]) == 1
    assert result["limitations"] == []


def test_nestjs_selection_uses_primary_language_without_extra_api_calls():
    class Session:
        headers = {}

        def get(self, url, timeout):
            if "/orgs/" in url:
                value = [{"full_name": "nestjs/one", "updated_at": "2026-01-01",
                          "default_branch": "main", "language": "TypeScript"}]
            elif "/commits/" in url:
                value = {"sha": "a" * 40}
            else:
                pytest.fail(f"Consulta innecesaria: {url}")
            return SimpleNamespace(status_code=200, json=lambda: value)

    selected = select_repositories("nestjs", 50, session=Session())
    assert selected["requested_count"] == 1
    assert selected["repositories"][0]["category"] == "TypeScript"
    assert selected["repositories"][0]["languages"] == ["javascript"]


def test_snapshot_excludes_environment_and_records_uncommitted_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.py").write_text("print(1)")
    (source / ".env").write_text("SECRET=do-not-copy")
    (source / ".venv").mkdir()
    (source / ".venv/secret").write_text("do-not-copy")
    (source / "visualizer/assets").mkdir(parents=True)
    (source / "visualizer/assets/dashboard.js").write_text("const chart = 1;")
    (source / "results").mkdir()
    (source / "results/secret.json").write_text("do-not-copy")
    target = tmp_path / "snapshot"
    result = snapshot_project(source, target)
    assert result["commit"] is None
    assert set(result["files"]) == {"main.py", "visualizer/assets/dashboard.js"}
    assert not (target / ".env").exists()
    assert not (target / "results").exists()
    assert sha256_file(target / "visualizer/assets/dashboard.js") == result["files"]["visualizer/assets/dashboard.js"]
    assert result["source_sha256"] == fingerprint(result["files"])


def test_cli_visualize_and_help(dataset):
    run, _ = dataset
    result = CliRunner().invoke(app, ["visualize", "--run", str(run)])
    assert result.exit_code == 0, result.output
    assert (run / "reports/dashboard.html").is_file()
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "report" in result.output and "mine" in result.output



def test_evidence_ids_ignore_checkout_paths_and_keep_original_reference(tmp_path):
    from support.core.models import RepositoryScan
    identities = []
    for index in range(2):
        run = initialize_run(tmp_path / f"run-{index}")
        write_json(run / "manifest.json", {"selection": {"requested_count": 1}})
        source = f"/temporary/checkout-{index}"
        component = {"bom-ref": f"ephemeral-{index}", "name": source + "/Cargo.lock", "type": "file"}
        artifact = run / "raw/sbom.cdx.json"
        write_json(artifact, {"metadata": {"component": {"name": source}}, "components": [component]})
        tools = (ToolResult(tool="codeql", status="unsupported", error="No supported language"),
                 ToolResult(tool="syft", status="success", artifacts=(str(artifact),),
                            data={"components": [component], "component_count": 1}),
                 ToolResult(tool="grype", status="success_empty", data={"findings": []}))
        save_scan(run, run / "records/001.json", RepositoryScan(
            repository="acme/repo", url="local", commit="a"*40, config_sha256="config", tools=tools))
        evidence = prepare_data(run)["evidence"][0]
        identities.append(evidence["id"])
        assert evidence["detail"]["name"] == "Cargo.lock"
        assert evidence["source_refs"] == [f"ephemeral-{index}"]
    assert identities[0] == identities[1]


def test_missing_artifact_inventory_blocks_cleanup(dataset):
    run, _ = dataset
    workspace = own_directory(run, "repo-")
    record_path = run / "records/001.json"
    record = read_json(record_path)
    record["artifact_hashes"] = {}
    write_json(record_path, record)
    with pytest.raises(ValueError, match="inventario"):
        cleanup_work(run, workspace, record_path)
    assert workspace.exists()


def test_successful_export_is_portable_and_does_not_copy_work(dataset, tmp_path):
    from support.core.export import export_run
    run, data = dataset
    (run / "work/temporary").write_text("not for export")
    generate_html(data, run / "reports/dashboard.html")
    target = export_run(run, tmp_path / "export")
    assert not (target / "work/temporary").exists()
    assert prepare_data(target)["summary"] == data["summary"]
    assert (target / "raw/result.sarif").is_file()


def test_reporter_export_keeps_report_without_generating_dashboard(dataset, tmp_path):
    from support.core.export import export_run
    run, _ = dataset
    write_json(run / "manifest.json", {"snapshot": {"source_sha256": "abc", "files": {}}})
    (run / "reports/security-report.md").write_text("Informe validado")
    target = export_run(run, tmp_path / "reporter-export")
    assert (target / "reports/security-report.md").read_text() == "Informe validado"
    assert not (target / "reports/dashboard.html").exists()


def test_notebook_template_points_to_portable_data(dataset):
    import nbformat
    from analyzer.notebook import analyze
    run, data = dataset
    path = analyze(data, run, execute=False)
    notebook = nbformat.read(path, as_version=4)
    assert not (run / "prepared/tables.json").exists()
    assert "../prepared/data.json" in notebook.cells[1].source
    assert all(cell.get("execution_count") is None for cell in notebook.cells if cell.cell_type == "code")


def test_notebook_cells_are_valid_python_with_spanish_labels(dataset):
    import ast
    import nbformat
    from analyzer.notebook import analyze

    run, data = dataset
    notebook = nbformat.read(analyze(data, run, execute=False), as_version=4)
    for cell in notebook.cells:
        if cell.cell_type == "code":
            ast.parse(cell.source)
    assert any("Cobertura" in cell.source for cell in notebook.cells if cell.cell_type == "markdown")


def test_snapshot_does_not_recurse_into_its_destination(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.py").write_text("print(1)")
    result = snapshot_project(source, source / "custom-output/snapshot")
    assert list(result["files"]) == ["main.py"]


def test_invalid_grype_database_is_not_accepted(monkeypatch):
    from miner.grype import GrypeRunner
    monkeypatch.setattr(GrypeRunner, "run", lambda *_: '{"valid":false}')
    with pytest.raises(GrypeError, match="no es válida"):
        GrypeRunner("test").database_status()


def test_cli_export_and_invalid_run(dataset, tmp_path):
    run, _ = dataset
    result = CliRunner().invoke(app, ["export", "--run", str(run), "--destination", str(tmp_path / "export")])
    assert result.exit_code == 0, result.output
    result = CliRunner().invoke(app, ["analyze", "--run", str(tmp_path / "missing")])
    assert result.exit_code == 1


def test_successful_grype_does_not_treat_vulnerabilities_as_failure(tmp_path):
    source = tmp_path / "sbom.json"
    source.write_text('{}')
    sbom = ToolResult(tool="syft", status="success", artifacts=(str(source),),
                      data={"component_count": 1, "sbom_sha256": sha256_file(source)})
    class Runner:
        version = "test"
        def database_status(self):
            return {"valid": True, "built": "test"}
        def scan(self, sbom_path, destination):
            result = {"matches": [{"vulnerability": {"id": "CVE-test", "severity": "High"},
                                   "artifact": {"name": "example", "version": "1.0", "type": "python"}}]}
            write_json(destination, result)
            return result
    result = analyze_grype(sbom, tmp_path / "output", runner=Runner())
    assert result.status == "success"
    assert result.data["findings"][0]["vulnerability_id"] == "CVE-test"
    assert result.data["database"]["valid"] is True
