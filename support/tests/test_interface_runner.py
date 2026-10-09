"""Comprueba sin red la coordinación de la interfaz de escritorio."""

import builtins
from pathlib import Path

import pytest
from typer.testing import CliRunner

import main
from support.interface import runner
from support.core.storage import fingerprint, initialize_run, write_json


def test_desktop_run_reports_phases_and_existing_html(tmp_path, monkeypatch):
    events = []
    dashboards = []
    calls = []
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(runner, "select_repositories", lambda org, limit: {
        "repositories": [{"repository": "acme/one"}], "requested_count": 1})
    monkeypatch.setattr(runner, "tool_configuration", lambda **kwargs: {"timeout": kwargs["timeout"]})
    monkeypatch.setattr(runner, "mine", lambda selection, run, config, **kwargs: calls.append(
        ("mine", selection["requested_count"], kwargs["progress"] is not None, run)))
    monkeypatch.setattr(runner, "prepare_data", lambda run: {"summary": {"repositories": 1}})
    monkeypatch.setattr(runner, "analyze", lambda data, run, **kwargs: calls.append(("analyze", kwargs["execute"])))

    def html(data, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("<html></html>")
        return destination

    monkeypatch.setattr(runner, "generate_html", html)

    def report(source, run, config, **kwargs):
        calls.append(("report", kwargs["client"]))
        return run / "reports/security-report.md"

    monkeypatch.setattr(runner, "run_report", report)

    def export(run, destination):
        calls.append(("export", destination.name))
        html({}, destination / "reports/dashboard.html")
        return destination

    monkeypatch.setattr(runner, "export_run", export)
    result = runner.run_analysis("acme", 50, events.append,
                                 lambda path: dashboards.append((path, Path(path).is_file())), root=tmp_path)

    assert calls[0] == ("mine", 1, True, tmp_path / "runs/acme")
    assert ("analyze", True) in calls
    assert ("report", None) in calls
    assert len([call for call in calls if call[0] == "export"]) == 2
    assert next(i for i, call in enumerate(calls) if call[0] == "export") < next(
        i for i, call in enumerate(calls) if call[0] == "report")
    assert all(exists for _, exists in dashboards)
    assert result.dashboard == dashboards[-1][0]
    assert result.dashboard.is_file()
    assert result.reporter_error is None
    assert all(any(message.startswith(phase) for message in events)
               for phase in ("Miner", "Analyzer", "Visualizer", "Reporter", "Resultados"))


def test_miner_phase_uses_one_fixed_run_path(tmp_path, monkeypatch):
    paths = []
    monkeypatch.setattr(runner, "select_repositories", lambda *_: {
        "repositories": [{"repository": "acme/one"}]})
    monkeypatch.setattr(runner, "tool_configuration", lambda **_: {})
    monkeypatch.setattr(runner, "mine", lambda selection, run, config, **kwargs: paths.append(run))

    first = runner.mine_phase("acme", 5, lambda _: None, root=tmp_path)
    second = runner.mine_phase("acme", 5, lambda _: None, root=tmp_path)
    assert first == second == tmp_path / "runs/acme"
    assert paths == [first, first]


def test_miner_reuses_matching_saved_selection_and_configuration(tmp_path, monkeypatch):
    run = initialize_run(tmp_path / "runs/acme")
    saved = {"organization": "acme", "requested_count": 1,
             "repositories": [{"repository": "acme/one", "commit": "abc"}],
             "created_at": "previous"}
    write_json(run / "manifest.json", {"selection": saved,
                                       "config_sha256": fingerprint({"timeout": 900})})
    monkeypatch.setattr(runner, "select_repositories", lambda *_: {**saved, "created_at": "new"})
    monkeypatch.setattr(runner, "tool_configuration", lambda **_: {"timeout": 900})
    calls = []
    monkeypatch.setattr(runner, "mine", lambda selection, path, config, **kwargs:
                        calls.append((selection["created_at"], kwargs["resume"])))

    runner.mine_phase("acme", 1, lambda _: None, root=tmp_path)
    assert calls == [("previous", True)]

    monkeypatch.setattr(runner, "tool_configuration", lambda **_: {"timeout": 300})
    runner.mine_phase("acme", 1, lambda _: None, root=tmp_path)
    assert calls[-1] == ("new", False)


def test_miner_matches_repository_revisions_even_if_github_order_changes():
    previous = {"organization": "Acme", "repositories": [
        {"repository": "Acme/one", "commit": "a"},
        {"repository": "Acme/two", "commit": "b"}]}
    current = {"organization": "acme", "repositories": [
        {"repository": "acme/two", "commit": "b", "updated_at": "later"},
        {"repository": "acme/one", "commit": "a"}]}
    assert runner.same_revisions(previous, current)
    current["repositories"][0]["commit"] = "c"
    assert not runner.same_revisions(previous, current)
    current["repositories"][0]["commit"] = None
    assert not runner.same_revisions(previous, current)
    current["repositories"][0]["commit"] = "b"
    current["repositories"][0]["category"] = "Servicios"
    assert not runner.same_revisions(previous, current)


def test_desktop_run_exports_miner_when_reporter_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "select_repositories", lambda *_: {"repositories": [{"repository": "a/b"}]})
    monkeypatch.setattr(runner, "tool_configuration", lambda **_: {})
    monkeypatch.setattr(runner, "mine", lambda *_, **__: None)
    monkeypatch.setattr(runner, "prepare_data", lambda *_: {})
    monkeypatch.setattr(runner, "analyze", lambda *_, **__: None)

    def html(_, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("<html></html>")
        return destination

    monkeypatch.setattr(runner, "generate_html", html)
    monkeypatch.setattr(runner, "run_report", lambda *_, **__: (_ for _ in ()).throw(ValueError("LLM failed")))
    exports = []

    def export(_, destination):
        exports.append(destination)
        html({}, destination / "reports/dashboard.html")

    monkeypatch.setattr(runner, "export_run", export)
    outcome = runner.run_analysis("acme", 5, lambda _: None, lambda _: None, root=tmp_path)
    assert outcome.reporter_error == "LLM failed"
    assert outcome.dashboard.is_file()
    assert exports == [outcome.export]


@pytest.mark.parametrize("organization, limit", [("", 5), ("acme/repo", 5), ("acme", 0), ("acme", True)])
def test_desktop_run_rejects_invalid_inputs_before_network(organization, limit):
    with pytest.raises(ValueError):
        runner.run_analysis(organization, limit, lambda _: None, lambda _: None)


def test_no_gui_runs_the_complete_pipeline_without_importing_tk(monkeypatch, tmp_path):
    captured = {}
    original_import = builtins.__import__

    def reject_tk(name, *args, **kwargs):
        if name.split(".", 1)[0] in {"tkinter", "_tkinter"}:
            raise AssertionError("El modo sin GUI importó Tkinter")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_tk)

    def fake_run(organization, limit, progress, dashboard_ready, *, timeout):
        captured.update(organization=organization, limit=limit, timeout=timeout)
        progress("Miner: listo")
        dashboard_ready(tmp_path / "dashboard.html")
        return runner.RunOutcome(tmp_path / "dashboard.html", tmp_path / "export", None, None)

    monkeypatch.setattr(main, "run_analysis", fake_run)
    result = CliRunner().invoke(main.app, ["--no-gui", "--organization", "acme",
                                           "--limit", "7", "--timeout", "120"])
    assert result.exit_code == 0, result.output
    assert captured == {"organization": "acme", "limit": 7, "timeout": 120}
    assert "Miner: listo" in result.output
    assert "Resultados portables:" in result.output


def test_no_gui_rejects_combination_with_a_subcommand():
    result = CliRunner().invoke(main.app, ["--no-gui", "analyze"])
    assert result.exit_code == 1
    assert "no se puede combinar" in result.output


def test_close_during_analysis_requires_confirmation(monkeypatch):
    from support.interface.tk_runtime import prepare

    prepare()
    from support.interface.app import AnalysisApp, messagebox

    class Root:
        closed = False

        def destroy(self):
            self.closed = True

    app = AnalysisApp.__new__(AnalysisApp)
    app.root = Root()
    app.running = True
    responses = iter((False, True))
    monkeypatch.setattr(messagebox, "askyesno", lambda *_: next(responses))

    app.close()
    assert app.root.closed is False
    app.close()
    assert app.root.closed is True


def test_saved_miner_run_is_available_only_after_all_records_are_saved(tmp_path, monkeypatch):
    run = initialize_run(tmp_path / "runs" / "acme-previous")
    write_json(run / "manifest.json", {"config_sha256": "settings", "selection": {
        "organization": "acme", "requested_count": 2,
        "repositories": [{"repository": "acme/one", "commit": "one"},
                         {"repository": "acme/two", "commit": "two"}]}})
    write_json(run / "logs/progress.json", {"completed": 2, "total": 2})
    write_json(run / "records/001.json", {"repository": "acme/one", "commit": "one",
                                           "config_sha256": "settings"})
    saved = runner.saved_run(run)
    assert saved is not None
    assert saved.completed == 1
    with pytest.raises(ValueError, match="solo registró"):
        runner.analyze_phase(run, lambda _: None, root=tmp_path)

    write_json(run / "records/002.json", {"repository": "acme/two", "commit": "two",
                                           "config_sha256": "settings"})
    assert runner.saved_run(run).completed == 2
    calls = []
    monkeypatch.setattr(runner, "prepare_data", lambda path: calls.append(path) or {})
    monkeypatch.setattr(runner, "analyze", lambda data, path, **kwargs: run / "reports/analysis.ipynb")
    assert runner.analyze_phase(run, lambda _: None, root=tmp_path) == run / "reports/analysis.ipynb"
    assert calls == [run]


def test_gui_phase_buttons_follow_saved_run_state(tmp_path):
    from support.interface.tk_runtime import prepare

    prepare()
    from support.interface.app import AnalysisApp

    class Control:
        def __init__(self):
            self.state = None

        def configure(self, **values):
            self.state = values.get("state", self.state)

    class Variable:
        def set(self, value):
            self.value = value

    run = tmp_path / "runs" / "acme-saved"
    app = AnalysisApp.__new__(AnalysisApp)
    app.running = False
    app.run_status = Variable()
    app.buttons = {phase: Control() for phase in ("all", "miner", "analyzer", "visualizer", "reporter")}
    app.refresh_button = Control()
    app.miner_run = runner.SavedRun(run, "acme", 1, 2, False, False)

    app.update_buttons()
    assert app.buttons["miner"].state == "normal"
    assert app.buttons["reporter"].state == "normal"
    assert app.buttons["analyzer"].state == "disabled"
    assert app.buttons["visualizer"].state == "disabled"

    app.miner_run = runner.SavedRun(run, "acme", 2, 2, True, False)
    app.update_buttons()
    assert app.buttons["analyzer"].state == "normal"
    assert app.buttons["visualizer"].state == "normal"
    assert app.buttons["reporter"].state == "normal"

    app.running = True
    app.update_buttons()
    assert all(button.state == "disabled" for button in app.buttons.values())


def test_gui_reports_html_path_relative_to_project_without_popup(tmp_path, monkeypatch):
    from support.interface.tk_runtime import prepare

    prepare()
    from support.interface import app as desktop

    dashboard = tmp_path / "results" / "run with spaces" / "reports/dashboard.html"
    dashboard.parent.mkdir(parents=True)
    dashboard.write_text("<html></html>")
    monkeypatch.setattr(desktop, "ROOT", tmp_path)
    monkeypatch.setattr(desktop.messagebox, "showinfo", lambda *_: pytest.fail("No debe abrir un pop-up"))
    messages = []
    instance = desktop.AnalysisApp.__new__(desktop.AnalysisApp)
    instance.events = desktop.queue.Queue()
    instance.root = type("Root", (), {"after": lambda *_: None})()
    instance.append_log = messages.append
    instance.events.put(("dashboard", dashboard))
    instance.process_events()
    assert messages == ["HTML listo: results/run with spaces/reports/dashboard.html "
                        "(desde la raíz del proyecto)."]
