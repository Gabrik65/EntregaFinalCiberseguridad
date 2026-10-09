"""Comprueba que el bundle queda utilizable por el UID de Compose."""

import stat

import pytest

from miner.codeql import CodeQLConfigurationError, CodeQLRunner
from support.scripts.install_codeql import make_bundle_readable


def test_preflight_rejects_unreadable_qlx_and_installer_repairs_it(tmp_path, monkeypatch):
    executable = tmp_path / "codeql" / "codeql"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    precompiled = executable.parent / "qlpacks/codeql/javascript-queries/1/.codeql/precompiled"
    precompiled.mkdir(parents=True)
    query = precompiled / "query.qlx"
    query.write_bytes(b"compiled")
    query.chmod(0o600)
    monkeypatch.setattr("miner.codeql.available_container_memory", lambda: 8 * 1024 ** 3)
    with pytest.raises(CodeQLConfigurationError, match="no puede leer"):
        CodeQLRunner.preflight(executable)
    make_bundle_readable(executable.parent)
    assert query.stat().st_mode & stat.S_IROTH
    assert all(path.stat().st_mode & stat.S_IXOTH for path in (precompiled, *precompiled.parents[:4]))

    def fake_json(self, arguments, workspace):
        return {"version": "2.25.5"} if arguments[0] == "version" else {"javascript": {}}

    monkeypatch.setattr(CodeQLRunner, "_json", fake_json)
    assert "javascript" in CodeQLRunner.preflight(executable).available_languages


def test_preflight_requires_eight_gib(tmp_path, monkeypatch):
    executable = tmp_path / "codeql"
    executable.write_text("x")
    executable.chmod(0o755)
    monkeypatch.setattr("miner.codeql.available_container_memory", lambda: 7 * 1024 ** 3)
    with pytest.raises(CodeQLConfigurationError, match="8 GiB"):
        CodeQLRunner.preflight(executable)
