"""Pruebas breves de interpretación SARIF sin ejecutar CodeQL."""

import json

import pytest

from miner.sarif import SarifError, parse_sarif



def test_parse_sarif_converts_a_result_to_a_finding(tmp_path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    sarif_path = tmp_path / "result.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [
                                    {
                                        "id": "py/example-rule",
                                        "defaultConfiguration": {
                                            "level": "warning"
                                        },
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleIndex": 0,
                                "message": {"text": "Example finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "src/example.py",
                                                "uriBaseId": "%SRCROOT%",
                                            },
                                            "region": {"startLine": 42},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = parse_sarif(sarif_path, checkout)

    assert len(findings) == 1
    assert findings[0].rule_id == "py/example-rule"
    assert findings[0].severity == "warning"
    assert findings[0].message == "Example finding"
    assert findings[0].file == "src/example.py"
    assert findings[0].start_line == 42


def test_parse_sarif_rejects_a_finding_without_a_location(tmp_path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    sarif_path = tmp_path / "invalid.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "CodeQL", "rules": []}},
                        "results": [
                            {
                                "ruleId": "py/example-rule",
                                "message": {"text": "Missing location"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SarifError, match="no tiene ubicación"):
        parse_sarif(sarif_path, checkout)
