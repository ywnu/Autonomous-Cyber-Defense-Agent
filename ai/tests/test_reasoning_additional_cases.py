import json
from dataclasses import replace
from pathlib import Path

from ai.config import get_settings
from ai.service import analyze_evidence

BASE = Path(__file__).resolve().parents[1] / "test_cases" / "additional"


def run_safe_case(logs=None):
    dockerfile = (BASE / "safe.Dockerfile").read_text(
        encoding="utf-8-sig"
    )
    settings = replace(get_settings(), mode="mock")

    return analyze_evidence(
        dockerfile,
        logs,
        settings=settings,
    )


def test_safe_dockerfile_has_no_findings():
    result = run_safe_case()

    assert result["status"] == "completed"
    assert result["ai"]["source"] == "mock"
    assert result["findings"] == []


def test_unrelated_logs_have_no_correlations():
    logs = json.loads(
        (BASE / "unrelated_logs.json").read_text(
            encoding="utf-8-sig"
        )
    )

    result = run_safe_case(logs)

    assert result["status"] == "completed"
    assert result["correlations"] == []


def test_no_logs_means_no_correlations():
    result = run_safe_case()

    assert result["correlations"] == []
