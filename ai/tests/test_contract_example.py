"""
contracts/example_response.json must have the structure the API really returns.
Regression: the example used old field names ("issue", finding "evidence") and had
no `ai` object or `patch.summary`, so it did not match the integrated API.

Offline only: AI_MODE is forced to mock, or the AI call is replaced.
"""

import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = json.loads((REPO / "contracts" / "example_response.json").read_text(encoding="utf-8"))
client = TestClient(main.app)

# Lists that are empty in the example: the item shape a real response must use.
EMPTY_LIST_ITEMS = {
    "$.tests.proposed_patch.details": str,
    "$.ai.warnings": str,
    "$.ai.patch_review.issues": {"code": str, "message": str},
    "$.response.actions": {"type": str, "target": str, "reason": str, "status": str},
}


def assert_same_structure(real, example, path="$"):
    """Same keys at every level, same value types, list items shaped like the example's."""
    if path == "$.ai.finding_evidence":  # {finding_id: evidence}; ids depend on the findings
        assert isinstance(real, dict) and all(isinstance(v, str) for v in real.values()), path
        return
    if isinstance(example, dict):
        assert isinstance(real, dict), f"{path}: expected object"
        assert set(real) == set(example), f"{path}: keys {sorted(set(real) ^ set(example))} differ"
        for key, value in example.items():
            assert_same_structure(real[key], value, f"{path}.{key}")
    elif isinstance(example, list):
        assert isinstance(real, list), f"{path}: expected array"
        item = example[0] if example else EMPTY_LIST_ITEMS[path]
        for index, value in enumerate(real):
            if isinstance(item, type):
                assert isinstance(value, item), f"{path}[{index}]: expected {item.__name__}"
            else:
                shape = item if example else {k: t() for k, t in item.items()}
                assert_same_structure(value, shape, f"{path}[{index}]")
    elif example is None:
        assert real is None, f"{path}: expected null"
    else:
        assert type(real) is type(example), f"{path}: expected {type(example).__name__}"


def post(dockerfile: bytes, logs: bytes):
    return client.post("/api/analyze", files={
        "dockerfile": ("Dockerfile", io.BytesIO(dockerfile), "text/plain"),
        "attack_logs": ("attack_logs.json", io.BytesIO(logs), "application/json"),
    })


def test_real_mock_response_matches_contract_example(monkeypatch):
    monkeypatch.setenv("AI_MODE", "mock")
    data = post((REPO / "security" / "vulnerable.Dockerfile").read_bytes(),
                (REPO / "security" / "attack_logs.json").read_bytes()).json()
    assert data["status"] == "completed" and data["ai"]["source"] == "mock"
    # Make sure the nested checks run on non-empty data.
    assert data["findings"] and data["correlations"] and data["response"]["actions"]
    assert "proposed_patch" in data["tests"]
    assert_same_structure(data, EXAMPLE)
    assert set(data["ai"]["finding_evidence"]) == {f["id"] for f in data["findings"]}


def test_contract_example_tests_block_is_real_backend_output(monkeypatch):
    """The example's `tests` values are what the backend computes for its own scenario."""
    ai_part = {k: EXAMPLE[k] for k in ("status", "findings", "correlations", "patch", "ai")}
    monkeypatch.setattr(main, "analyze_evidence", lambda *_: json.loads(json.dumps(ai_part)))
    original = b"FROM python:3.11-slim\n"  # the "-" side of the example's diff
    assert EXAMPLE["patch"]["diff"].startswith(
        "--- Dockerfile\n+++ Dockerfile.proposed\n@@ -1 +1,3 @@\n " + original.decode())
    data = post(original, b'{"events": []}').json()
    assert data["tests"] == EXAMPLE["tests"]
    assert data["ai"]["patch_status"] == EXAMPLE["ai"]["patch_status"]


@pytest.mark.parametrize("old_field", ["issue", "evidence"])
def test_example_does_not_use_pre_agreement_finding_fields(old_field):
    assert old_field not in EXAMPLE["findings"][0]
