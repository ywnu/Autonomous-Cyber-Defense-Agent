from pathlib import Path

from fastapi.testclient import TestClient
from backend.main import app

BASE = Path(__file__).resolve().parents[1] / "test_cases" / "additional"


def test_safe_case_through_backend():
    dockerfile = (BASE / "safe.Dockerfile").read_bytes()
    logs = (BASE / "unrelated_logs.json").read_bytes()

    assert not dockerfile.startswith(b"\xef\xbb\xbf")
    assert not logs.startswith(b"\xef\xbb\xbf")

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            files={
                "dockerfile": (
                    "Dockerfile",
                    dockerfile,
                    "text/plain"
                ),
                "attack_logs": (
                    "unrelated_logs.json",
                    logs,
                    "application/json"
                ),
            },
        )

    assert response.status_code == 200, response.text

    result = response.json()

    assert result["status"] == "completed"
    assert result["ai"]["source"] == "mock"
    assert result["findings"] == []
    assert result["correlations"] == []
    assert result["tests"]["status"] == "completed"
    assert result["tests"]["passed"] is True
