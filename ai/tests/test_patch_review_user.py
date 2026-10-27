"""
Regression tests: a proposed Dockerfile must actually SWITCH to a non-root user
with USER. Creating a user (useradd/adduser) is not enough; the live Nemotron
patch did exactly that and previously passed the AI static review.

No network and no mock mode: review_patch is called directly, or a stub client
is passed to the service.
"""

import io
import json

import pytest
from fastapi.testclient import TestClient

from ai.config import Settings
from ai.patch_review import review_patch
from ai.service import analyze_evidence
from backend import main

ORIGINAL = 'FROM python:3.9-slim\nENV DEBUG_MODE="true"\nWORKDIR /app\nCMD ["python", "app.py"]\n'
USER_CODES = {"missing_user", "root_user", "unverified_user", "undefined_user"}

# The live Nemotron patch after line-break normalization: creates appuser, never switches to it.
LIVE_PATCH_WITHOUT_USER = (
    'FROM python:3.9-slim\nENV AWS_SECRET_KEY=""\nENV DEBUG_MODE="false"\nWORKDIR /app\n'
    "RUN useradd -m appuser\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\n"
    'COPY . .\nEXPOSE 5000\nCMD ["python", "app.py"]\n'
)
GOOD_PATCH = LIVE_PATCH_WITHOUT_USER.replace("EXPOSE 5000\n", "USER appuser\nEXPOSE 5000\n")


def codes(patched):
    return {i["code"] for i in review_patch(ORIGINAL, patched, [])["issues"]}


# ---------------- rejected ----------------

@pytest.mark.parametrize("patched, expected", [
    (LIVE_PATCH_WITHOUT_USER, "missing_user"),                                        # useradd only
    ("FROM python:3.11-slim\nRUN adduser --disabled-password appuser\n", "missing_user"),  # adduser only
    ("FROM python:3.11-slim\n", "missing_user"),                                       # no user at all
    ("FROM python:3.11-slim\nUSER root\n", "root_user"),
    ("FROM python:3.11-slim\nUSER 0\n", "root_user"),
    ("FROM python:3.11-slim\nUSER root:root\n", "root_user"),
    ("FROM python:3.11-slim\nUSER 0:0\n", "root_user"),
    # Switches to appuser, then back to root: the LAST USER is what the container runs as.
    ("FROM python:3.11-slim\nRUN useradd appuser\nUSER appuser\nRUN id\nUSER root\n", "root_user"),
    # USER only in the build stage; the final stage (what runs) has none.
    ("FROM python:3.11-slim AS build\nRUN useradd app\nUSER app\nFROM python:3.11-slim\nCOPY --from=build /a /a\n",
     "missing_user"),
    ("FROM python:3.11-slim\nARG APP_USER=appuser\nUSER $APP_USER\n", "unverified_user"),
])
def test_patch_without_effective_non_root_user_is_rejected(patched, expected):
    review = review_patch(ORIGINAL, patched, [])
    assert review["passed"] is False
    assert expected in {i["code"] for i in review["issues"]}


# ---------------- accepted by this check ----------------

@pytest.mark.parametrize("patched", [
    GOOD_PATCH,                                                             # live patch + USER appuser
    "FROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser\n",
    "FROM python:3.11-slim\nRUN groupadd app && useradd -g app appuser\nUSER appuser:app\n",
    "FROM python:3.11-slim\nUSER 10001\n",                                  # numeric non-zero UID
    "FROM python:3.11-slim\nUSER nobody\n",                                 # exists in the base image
    "FROM python:3.11-slim AS build\nRUN echo hi\nFROM python:3.11-slim\nRUN useradd appuser\nUSER appuser\n",
])
def test_patch_that_switches_to_non_root_user_passes_user_checks(patched):
    assert codes(patched) & USER_CODES == set()


def test_good_patch_passes_the_whole_static_review():
    review = review_patch(ORIGINAL, GOOD_PATCH, [])
    assert review == {"type": "static", "passed": True, "issues": [],
                      "note": "Static text checks only. No image was built and no container was run."}


def test_user_that_is_never_created_is_still_reported_as_undefined():
    # Existing check kept: USER must name a user that is created in the final stage.
    assert "undefined_user" in codes("FROM python:3.11-slim\nUSER appuser\n")


# ---------------- through the AI service and the backend ----------------

STUB_SETTINGS = Settings(
    mode="live", api_key="stub-key-not-used", base_url="https://example.invalid/v1", model="stub-model",
    timeout_seconds=5, max_retries=0, max_output_tokens=1024, json_mode="json_object",
)


class StubClient:
    """Returns one fixed reply; never touches the network."""

    def __init__(self, patched):
        self.content = json.dumps({
            "summary": "s", "findings": [], "correlations": [], "limitations": [], "next_steps": [],
            "patch": {"patched_dockerfile": patched, "diff": "", "summary": "Adds a non-root user."},
        })

    def chat(self, system_prompt, user_prompt):
        return {"content": self.content, "model": "stub-model", "usage": {}, "finish_reason": "stop"}


@pytest.mark.parametrize("patched, status", [
    (LIVE_PATCH_WITHOUT_USER, "proposed_failed_static_review"),
    (GOOD_PATCH, "proposed_not_validated"),  # passing static review is still "not validated"
])
def test_service_patch_status(patched, status):
    result = analyze_evidence(ORIGINAL, None, settings=STUB_SETTINGS, client=StubClient(patched))
    assert result["status"] == "completed"
    assert result["ai"]["patch_status"] == status


@pytest.mark.parametrize("patched, ai_passed, backend_passed", [
    (LIVE_PATCH_WITHOUT_USER, False, False),
    (GOOD_PATCH, True, True),
])
def test_backend_and_ai_reviews_agree_on_user(monkeypatch, patched, ai_passed, backend_passed):
    monkeypatch.setattr(main, "analyze_evidence",
                        lambda text, logs: analyze_evidence(text, logs, settings=STUB_SETTINGS,
                                                            client=StubClient(patched)))
    data = TestClient(main.app).post("/api/analyze", files={
        "dockerfile": ("Dockerfile", io.BytesIO(ORIGINAL.encode()), "text/plain"),
    }).json()
    assert data["ai"]["patch_review"]["passed"] is ai_passed
    assert data["tests"]["proposed_patch"]["passed"] is backend_passed
    assert data["tests"]["proposed_patch"]["status"] == "static_review_only"
    expected = "proposed_not_validated" if ai_passed and backend_passed else "proposed_failed_static_review"
    assert data["ai"]["patch_status"] == expected
