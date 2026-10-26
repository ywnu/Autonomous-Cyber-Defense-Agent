"""
Regression tests: secret values from uploaded Dockerfiles must not appear anywhere in
the analyze_evidence result. Synthetic random canaries only; no network (urlopen is faked).
Failure messages report field paths, never the canary value.
"""

import json
import secrets as rnd

import pytest

import ai.nebius_client as nc
from ai.nebius_client import NebiusClient
from ai.service import REDACTED, _analyze_unredacted, _secret_values, analyze_evidence
from ai.tests.test_ai_integration import MOCK, SAMPLES, SETTINGS, FakeResponse, assert_contract, chat_body


def canary() -> str:
    return "canary" + rnd.token_hex(12)  # synthetic, not a credential


def leak_paths(obj, secret, path="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and secret in k:
                yield f"{path}.<key>"
            yield from leak_paths(v, secret, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leak_paths(v, secret, f"{path}[{i}]")
    elif isinstance(obj, str) and secret in obj:
        yield path


def ensure(ok: bool, message: str):
    """Assert on a plain bool so pytest never prints compared values (which could contain the canary)."""
    __tracebackhide__ = True  # keep this frame (and its arguments) out of failure output
    assert ok, message


def assert_no_leak(result, secret):
    __tracebackhide__ = True  # failure output must not show the `secret` argument
    found = list(leak_paths(result, secret))
    assert not found, f"secret value found at: {found}"


def type_skeleton(obj):
    """Structure and types only, so tests can compare shapes without printing values."""
    if isinstance(obj, dict):
        return {k: type_skeleton(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [type_skeleton(v) for v in obj]
    return type(obj).__name__


def fake_model(monkeypatch, reply):
    body = json.dumps(chat_body(json.dumps(reply))).encode()
    monkeypatch.setattr(nc, "urlopen", lambda *a, **k: FakeResponse(body))
    return NebiusClient(SETTINGS, sleep=lambda s: None)


LOGS = [{"event_type": "EXPLOITATION_ATTEMPT", "source_ip": "192.0.2.5", "target_port": 22,
         "payload": "/api/debug?env=true"}]


def dockerfile_with(secret_line: str) -> str:
    return f"FROM python:3.11-slim\n{secret_line}\nEXPOSE 22 8000\nCMD [\"python\", \"app.py\"]\n"


# ---------------- mock response ----------------

def test_mock_response_redacts_dockerfile_secret():
    secret = canary()
    docker = dockerfile_with(f"ENV API_TOKEN={secret}")
    result = analyze_evidence(docker, LOGS, settings=MOCK)

    assert_no_leak(result, secret)
    assert_contract(result)
    assert result["status"] == "completed"
    evidence = result["ai"]["finding_evidence"]
    secret_id = next(f["id"] for f in result["findings"] if f["title"] == "Hardcoded secret")
    ensure(evidence[secret_id] == f"ENV API_TOKEN={REDACTED}", "evidence line not redacted as expected")
    ensure(f"-ENV API_TOKEN={REDACTED}" in result["patch"]["diff"], "removed secret line not redacted in diff")


def test_mock_redaction_keeps_unrelated_content_and_structure():
    secret = canary()
    docker = dockerfile_with(f"ENV API_TOKEN={secret}")
    raw = _analyze_unredacted(docker, LOGS, settings=MOCK)
    result = analyze_evidence(docker, LOGS, settings=MOCK)

    ensure(type_skeleton(result) == type_skeleton(raw), "structure or types changed")
    ensure([f["title"] for f in result["findings"]] == [f["title"] for f in raw["findings"]], "titles changed")
    ensure(result["correlations"] == raw["correlations"], "correlations changed")
    ensure(result["patch"]["patched_dockerfile"] == raw["patch"]["patched_dockerfile"],  # secret already removed
           "patched_dockerfile changed")
    ensure(result["patch"]["summary"] == raw["patch"]["summary"], "patch summary changed")
    ensure(result["ai"]["patch_status"] == raw["ai"]["patch_status"], "patch_status changed")
    ensure("EXPOSE 8000" in result["patch"]["patched_dockerfile"], "unrelated patch content lost")


def test_no_secret_means_result_is_unchanged():
    docker = (SAMPLES / "Dockerfile.hardened").read_text()
    assert analyze_evidence(docker, None, settings=MOCK) == _analyze_unredacted(docker, None, settings=MOCK)


# ---------------- simulated model response ----------------

def test_simulated_model_response_is_redacted_everywhere(monkeypatch):
    secret = canary()
    docker = dockerfile_with(f'ENV AWS_SECRET_KEY="{secret}"')
    secret_line = f'ENV AWS_SECRET_KEY="{secret}"'
    reply = {
        "summary": f"Found {secret}",
        "limitations": [f"saw {secret}"],
        "next_steps": [f"rotate {secret}"],
        "findings": [{"id": "F-001", "title": f"Hardcoded secret {secret}", "severity": "CRITICAL",
                      "description": f"value is {secret}", "recommendation": f"remove {secret}",
                      "evidence": secret_line}],
        "correlations": [{"event_type": f"EXFIL_{secret}", "source_ip": "192.0.2.5",
                          "related_finding_ids": ["F-001"], "explanation": f"payload targets {secret}"}],
        # Patch keeps the secret line -> static review reports it (nested review message).
        "patch": {"patched_dockerfile": f"FROM python:3.11-slim\n{secret_line}\nRUN useradd app\nUSER app\n"
                                        "CMD [\"python\", \"app.py\"]\n",
                  "diff": "", "summary": f"keeps {secret}"},
    }
    result = analyze_evidence(docker, LOGS, settings=SETTINGS, client=fake_model(monkeypatch, reply))

    assert_no_leak(result, secret)
    assert_contract(result)
    assert result["status"] == "completed"
    review = result["ai"]["patch_review"]
    assert {i["code"] for i in review["issues"]} >= {"hardcoded_secret", "unresolved_finding"}
    ensure(any(REDACTED in i["message"] for i in review["issues"]), "review message not redacted")
    assert result["ai"]["patch_status"] == "proposed_failed_static_review"
    ensure(REDACTED in result["ai"]["finding_evidence"]["F-001"], "model evidence not redacted")
    ensure(any(REDACTED in w for w in result["ai"]["warnings"]), "warning not redacted")  # invented event_type
    assert result["correlations"][0]["event_type"] is None
    assert result["correlations"][0]["source_ip"] == "192.0.2.5"  # non-sensitive value untouched


def test_secret_added_only_in_proposed_patch_is_redacted(monkeypatch):
    secret = canary()
    reply = {"findings": [], "correlations": [],
             "patch": {"patched_dockerfile": f"FROM python:3.11-slim\nENV API_KEY={secret}\nUSER 1000\n",
                       "summary": "adds config"}}
    result = analyze_evidence("FROM python:3.11-slim\n", None, settings=SETTINGS,
                              client=fake_model(monkeypatch, reply))
    assert_no_leak(result, secret)
    assert_contract(result)


def test_ai_error_result_is_redacted(monkeypatch):
    secret = canary()
    monkeypatch.setenv("NEBIUS_API_KEY", "")
    import dataclasses
    result = analyze_evidence(dockerfile_with(f"ENV DB_PASSWORD={secret}"), None,
                              settings=dataclasses.replace(SETTINGS, api_key=""))
    assert result["status"] == "ai_error" and result["ai"]["error"]["code"] == "config_error"
    assert_no_leak(result, secret)
    assert_contract(result)


# ---------------- detection rules ----------------

@pytest.mark.parametrize("template", [
    "ENV API_TOKEN={s}",
    'ENV DB_PASSWORD="{s}"',
    "ENV GITHUB_TOKEN='{s}'",
    "ARG PRIVATE_KEY={s}",
    "ENV APP_SECRET {s}",                    # legacy ENV form
    "ENV MODE=prod SERVICE_API_KEY={s}",     # several pairs on one line
])
def test_secret_forms_are_detected_and_redacted(template):
    secret = canary()
    docker = dockerfile_with(template.format(s=secret))
    ensure(secret in _secret_values(docker), f"secret not detected for form: {template.split('{')[0]}")
    assert_no_leak(analyze_evidence(docker, LOGS, settings=MOCK), secret)


@pytest.mark.parametrize("line", [
    "ENV API_TOKEN=$API_TOKEN",
    "ENV API_TOKEN=${API_TOKEN}",
    'ENV DB_PASSWORD="${DB_PASSWORD}"',
    "ARG SECRET_KEY=$SECRET_KEY",
    "ENV DEBUG_TOKEN=1",                     # too short to redact safely
    "ENV APP_NAME=my-service",               # not a secret-like key
])
def test_references_and_non_secrets_are_not_redacted(line):
    docker = dockerfile_with(line)
    assert _secret_values(docker) == set()
    assert analyze_evidence(docker, LOGS, settings=MOCK) == _analyze_unredacted(docker, LOGS, settings=MOCK)
