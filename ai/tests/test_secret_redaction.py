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


# ---------------- finding ids after redaction (review case E7) ----------------

def short_canary() -> str:
    return "c" + rnd.token_hex(4)  # 9 chars: fits in a 20-character finding id; synthetic


def test_e7_redaction_does_not_create_duplicate_ids_or_mislink(monkeypatch):
    s1, s2 = short_canary(), short_canary()
    docker = f"FROM python:3.11-slim\nENV API_TOKEN={s1}\nENV DB_PASSWORD={s2}\n"
    reply = {
        "findings": [
            {"id": s1, "title": "first", "evidence": f"ENV API_TOKEN={s1}"},
            {"id": s2, "title": "second", "evidence": f"ENV DB_PASSWORD={s2}"},
            {"id": "F-001", "title": "third", "evidence": "FROM python:3.11-slim"},
        ],
        "correlations": [{"related_finding_ids": [s2], "explanation": "meant second"},
                         {"related_finding_ids": [s1, "F-001"], "explanation": "meant first and third"}],
        "patch": {"patched_dockerfile": "FROM python:3.11-slim\nRUN useradd app\nUSER app\n", "summary": "s"},
    }
    result = analyze_evidence(docker, [], settings=SETTINGS, client=fake_model(monkeypatch, reply))

    assert_no_leak(result, s1)
    assert_no_leak(result, s2)
    assert_contract(result)  # includes: ids unique, evidence keys == ids, references valid
    titles = {f["id"]: f["title"] for f in result["findings"]}
    ensure(len(titles) == 3, "finding ids are not unique after redaction")
    by_title = {t: i for i, t in titles.items()}
    ensure(by_title["first"] == REDACTED and by_title["third"] == "F-001", "unexpected kept ids")
    ensure(by_title["second"] not in (REDACTED, "F-001"), "renamed id collides")
    links = [[titles[i] for i in c["related_finding_ids"]] for c in result["correlations"]]
    ensure(links == [["second"], ["first", "third"]], "correlation points at the wrong finding")
    evidence = result["ai"]["finding_evidence"]
    ensure(evidence[by_title["second"]] == f"ENV DB_PASSWORD={REDACTED}", "evidence lost or mismatched")
    ensure(evidence[by_title["first"]] == f"ENV API_TOKEN={REDACTED}", "evidence lost or mismatched")
    ensure(any("renamed to" in w and "secret redaction" in w for w in result["ai"]["warnings"]),
           "missing rename warning")


def test_e7_review_messages_follow_renamed_id(monkeypatch):
    s1, s2 = short_canary(), short_canary()
    docker = f"FROM python:3.11-slim\nENV API_TOKEN={s1}\nENV DB_PASSWORD={s2}\n"
    reply = {  # patch keeps both secret lines -> unresolved_finding messages start with the finding id
        "findings": [{"id": s1, "title": "first", "evidence": f"ENV API_TOKEN={s1}"},
                     {"id": s2, "title": "second", "evidence": f"ENV DB_PASSWORD={s2}"}],
        "correlations": [],
        "patch": {"patched_dockerfile": docker + "RUN useradd app\nUSER app\n", "summary": "s"},
    }
    result = analyze_evidence(docker, [], settings=SETTINGS, client=fake_model(monkeypatch, reply))
    assert_no_leak(result, s1)
    assert_no_leak(result, s2)
    assert_contract(result)
    renamed = next(f["id"] for f in result["findings"] if f["title"] == "second")
    messages = [i["message"] for i in result["ai"]["patch_review"]["issues"] if i["code"] == "unresolved_finding"]
    ensure(any(m.startswith(f"{renamed} (second)") for m in messages), "review message not renamed")
    ensure(any(m.startswith(f"{REDACTED} (first)") for m in messages), "first review message changed")


def test_no_rename_when_redaction_keeps_ids_distinct(monkeypatch):
    s1 = short_canary()
    reply = {"findings": [{"id": s1, "title": "first"}, {"id": "F-002", "title": "second"}], "correlations": []}
    result = analyze_evidence(f"FROM python:3.11-slim\nENV API_TOKEN={s1}\n", [], settings=SETTINGS,
                              client=fake_model(monkeypatch, reply))
    assert_no_leak(result, s1)
    assert_contract(result)
    ensure([f["id"] for f in result["findings"]] == [REDACTED, "F-002"], "ids changed unnecessarily")
    ensure(not any("secret redaction" in w for w in result["ai"]["warnings"]), "unexpected rename warning")


# ---------------- secret fragments from length limits ----------------
# The parser shortens model fields (ids to 20 chars, titles to 300, ...). If a cut lands
# inside a secret, the remaining prefix is not the full secret, so plain redaction misses it.

MIN_FRAGMENT = 8


def fragment_paths(obj, secret, path="$"):
    """Paths of strings containing any piece of `secret` of MIN_FRAGMENT+ chars (every longer piece contains one)."""
    pieces = {secret[i:i + MIN_FRAGMENT] for i in range(len(secret) - MIN_FRAGMENT + 1)}
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from fragment_paths(k, secret, f"{path}.<key>")
            yield from fragment_paths(v, secret, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from fragment_paths(v, secret, f"{path}[{i}]")
    elif isinstance(obj, str) and any(p in obj for p in pieces):
        yield path


def assert_no_fragment(result, secret):
    __tracebackhide__ = True  # failure output must not show the `secret` argument
    found = sorted(set(fragment_paths(result, secret)))
    assert not found, f"secret fragment (>= {MIN_FRAGMENT} chars) found at: {found}"


ONE_FINDING = [{"id": "F-001", "title": "t"}]
FRAGMENT_CASES = {  # each places a 30-char secret across a parser length limit
    "finding_id": lambda s: {"findings": [{"id": s, "title": "t"}]},
    "finding_id_with_prefix": lambda s: {"findings": [{"id": "F-" + s, "title": "t"}]},
    "duplicate_long_id_warning": lambda s: {"findings": [{"id": "y" * 20 + s, "title": "a"},
                                                         {"id": "y" * 20 + s, "title": "b"}]},
    "title": lambda s: {"findings": [{"id": "F-001", "title": "x" * 290 + s}]},
    "description": lambda s: {"findings": [{"id": "F-001", "title": "t", "description": "x" * 3990 + s}]},
    "recommendation": lambda s: {"findings": [{"id": "F-001", "title": "t", "recommendation": "x" * 3990 + s}]},
    "evidence": lambda s: {"findings": [{"id": "F-001", "title": "t", "evidence": "x" * 3990 + s}]},
    "event_type_warning": lambda s: {"findings": ONE_FINDING, "correlations": [
        {"event_type": "E" * 90 + s, "related_finding_ids": ["F-001"], "explanation": "x"}]},
    "source_ip_warning": lambda s: {"findings": ONE_FINDING, "correlations": [
        {"source_ip": "1" * 50 + s, "related_finding_ids": ["F-001"], "explanation": "x"}]},
    "explanation": lambda s: {"findings": ONE_FINDING, "correlations": [
        {"related_finding_ids": ["F-001"], "explanation": "x" * 3990 + s}]},
    "summary": lambda s: {"findings": [], "summary": "x" * 990 + s},
    "limitation": lambda s: {"findings": [], "limitations": ["x" * 3990 + s]},
    "next_step": lambda s: {"findings": [], "next_steps": ["x" * 3990 + s]},
    "patch_summary": lambda s: {"findings": [], "patch": {
        "patched_dockerfile": "FROM python:3.11-slim\nUSER 1000\n", "summary": "x" * 990 + s}},
}


@pytest.mark.parametrize("build", list(FRAGMENT_CASES.values()), ids=list(FRAGMENT_CASES))
def test_length_limits_never_leave_a_secret_fragment(monkeypatch, build):
    secret = canary()  # 30 chars, longer than the 20-char id limit
    docker = dockerfile_with(f"ENV API_TOKEN={secret}")
    result = analyze_evidence(docker, LOGS, settings=SETTINGS, client=fake_model(monkeypatch, build(secret)))
    assert result["status"] == "completed"
    assert_no_leak(result, secret)
    assert_no_fragment(result, secret)
    assert_contract(result)  # ids still non-empty, unique, <= 20 chars, schema unchanged


def test_patched_dockerfile_cut_never_leaves_a_fragment(monkeypatch):
    from ai.response_parser import MAX_PATCH
    secret = canary()
    head = "FROM python:3.11-slim\nUSER 1000\n# "
    patched = head + "x" * (MAX_PATCH - 10 - len(head)) + secret + "\n"  # cut at MAX_PATCH lands inside it
    reply = {"findings": [], "patch": {"patched_dockerfile": patched, "summary": "s"}}
    result = analyze_evidence(dockerfile_with(f"ENV API_TOKEN={secret}"), None, settings=SETTINGS,
                              client=fake_model(monkeypatch, reply))
    assert_no_leak(result, secret)
    assert_no_fragment(result, secret)
    assert_contract(result)
    ensure(len(result["patch"]["patched_dockerfile"]) < MAX_PATCH, "patch was not cut before the secret")


def test_secret_known_only_from_patch_is_not_fragmented(monkeypatch):
    secret = canary()
    reply = {"findings": [{"id": "F-001", "title": "x" * 290 + secret}],
             "patch": {"patched_dockerfile": f"FROM python:3.11-slim\nENV API_KEY={secret}\nUSER 1000\n",
                       "summary": "s"}}
    result = analyze_evidence("FROM python:3.11-slim\n", None, settings=SETTINGS,
                              client=fake_model(monkeypatch, reply))
    assert_no_leak(result, secret)
    assert_no_fragment(result, secret)
    assert_contract(result)


def test_secret_defined_only_in_oversized_patch_is_not_fragmented(monkeypatch):
    # The only definition of the secret is a patch line that the MAX_PATCH cut splits.
    # The secret must be found in the full patch text, before cutting; otherwise only a
    # prefix is known and redacting it inside the title would leave the rest exposed.
    from ai.response_parser import MAX_PATCH
    secret = canary()
    prefix, line_start = "FROM python:3.11-slim\nUSER 1000\n", "ENV API_KEY="
    filler = "#" * (MAX_PATCH - len(prefix) - len(line_start) - 10 - 1) + "\n"
    patched = prefix + filler + line_start + secret + "\n"
    value_start = len(prefix) + len(filler) + len(line_start)
    ensure(value_start < MAX_PATCH < value_start + len(secret), "test setup: the cut must split the value")
    reply = {"findings": [{"id": "F-001", "title": f"API key {secret} is hardcoded"}],
             "patch": {"patched_dockerfile": patched, "summary": "s"}}
    result = analyze_evidence("FROM python:3.11-slim\n", None, settings=SETTINGS,  # no secret in the upload
                              client=fake_model(monkeypatch, reply))
    assert_no_leak(result, secret)
    assert_no_fragment(result, secret)
    assert_contract(result)
    ensure(result["findings"][0]["title"] == f"API key {REDACTED} is hardcoded", "title not redacted as a whole")
    ensure(len(result["patch"]["patched_dockerfile"]) <= MAX_PATCH, "patch length limit not applied")


def test_static_review_still_compares_evidence_with_original_dockerfile(monkeypatch):
    secret = canary()
    secret_line = f"ENV API_TOKEN={secret}"
    docker = dockerfile_with(secret_line)
    reply = {"findings": [{"id": "F-001", "title": "Hardcoded secret", "severity": "CRITICAL",
                           "evidence": secret_line, "description": "x" * 3990 + secret}],
             "patch": {"patched_dockerfile": docker.replace("CMD", "RUN useradd app\nUSER app\nCMD"),
                       "summary": "keeps the secret"}}
    result = analyze_evidence(docker, LOGS, settings=SETTINGS, client=fake_model(monkeypatch, reply))
    assert_no_fragment(result, secret)
    codes = {i["code"] for i in result["ai"]["patch_review"]["issues"]}
    assert {"hardcoded_secret", "unresolved_finding"} <= codes  # evidence line matched the original line
    assert result["ai"]["patch_status"] == "proposed_failed_static_review"
    ensure(result["ai"]["finding_evidence"]["F-001"] == f"ENV API_TOKEN={REDACTED}", "evidence changed")


def test_cuts_away_from_secrets_are_unchanged(monkeypatch):
    secret = canary()
    reply = {"findings": [
        {"id": "F-001", "title": "y" * 400},                              # no secret: normal cut
        {"id": "F-002", "title": secret + " tail"},                       # whole secret inside limit
        {"id": "F-003", "title": "z" * 295 + secret[:7] + "QQQQQQ"},      # only 7 chars shared: not a secret
    ]}
    result = analyze_evidence(dockerfile_with(f"ENV API_TOKEN={secret}"), None, settings=SETTINGS,
                              client=fake_model(monkeypatch, reply))
    titles = [f["title"] for f in result["findings"]]
    ensure(titles[0] == "y" * 300, "unrelated text was cut differently")
    ensure(titles[1] == f"{REDACTED} tail", "full secret not redacted or text around it lost")
    ensure(len(titles[2]) == 300, "text that is not a secret was shortened")


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
