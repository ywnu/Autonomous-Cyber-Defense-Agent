"""
Backend entry point for AI analysis.

    from ai.service import analyze_evidence
    result = analyze_evidence(dockerfile_text, attack_logs)  # never raises

Returns a dict matching contracts/example_response.json, plus one additive
`ai` key with metadata (real vs mock, model, summary, limitations, errors).

- `findings`, `correlations`, `patch` come from the model (validated).
- `tests` is always {"status": "not_run", ...}: the backend must fill it after
  running its own validation. The AI never reports test results.
- `response` is always {"mode": "simulation", "actions": []}: the backend's
  simulation fills it. The AI never proposes or performs actions.

This function is blocking (network I/O). From an async FastAPI route call it with
`await starlette.concurrency.run_in_threadpool(analyze_evidence, text, logs)`.

Literal values of secret-like ENV/ARG keys in the uploaded Dockerfile (and in the
proposed patch) are replaced with "[REDACTED]" in every string of the returned
result. This protects the response only; the prompt sent to the model is unchanged.
"""

import difflib
import re
from typing import Any, Optional

from ai.config import Settings, get_settings
from ai.mock import MOCK_MODEL_NAME, mock_model_reply
from ai.nebius_client import AIIntegrationError, NebiusClient
from ai.patch_review import SECRET_KEY_RE, _instructions, review_patch
from ai.prompts import SYSTEM_PROMPT, build_user_prompt
from ai.response_parser import parse_model_response


def _unified_diff(original: str, patched: str) -> str:
    if not patched:
        return ""

    def lines(text: str) -> list[str]:
        return (text if text.endswith("\n") else text + "\n").splitlines(keepends=True)

    return "".join(difflib.unified_diff(
        lines(original), lines(patched), fromfile="Dockerfile", tofile="Dockerfile.proposed"
    ))


def _log_facts(attack_logs: Any) -> tuple[dict[str, str], set[str]]:
    """Event types (lowercase -> original spelling) and source IPs that actually appear in the logs."""
    if isinstance(attack_logs, dict):
        events = attack_logs.get("events", [attack_logs])
    else:
        events = attack_logs
    types: dict[str, str] = {}
    ips: set[str] = set()
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        event_type = event.get("event_type") or event.get("type")
        if isinstance(event_type, str) and event_type.strip():
            types.setdefault(event_type.strip().lower(), event_type.strip())
        ip = event.get("source_ip")
        if isinstance(ip, str) and ip.strip():
            ips.add(ip.strip())
    return types, ips


def _ground_correlations(
    correlations: list[dict], attack_logs: Any, finding_ids: set[str], warnings: list[str]
) -> list[dict]:
    """Keep event_type/source_ip only if they appear in the logs (else null); drop unknown finding ids."""
    types, ips = _log_facts(attack_logs)
    grounded = []
    for index, corr in enumerate(correlations):
        event_type = corr["event_type"]
        if event_type is not None:
            matched = types.get(event_type.lower())
            if matched is None:
                warnings.append(f"Correlation {index}: event_type '{event_type}' not found in logs; set to null.")
            event_type = matched
        source_ip = corr["source_ip"]
        if source_ip is not None and source_ip not in ips:
            warnings.append(f"Correlation {index}: source_ip '{source_ip}' not found in logs; set to null.")
            source_ip = None
        related = [fid for fid in corr["related_finding_ids"] if fid in finding_ids]
        if len(related) != len(corr["related_finding_ids"]):
            warnings.append(f"Correlation {index}: dropped reference(s) to unknown finding ids.")
        grounded.append({
            "event_type": event_type,
            "source_ip": source_ip,
            "related_finding_ids": related,
            "explanation": corr["explanation"],
        })
    return grounded


def _base_result(status: str, source: str, model: str) -> dict[str, Any]:
    return {
        "status": status,
        "findings": [],
        "correlations": [],
        "patch": {"patched_dockerfile": "", "diff": "", "summary": ""},
        "tests": {"status": "not_run", "passed": None, "details": []},
        "response": {"mode": "simulation", "actions": []},
        "ai": {
            "source": source,          # "nebius" (real model) or "mock"
            "model": model,
            "summary": "",
            "limitations": [],
            "next_steps": [],
            "warnings": [],
            "finding_evidence": {},    # {finding_id: quoted Dockerfile evidence}
            "patch_status": "proposed_not_validated",
            "error": None,             # {"code": ..., "message": ...} on failure
        },
    }


REDACTED = "[REDACTED]"
# Shorter values are not redacted: replacing e.g. "1" or "on" everywhere would corrupt unrelated text.
MIN_SECRET_LENGTH = 4


def _secret_values(dockerfile_text: Any) -> set[str]:
    """Literal values assigned to secret-like ENV/ARG keys. Same parsing rules as
    ai.patch_review._hardcoded_secrets, but returns values instead of key names.
    Variable references ($VAR, ${VAR}) are not literal secrets and are skipped."""
    if not isinstance(dockerfile_text, str):
        return set()
    values = set()
    for name, value in _instructions(dockerfile_text):
        if name not in ("ENV", "ARG"):
            continue
        pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", value)
        if not pairs:  # legacy form: ENV KEY value
            parts = value.split(None, 1)
            if name == "ENV" and len(parts) == 2:
                pairs = [(parts[0], parts[1])]
        for key, raw in pairs:
            secret = raw.strip().strip("\"'")
            if SECRET_KEY_RE.search(key) and len(secret) >= MIN_SECRET_LENGTH and not secret.startswith("$"):
                values.add(secret)
    return values


def _redact(value: Any, secrets: list[str]) -> Any:
    """Return a copy with every secret replaced in all strings (dict keys included). Types are preserved."""
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, dict):
        return {_redact(k, secrets): _redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, secrets) for v in value]
    return value


def analyze_evidence(
    dockerfile_text: str,
    attack_logs: Optional[Any] = None,
    settings: Optional[Settings] = None,
    client: Optional[NebiusClient] = None,
) -> dict[str, Any]:
    """
    Analyze already-validated evidence. Never raises for AI/network problems:
    on failure returns status "ai_error" with ai.error = {code, message}.
    Secret values from the Dockerfile and proposed patch are redacted from the whole result.
    """
    result = _analyze_unredacted(dockerfile_text, attack_logs, settings, client)
    secrets = _secret_values(dockerfile_text) | _secret_values(result["patch"]["patched_dockerfile"])
    if not secrets:
        return result
    # Longest first, so a secret that contains another secret is fully replaced.
    return _redact(result, sorted(secrets, key=len, reverse=True))


def _analyze_unredacted(
    dockerfile_text: str,
    attack_logs: Optional[Any] = None,
    settings: Optional[Settings] = None,
    client: Optional[NebiusClient] = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    source = "mock" if settings.mode == "mock" else "nebius"
    model = MOCK_MODEL_NAME if source == "mock" else settings.model

    def fail(code: str, message: str) -> dict[str, Any]:
        result = _base_result("ai_error", source, model)
        result["ai"]["error"] = {"code": code, "message": message}
        result["ai"]["patch_status"] = "none"
        return result

    if not isinstance(dockerfile_text, str) or not dockerfile_text.strip():
        return fail("bad_request", "Dockerfile text is empty.")

    try:
        if source == "mock":
            raw = mock_model_reply(dockerfile_text, attack_logs)
            usage: dict = {}
        else:
            reply = (client or NebiusClient(settings)).chat(
                SYSTEM_PROMPT, build_user_prompt(dockerfile_text, attack_logs)
            )
            raw, model, usage = reply["content"], reply["model"], reply["usage"]
        parsed = parse_model_response(raw)
    except AIIntegrationError as exc:
        return fail(exc.code, str(exc))
    except ValueError as exc:
        return fail("invalid_response", str(exc))

    result = _base_result("completed", source, model)
    warnings = list(parsed["warnings"])
    result["findings"] = parsed["findings"]
    result["correlations"] = (
        _ground_correlations(parsed["correlations"], attack_logs, {f["id"] for f in parsed["findings"]}, warnings)
        if attack_logs is not None else []
    )
    patched = parsed["patch"]["patched_dockerfile"]
    result["patch"] = {
        "patched_dockerfile": patched,
        # Computed locally; the model's own diff is not trusted.
        "diff": _unified_diff(dockerfile_text, patched),
        "summary": parsed["patch"]["summary"] if patched else "",
    }
    evidence = parsed["finding_evidence"]
    review = review_patch(
        dockerfile_text, patched, [{**f, "evidence": evidence.get(f["id"], "")} for f in parsed["findings"]]
    )
    if not patched:
        patch_status = "none"
    elif review["passed"]:
        # Static checks passed, but nothing was built or run.
        patch_status = "proposed_not_validated"
    else:
        patch_status = "proposed_failed_static_review"
    result["ai"].update(
        summary=parsed["summary"],
        limitations=parsed["limitations"],
        next_steps=parsed["next_steps"],
        warnings=warnings,
        finding_evidence=evidence,
        patch_status=patch_status,
        patch_review=review,
    )
    if usage:
        result["ai"]["usage"] = {
            k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens") if k in usage
        }
    return result
