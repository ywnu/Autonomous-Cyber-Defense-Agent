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
from ai.response_parser import (
    _extract_json_object,
    normalize_patch_line_breaks,
    parse_model_response,
)


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


def _full_patch_text(raw: Any) -> str:
    """patch.patched_dockerfile from the model reply exactly as sent (before any length
    limit), found the same way the parser finds the JSON object. "" if absent or invalid."""
    if not isinstance(raw, str) or not raw.strip():
        return ""
    try:
        data = _extract_json_object(raw)
    except ValueError:
        return ""
    patch = data.get("patch") if isinstance(data, dict) else None
    value = patch.get("patched_dockerfile") if isinstance(patch, dict) else None
    # Same line-break normalization as the parser, so secrets on "lines" that the
    # model joined with literal "\n" are still found before any length limit.
    return normalize_patch_line_breaks(value) if isinstance(value, str) else ""


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
    used_for_cuts: set[str] = set()
    result = _analyze_unredacted(dockerfile_text, attack_logs, settings, client, used_for_cuts)
    # Redact every value the parser protected, even one whose defining line was later cut away.
    secrets = (_secret_values(dockerfile_text) | _secret_values(result["patch"]["patched_dockerfile"])
               | used_for_cuts)
    if not secrets:
        return result
    # Longest first, so a secret that contains another secret is fully replaced.
    ordered = sorted(secrets, key=len, reverse=True)
    _keep_ids_unique_after_redaction(result, ordered)
    return _redact(result, ordered)


def _keep_ids_unique_after_redaction(result: dict[str, Any], secrets: list[str]) -> None:
    """
    Redaction could turn two different finding ids into the same text (for example
    two ids that both contain a secret value). Before redacting, rename the later
    finding to a free "F-NNN" that redaction leaves unchanged, and update every place
    that refers to it (evidence keys, correlation references, review messages).
    Ids are unique before this step, so each reference is remapped exactly; nothing
    is guessed. Modifies `result` in place.
    """
    findings = result["findings"]
    if len(findings) < 2:
        return
    final_ids = {f["id"]: _redact(f["id"], secrets) for f in findings}
    reserved = set(final_ids) | set(final_ids.values())
    seen: set[str] = set()
    renames: dict[str, str] = {}
    number = 1
    for finding in findings:
        final = final_ids[finding["id"]]
        if final not in seen:
            seen.add(final)
            continue
        while (f"F-{number:03d}" in reserved
               or _redact(f"F-{number:03d}", secrets) != f"F-{number:03d}"):
            number += 1
        new_id = f"F-{number:03d}"
        reserved.add(new_id)
        seen.add(new_id)
        renames[finding["id"]] = new_id
    if not renames:
        return

    for finding in findings:
        finding["id"] = renames.get(finding["id"], finding["id"])
    ai = result["ai"]
    ai["finding_evidence"] = {renames.get(k, k): v for k, v in ai["finding_evidence"].items()}
    for corr in result["correlations"]:
        corr["related_finding_ids"] = [renames.get(i, i) for i in corr["related_finding_ids"]]
    for issue in ai.get("patch_review", {}).get("issues", []):
        for old, new in renames.items():
            if issue["message"].startswith(f"{old} ("):  # unresolved_finding messages start with the id
                issue["message"] = new + issue["message"][len(old):]
    for new_id in renames.values():
        ai["warnings"].append(
            f"A finding id would have matched another id after secret redaction; it was renamed to '{new_id}'."
        )


def _analyze_unredacted(
    dockerfile_text: str,
    attack_logs: Optional[Any] = None,
    settings: Optional[Settings] = None,
    client: Optional[NebiusClient] = None,
    secrets_out: Optional[set] = None,
) -> dict[str, Any]:
    """Analysis without redaction. Adds the secret values used for safe cuts to `secrets_out`."""
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
            # NebiusClient already rejects cut-off replies; this also covers injected clients.
            if reply.get("finish_reason") == "length":
                return fail("invalid_response", "Model output was cut off (max tokens); response rejected.")
            raw, model, usage = reply["content"], reply["model"], reply["usage"]
        # Length limits must never split a secret (a partial value would escape redaction).
        # Secrets come from the uploaded Dockerfile and from the FULL proposed patch, read
        # before any length limit: a cut patch line would only reveal a prefix of the value.
        sensitive = _secret_values(dockerfile_text) | _secret_values(_full_patch_text(raw))
        parsed = parse_model_response(raw, sensitive)
        # Safety net; with the full patch already scanned this should find nothing new.
        patch_secrets = _secret_values(parsed["patch"]["patched_dockerfile"]) - sensitive
        if patch_secrets:
            sensitive |= patch_secrets
            parsed = parse_model_response(raw, sensitive)
        if secrets_out is not None:
            secrets_out |= sensitive
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
    # Token counts come from Nebius (untrusted): keep only non-negative integers.
    counts = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage.get(key) if isinstance(usage, dict) else None
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            counts[key] = value
    if counts:
        result["ai"]["usage"] = counts
    return result
