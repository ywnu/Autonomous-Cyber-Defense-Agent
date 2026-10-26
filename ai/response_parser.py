"""
Parse and validate the JSON returned by the AI model.

Model output is untrusted input. This module checks structure and types,
normalizes values, and drops malformed items. It does NOT verify that the
security findings are correct, and it never executes anything.

The model only produces the AI-owned parts of the team contract
(`findings`, `correlations`, `patch`) plus optional notes. `tests` and
`response` are owned by the backend; anything the model sends for them is ignored.
"""

import json
import re
from typing import Any, Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "INFORMATIONAL": "INFO", "NONE": "INFO", "WARNING": "MEDIUM"}
MAX_FINDINGS = 50
MAX_TEXT = 4_000
MAX_PATCH = 100_000

# Team-agreed public schema (exact keys).
FINDING_FIELDS = ("id", "title", "severity", "description", "recommendation")
CORRELATION_FIELDS = ("event_type", "source_ip", "related_finding_ids", "explanation")
PATCH_FIELDS = ("patched_dockerfile", "diff", "summary")

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json_object(raw: str) -> Any:
    text = _THINK_RE.sub("", raw).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fence = _FENCE_RE.search(text)
    if fence:
        try:
            return json.loads(fence.group(1).strip())
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    if start != -1:
        try:
            obj, _ = json.JSONDecoder().raw_decode(text[start:])
            return obj
        except json.JSONDecodeError:
            pass
    raise ValueError("Model response is not valid JSON.")


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = "\n".join(str(v) for v in value)
    elif not isinstance(value, str):
        value = str(value)
    return value.strip()[:limit]


def _severity(value: Any) -> str:
    sev = _text(value, 20).upper()
    sev = SEVERITY_ALIASES.get(sev, sev)
    return sev if sev in SEVERITIES else "MEDIUM"


def _str_list(value: Any, limit: int = 20) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [_text(v) for v in value[:limit] if _text(v)]


def _optional_text(value: Any, limit: int = 100) -> Optional[str]:
    text = _text(value, limit)
    return text if text and text.lower() not in ("null", "none", "unknown", "n/a") else None


def _parse_findings(items: Any, warnings: list[str]) -> tuple[list[dict], dict[str, str]]:
    """Return (findings in the agreed schema, {finding_id: quoted evidence})."""
    if not isinstance(items, list):
        warnings.append("'findings' was not a list; treated as empty.")
        return [], {}
    findings: list[dict] = []
    evidence: dict[str, str] = {}
    for index, item in enumerate(items[:MAX_FINDINGS]):
        # "issue" is the pre-agreement name for "title"; accept both.
        title = _text(item.get("title") or item.get("issue"), 300) if isinstance(item, dict) else ""
        if not title:
            warnings.append(f"Dropped malformed finding at index {index}.")
            continue
        finding = {
            "id": _text(item.get("id"), 20) or f"F-{len(findings) + 1:03d}",
            "title": title,
            "severity": _severity(item.get("severity")),
            "description": _text(item.get("description")),
            "recommendation": _text(item.get("recommendation")),
        }
        evidence[finding["id"]] = _text(item.get("evidence"))
        if not evidence[finding["id"]]:
            warnings.append(f"Finding {finding['id']} has no quoted evidence.")
        findings.append(finding)
    if len(items) > MAX_FINDINGS:
        warnings.append(f"Only the first {MAX_FINDINGS} findings were kept.")
    return findings, evidence


def _parse_correlations(items: Any, warnings: list[str]) -> list[dict]:
    """Structure only. Grounding of event_type/source_ip against the logs is done in ai.service."""
    if items is None:
        return []
    if not isinstance(items, list):
        warnings.append("'correlations' was not a list; treated as empty.")
        return []
    result = []
    for index, item in enumerate(items[:MAX_FINDINGS]):
        if not isinstance(item, dict) or not _text(item.get("explanation")):
            warnings.append(f"Dropped malformed correlation at index {index}.")
            continue
        # "finding_ids" is the pre-agreement name for "related_finding_ids"; accept both.
        ids = item.get("related_finding_ids", item.get("finding_ids", []))
        if isinstance(ids, str):
            ids = [ids]
        result.append({
            "event_type": _optional_text(item.get("event_type")),
            "source_ip": _optional_text(item.get("source_ip"), 64),
            "related_finding_ids": [_text(f, 20) for f in ids if _text(f, 20)] if isinstance(ids, list) else [],
            "explanation": _text(item.get("explanation")),
        })
    return result


def _parse_patch(value: Any, warnings: list[str]) -> dict:
    empty = {"patched_dockerfile": "", "diff": "", "summary": ""}
    if value is None:
        return empty
    if not isinstance(value, dict):
        warnings.append("'patch' was not an object; treated as empty.")
        return empty
    patch = {}
    for field, limit in (("patched_dockerfile", MAX_PATCH), ("diff", MAX_PATCH), ("summary", 1_000)):
        raw = value.get(field)
        if raw is not None and not isinstance(raw, str):
            warnings.append(f"'patch.{field}' was not a string; treated as empty.")
            raw = ""
        patch[field] = (raw or "").strip()[:limit] if field == "summary" else (raw or "")[:limit]
    return patch


def parse_model_response(raw_response: str) -> dict[str, Any]:
    """
    Return the validated AI portion:
    {findings, finding_evidence, correlations, patch, summary, limitations, next_steps, warnings}
    Raises ValueError if the response is empty, not JSON, or not a JSON object
    with a 'findings' field.
    """
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise ValueError("Model response is empty.")

    data = _extract_json_object(raw_response)
    if not isinstance(data, dict):
        raise ValueError("Model response must be a JSON object.")
    if "findings" not in data:
        raise ValueError("Model response is missing fields: ['findings']")

    warnings: list[str] = []
    findings, evidence = _parse_findings(data.get("findings"), warnings)
    return {
        "findings": findings,
        "finding_evidence": evidence,
        "correlations": _parse_correlations(data.get("correlations"), warnings),
        "patch": _parse_patch(data.get("patch"), warnings),
        "summary": _text(data.get("summary"), 1_000),
        "limitations": _str_list(data.get("limitations")),
        "next_steps": _str_list(data.get("next_steps")),
        "warnings": warnings,
    }


def to_json(data: dict[str, Any]) -> str:
    """Serialize a validated response as readable JSON."""
    return json.dumps(data, indent=2, ensure_ascii=False)
