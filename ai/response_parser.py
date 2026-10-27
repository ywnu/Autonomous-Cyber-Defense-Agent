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
from collections import Counter
from contextvars import ContextVar
from typing import Any, Iterable, Optional

from ai.patch_review import ESCAPED_INSTRUCTION_BREAK_RE

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_ALIASES = {"MODERATE": "MEDIUM", "INFORMATIONAL": "INFO", "NONE": "INFO", "WARNING": "MEDIUM"}
MAX_FINDINGS = 50
MAX_TEXT = 4_000
MAX_PATCH = 100_000
ID_LIMIT = 20       # length of public finding ids (agreed format)
RAW_ID_LIMIT = 200  # model ids/references are matched on their full text up to this length
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

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


# Secret values for the parse in progress (set by parse_model_response). Used only to
# choose safe cut points; the parser never redacts (ai.service does, at the end).
_SENSITIVE: ContextVar[tuple[str, ...]] = ContextVar("_SENSITIVE", default=())


def _cut(text: str, limit: int) -> str:
    """
    text[:limit], except that the cut never lands inside a sensitive value: if it
    would, cut just before that value. Otherwise final redaction would miss the
    remaining prefix (it only matches whole values).
    """
    if len(text) <= limit:
        return text
    end = limit
    moved = True
    while moved:
        moved = False
        for value in _SENSITIVE.get():
            for start in range(max(0, end - len(value) + 1), end):
                if text.startswith(value, start):  # occurrence crosses the cut
                    end, moved = start, True
                    break
    return text[:end]


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = "\n".join(str(v) for v in value)
    elif not isinstance(value, str):
        value = str(value)
    return _cut(value.strip(), limit)


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


def _raw_id(value: Any) -> Optional[str]:
    """
    Full model-provided id used for matching, or None if unusable.
    Accepts strings and integers only; lists, objects, floats and booleans are not
    turned into ids. Ids with control characters or over RAW_ID_LIMIT are unusable.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > RAW_ID_LIMIT or _CONTROL_RE.search(value):
        return None
    return value


def _short(raw: str) -> str:
    return raw if len(raw) <= 40 else _cut(raw, 40) + "..."


def _parse_findings(items: Any, warnings: list[str]) -> tuple[list[dict], dict[str, str], dict]:
    """
    Return (findings in the agreed schema, {finding_id: quoted evidence}, ref_index).

    Public ids are at most ID_LIMIT characters and unique:
    - A usable model id keeps its first ID_LIMIT characters as the public id.
    - All public forms of model ids are reserved first; a missing, unusable or
      already-used id gets the next free "F-NNN".

    ref_index tells _parse_correlations how to resolve references, using the FULL
    model id (never the shortened one):
      "resolve":   {full id: public id} for ids that identify exactly one retained finding
      "ambiguous": full ids given more than once, or whose public form collides
                   with another retained id (cut to ID_LIMIT), or that are shared
                   with a dropped/capped finding
      "unretained": full ids of findings that were malformed or beyond MAX_FINDINGS
    """
    empty_index = {"resolve": {}, "ambiguous": set(), "unretained": set()}
    if not isinstance(items, list):
        warnings.append("'findings' was not a list; treated as empty.")
        return [], {}, empty_index

    valid = []  # (index, item, title, full model id or None)
    unretained: set[str] = set()
    for index, item in enumerate(items):
        raw = _raw_id(item.get("id")) if isinstance(item, dict) else None
        if index >= MAX_FINDINGS:
            if raw:
                unretained.add(raw)
            continue
        # "issue" is the pre-agreement name for "title"; accept both.
        title = _text(item.get("title") or item.get("issue"), 300) if isinstance(item, dict) else ""
        if not title:
            warnings.append(f"Dropped malformed finding at index {index}.")
            if raw:
                unretained.add(raw)
            continue
        if raw is None and item.get("id") not in (None, ""):
            warnings.append(f"Finding at index {index} has an unusable id (not a short single-line "
                            f"string or integer); a new id was assigned.")
        valid.append((index, item, title, raw))

    raw_counts = Counter(raw for *_, raw in valid if raw)
    # Public form: first ID_LIMIT chars, cut before any secret (may be "" if the id starts with one).
    public_of = {raw: _cut(raw, ID_LIMIT) for raw in raw_counts}
    public_forms: dict[str, set[str]] = {}
    for raw, public in public_of.items():
        if public:
            public_forms.setdefault(public, set()).add(raw)
    ambiguous = {
        raw for raw, count in raw_counts.items()
        if count > 1 or len(public_forms.get(public_of[raw], ())) > 1 or raw in unretained
    }
    taken = set(public_forms)  # reserve every model id's public form before generating replacements

    findings: list[dict] = []
    evidence: dict[str, str] = {}
    resolve: dict[str, str] = {}
    assigned: set[str] = set()
    next_number = 1
    for index, item, title, raw in valid:
        finding_id = public_of[raw] if raw else ""
        if not finding_id or finding_id in assigned:
            while f"F-{next_number:03d}" in taken:
                next_number += 1
            new_id = f"F-{next_number:03d}"
            taken.add(new_id)
            if finding_id:
                warnings.append(f"Finding at index {index}: id '{_short(raw)}' is already used, or matches "
                                f"another id in its first {ID_LIMIT} characters; renamed to '{new_id}'.")
            elif raw:
                warnings.append(f"Finding at index {index}: id could not be shortened safely; renamed to '{new_id}'.")
            finding_id = new_id
        if raw and raw not in ambiguous:
            resolve[raw] = finding_id  # the full id identifies exactly this finding
        assigned.add(finding_id)
        finding = {
            "id": finding_id,
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
    return findings, evidence, {"resolve": resolve, "ambiguous": ambiguous, "unretained": unretained}


def _parse_correlations(items: Any, warnings: list[str], ref_index: dict) -> list[dict]:
    """
    Structure, plus finding references. A reference is kept only if its FULL text
    matches exactly one retained finding's model id (see _parse_findings); it is then
    replaced by that finding's public id. References to duplicated, colliding,
    dropped, capped, unknown or parser-generated ids are dropped with a warning
    instead of guessing which finding was meant.
    Grounding of event_type/source_ip against the logs is done in ai.service.
    """
    resolve, ambiguous_ids, unretained = ref_index["resolve"], ref_index["ambiguous"], ref_index["unretained"]
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
        refs = [_raw_id(f) for f in ids] if isinstance(ids, list) else []
        ambiguous = sorted({_short(r) for r in refs if r in ambiguous_ids})
        if ambiguous:
            warnings.append(f"Correlation at index {index}: dropped reference(s) to duplicated finding id(s) "
                            f"{ambiguous}; the intended finding is unclear.")
        if any(r in unretained and r not in ambiguous_ids for r in refs):
            warnings.append(f"Correlation at index {index}: dropped reference(s) to findings that were "
                            f"malformed or beyond the first {MAX_FINDINGS}.")
        if any(r is None or (r not in resolve and r not in ambiguous_ids and r not in unretained) for r in refs):
            warnings.append(f"Correlation at index {index}: dropped reference(s) to unknown finding ids.")
        related = []
        for ref in refs:
            public = resolve.get(ref) if ref else None
            if public and public not in related:
                related.append(public)
        result.append({
            "event_type": _optional_text(item.get("event_type")),
            "source_ip": _optional_text(item.get("source_ip"), 64),
            "related_finding_ids": related,
            "explanation": _text(item.get("explanation")),
        })
    return result


_TRAILING_ESCAPED_BREAKS_RE = re.compile(r"(?:(?:\\r)?\\n)+\s*$")


def normalize_patch_line_breaks(text: str) -> str:
    """
    Some models return the patched Dockerfile with its line breaks escaped
    (the text "\\n" instead of a real newline), so the whole file is one line.
    Fix that, but only when it is unambiguous:
      - the text has no real line break (apart from surrounding whitespace), and
      - only a literal "\\n" directly before a Dockerfile instruction, or at the
        very end, is converted. Any other "\\n" (e.g. inside RUN printf "a\\nb")
        is kept as written.
    Text that already has real line breaks is returned unchanged.
    """
    if not isinstance(text, str) or "\n" in text.strip() or not ESCAPED_INSTRUCTION_BREAK_RE.search(text):
        return text
    fixed = ESCAPED_INSTRUCTION_BREAK_RE.sub("\n", text)
    return _TRAILING_ESCAPED_BREAKS_RE.sub("\n", fixed)


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
        if field == "patched_dockerfile" and raw:
            fixed = normalize_patch_line_breaks(raw)
            if fixed != raw:
                warnings.append("'patch.patched_dockerfile' used literal '\\n' sequences instead of "
                                "line breaks; they were converted to real line breaks.")
                raw = fixed
        patch[field] = _cut((raw or "").strip(), limit) if field == "summary" else _cut(raw or "", limit)
    return patch


def parse_model_response(raw_response: str, sensitive: Iterable[str] = ()) -> dict[str, Any]:
    """
    Return the validated AI portion:
    {findings, finding_evidence, correlations, patch, summary, limitations, next_steps, warnings}
    Raises ValueError if the response is empty, not JSON, or not a JSON object
    with a 'findings' field.

    `sensitive`: secret values that must never be split by a length limit (fields are
    cut before them instead). They are NOT redacted here; the caller redacts the result.
    """
    token = _SENSITIVE.set(tuple(v for v in set(sensitive) if v))
    try:
        return _parse(raw_response)
    finally:
        _SENSITIVE.reset(token)


def _parse(raw_response: str) -> dict[str, Any]:
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise ValueError("Model response is empty.")

    data = _extract_json_object(raw_response)
    if not isinstance(data, dict):
        raise ValueError("Model response must be a JSON object.")
    if "findings" not in data:
        raise ValueError("Model response is missing fields: ['findings']")

    warnings: list[str] = []
    findings, evidence, ref_index = _parse_findings(data.get("findings"), warnings)
    return {
        "findings": findings,
        "finding_evidence": evidence,
        "correlations": _parse_correlations(data.get("correlations"), warnings, ref_index),
        "patch": _parse_patch(data.get("patch"), warnings),
        "summary": _text(data.get("summary"), 1_000),
        "limitations": _str_list(data.get("limitations")),
        "next_steps": _str_list(data.get("next_steps")),
        "warnings": warnings,
    }


def to_json(data: dict[str, Any]) -> str:
    """Serialize a validated response as readable JSON."""
    return json.dumps(data, indent=2, ensure_ascii=False)
