"""
Static review of a model-proposed Dockerfile patch.

Text checks only. No image is built and no container is run, so passing
this review does NOT mean the patch is secure or that it works. It only
catches problems that are visible in the Dockerfile text itself.
"""

import re
from typing import Any

# Accounts present in the Debian/Alpine bases used by official images.
# Any other named user must be created in the final stage.
BASE_IMAGE_USERS = {"root", "nobody", "daemon", "bin", "sys", "www-data"}

SECRET_KEY_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)", re.IGNORECASE)
OVERCLAIM_RE = re.compile(r"^\s*#.*\b(fixed|verified|validated|tested|secured)\b", re.IGNORECASE)
CREATE_USER_RE = re.compile(r"\b(useradd|adduser)\b", re.IGNORECASE)
INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)\s+(.+)$")

DOCKERFILE_INSTRUCTIONS = (
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
)
# A literal backslash-n (text, not a line break) directly before an instruction:
# the model escaped the line breaks, so the "Dockerfile" is really one line.
ESCAPED_INSTRUCTION_BREAK_RE = re.compile(
    r"(?:\\r)?\\n(?=\s*(?:" + "|".join(DOCKERFILE_INSTRUCTIONS) + r")\b)", re.IGNORECASE
)

NOTE = "Static text checks only. No image was built and no container was run."


def _instructions(text: str) -> list[tuple[str, str]]:
    joined = re.sub(r"\\\r?\n\s*", " ", text)
    result = []
    for line in joined.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        match = INSTRUCTION_RE.match(line)
        if match:
            result.append((match.group(1).upper(), match.group(2).strip()))
    return result


def _final_stage(instructions: list[tuple[str, str]]) -> list[tuple[str, str]]:
    starts = [i for i, (name, _) in enumerate(instructions) if name == "FROM"]
    return instructions[starts[-1]:] if starts else instructions


def _hardcoded_secrets(instructions: list[tuple[str, str]]) -> list[str]:
    found = []
    for name, value in instructions:
        if name not in ("ENV", "ARG"):
            continue
        pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", value)
        if not pairs:  # legacy form: ENV KEY value
            parts = value.split(None, 1)
            if name == "ENV" and len(parts) == 2:
                pairs = [(parts[0], parts[1])]
        for key, raw in pairs:
            secret = raw.strip("\"'")
            if SECRET_KEY_RE.search(key) and secret and not secret.startswith("$"):
                found.append(key)
    return found


def _undefined_user(stage: list[tuple[str, str]]) -> str:
    users = [value.split()[0] for name, value in stage if name == "USER"]
    if not users:
        return ""
    user = users[-1].split(":")[0]
    if user.isdigit() or user.startswith("$") or user.lower() in BASE_IMAGE_USERS:
        return ""
    word = re.compile(rf"(?<![\w-]){re.escape(user)}(?![\w-])")
    created = any(
        name == "RUN" and CREATE_USER_RE.search(value) and word.search(value)
        for name, value in stage
    )
    return "" if created else user


def _final_user_issue(stage: list[tuple[str, str]]) -> dict[str, str] | None:
    """
    The container runs as the last USER of the final stage (root if there is none).
    Creating a user with useradd/adduser does not switch to it; only USER does.
    """
    users = [value.split()[0] for name, value in stage if name == "USER" and value.split()]
    if not users:
        return {"code": "missing_user",
                "message": "No USER instruction in the final stage, so the container still runs as root "
                           "(creating a user with useradd/adduser does not switch to it)."}
    user = users[-1].split(":")[0]
    if user.lower() in ("root", "0"):
        return {"code": "root_user",
                "message": f"The final USER is '{users[-1]}', which is root."}
    if user.startswith("$"):
        return {"code": "unverified_user",
                "message": f"The final USER is a variable ('{users[-1]}'); a static check cannot "
                           f"confirm that it is not root."}
    return None


def review_patch(original: str, patched: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return {"type": "static", "passed": bool, "issues": [{code, message}], "note": str}."""
    issues: list[dict[str, str]] = []
    if not patched.strip():
        return {"type": "static", "passed": True, "issues": [], "note": NOTE}

    # Escaped line breaks hide every instruction after the first, so no other
    # check below can be trusted for this text.
    if any(ESCAPED_INSTRUCTION_BREAK_RE.search(line) for line in patched.splitlines()):
        issues.append({"code": "malformed_line_breaks",
                       "message": "Patch contains literal '\\n' sequences instead of line breaks, "
                                  "so it is not a valid multi-line Dockerfile."})

    instructions = _instructions(patched)
    stage = _final_stage(instructions)

    for key in _hardcoded_secrets(instructions):
        issues.append({"code": "hardcoded_secret",
                       "message": f"Patch still hardcodes a secret in '{key}'."})

    user = _undefined_user(stage)
    if user:
        issues.append({"code": "undefined_user",
                       "message": f"USER '{user}' is never created in the final stage "
                                  f"(no useradd/adduser). Official python images do not define it, "
                                  f"so the container would fail to start."})

    user_issue = _final_user_issue(stage)
    if user_issue:
        issues.append(user_issue)

    patched_lines = {line.strip() for line in patched.splitlines() if line.strip()}
    original_lines = {line.strip() for line in original.splitlines() if line.strip()}
    for finding in findings:
        for line in str(finding.get("evidence", "")).splitlines():
            line = line.strip()
            if line and INSTRUCTION_RE.match(line) and line in original_lines and line in patched_lines:
                issues.append({"code": "unresolved_finding",
                               "message": f"{finding.get('id', '?')} ({finding.get('title') or finding.get('issue', '')}): "
                                          f"evidence line is unchanged in the patch: {line}"})

    for line in patched.splitlines():
        if OVERCLAIM_RE.match(line):
            issues.append({"code": "overclaim_comment",
                           "message": f"Patch comment claims a result that was not verified: {line.strip()}"})

    return {"type": "static", "passed": not issues, "issues": issues, "note": NOTE}
