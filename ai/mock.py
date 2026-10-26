"""
Mock model for offline development (AI_MODE=mock).

Produces a deterministic, model-shaped JSON string from a few simple rules
so the team can run the full pipeline without spending API credits.
Results are labelled `source: "mock"` and are NOT real AI analysis.
"""

import json
import re
from typing import Any, Optional

MOCK_MODEL_NAME = "mock-rule-based"


def _lines(dockerfile_text: str) -> list[str]:
    return [line.rstrip() for line in dockerfile_text.splitlines()]


def _find(lines: list[str], pattern: str) -> list[str]:
    regex = re.compile(pattern, re.IGNORECASE)
    return [line for line in lines if regex.search(line)]


def _log_events(attack_logs: Any) -> list[dict]:
    """Accept {"events": [...]} or a bare list. Normalize the two field styles the team uses:
    `type`/`port` (ai/samples) and `event_type`/`target_port` (security/attack_logs.json)."""
    events = attack_logs.get("events", []) if isinstance(attack_logs, dict) else attack_logs
    if not isinstance(events, list):
        return []
    normalized = []
    for event in events:
        if not isinstance(event, dict):
            continue
        normalized.append({
            **event,
            "_type": str(event.get("type") or event.get("event_type") or "").lower(),
            "_port": str(event.get("port") or event.get("target_port") or ""),
            "_text": f"{event.get('payload', '')} {event.get('details', '')}".lower(),
            # Original values, copied as-is into correlations (None when absent; never invented).
            "_event_type": _str_or_none(event.get("event_type") or event.get("type")),
            "_source_ip": _str_or_none(event.get("source_ip")),
        })
    return normalized


def _str_or_none(value: Any) -> Optional[str]:
    return value.strip() if isinstance(value, str) and value.strip() else None


def mock_model_reply(dockerfile_text: str, attack_logs: Optional[Any] = None) -> str:
    lines = _lines(dockerfile_text)
    findings: list[dict] = []

    def add(title, severity, description, evidence, recommendation):
        findings.append({
            "id": f"F-{len(findings) + 1:03d}",
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    user_lines = _find(lines, r"^\s*USER\s+")
    if not user_lines:
        add("Container runs as root", "HIGH", "No USER instruction, so the container runs as root.",
            "No USER instruction found", "Create an unprivileged user and add `USER appuser`.")
    elif re.search(r"^\s*USER\s+(root|0)(\s|:|$)", user_lines[-1], re.IGNORECASE):
        add("Container runs as root", "HIGH", "The final USER is root.",
            user_lines[-1], "Switch to an unprivileged user.")

    ssh = _find(lines, r"^\s*EXPOSE\s+.*\b22(/tcp)?\b")
    if ssh:
        add("SSH port 22 exposed", "HIGH", "Exposing SSH increases attack surface and invites brute-force attempts.",
            ssh[0], "Remove `EXPOSE 22`; use `docker exec` for debugging instead of SSH.")

    ssh_install = _find(lines, r"^\s*RUN\s+.*\bopenssh-server\b")
    if ssh_install:
        add("SSH server installed", "MEDIUM", "An SSH daemon in the image is unnecessary attack surface.",
            ssh_install[0], "Remove openssh-server from the image.")

    # Key names such as DB_PASSWORD or AWS_SECRET_KEY with a literal (non-$) value.
    secrets = _find(lines, r"^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\w*"
                           r"\s*=\s*[\"']?[^\s\"'$]")
    if secrets:
        add("Hardcoded secret", "CRITICAL", "Secrets in the image are visible to anyone who can pull it.",
            secrets[0], "Inject secrets at runtime via environment or a secrets manager.")

    debug = _find(lines, r"^\s*(ENV|ARG)\s+\w*DEBUG\w*\s*=\s*[\"']?(true|1|yes|on)\b")
    if debug:
        add("Debug mode enabled", "MEDIUM", "Debug mode can expose internals such as environment variables.",
            debug[0], "Disable debug mode in production images.")

    chmod = _find(lines, r"chmod\s+(-R\s+)?777")
    if chmod:
        add("World-writable permissions", "MEDIUM", "chmod 777 lets any process modify these files.",
            chmod[0], "Use the least permissive mode needed (e.g. 755 or 644).")

    latest = _find(lines, r"^\s*FROM\s+\S+:latest\b") or _find(lines, r"^\s*FROM\s+[^\s:@]+\s*$")
    if latest:
        add("Unpinned base image", "LOW", "Unpinned images can change unexpectedly between builds.",
            latest[0], "Pin the base image to a specific version or digest.")

    correlations: list[dict] = []
    events = _log_events(attack_logs)
    by_title = {f["title"]: f["id"] for f in findings}

    def correlate(related_events, titles, explanation):
        """One correlation per (event_type, source_ip) pair, in log order."""
        ids = [by_title[t] for t in titles if t in by_title]
        if not ids:
            return
        seen = set()
        for event in related_events:
            key = (event["_event_type"], event["_source_ip"])
            if key in seen:
                continue
            seen.add(key)
            correlations.append({
                "event_type": key[0],
                "source_ip": key[1],
                "related_finding_ids": ids,
                "explanation": explanation,
            })

    ssh_events = [e for e in events if e["_port"] == "22" or "login" in e["_type"]]
    correlate(ssh_events, ["SSH port 22 exposed", "SSH server installed"],
              "Scanning and repeated login attempts on port 22 are consistent with brute-force "
              "against the exposed SSH service.")

    leak_events = [e for e in events if "exploit" in e["_type"]
                   or re.search(r"debug|env=|secret", e["_text"])]
    correlate(leak_events, ["Hardcoded secret", "Debug mode enabled"],
              "Requests targeting a debug/environment endpoint aim to read environment variables, "
              "which would expose the secret hardcoded in the image.")

    patched = []
    for line in lines:
        if line in secrets or line in debug:
            continue
        if line in ssh_install:
            line = re.sub(r"\s*\bopenssh-server\b", "", line)
            if re.search(r"\binstall(\s+-y)?\s*$", line):  # nothing left to install
                continue
        if line in ssh:
            ports = [p for p in line.split()[1:] if p.split("/")[0] != "22"]
            if ports:
                patched.append("EXPOSE " + " ".join(ports))
            continue
        line = re.sub(r"chmod\s+(-R\s+)?777", r"chmod \g<1>755", line)
        if line in latest:  # pin unpinned python images; other images stay flagged
            line = re.sub(r"^(\s*FROM\s+python)(:latest)?\s*$", r"\1:3.11-slim", line, flags=re.IGNORECASE)
        patched.append(line)
    if not user_lines and lines:
        # Insert before the final CMD/ENTRYPOINT so it applies at runtime.
        start = next((i for i in range(len(patched) - 1, -1, -1)
                      if re.match(r"^\s*(CMD|ENTRYPOINT)\b", patched[i], re.IGNORECASE)), len(patched))
        patched[start:start] = ["RUN useradd --create-home appuser", "USER appuser"]
    patched_text = "\n".join(patched) + "\n" if findings else ""

    changes = []
    if secrets:
        changes.append("removes the hardcoded secret")
    if debug:
        changes.append("disables debug mode")
    if ssh_install:
        changes.append("removes the SSH server")
    if ssh:
        changes.append("stops exposing port 22")
    if chmod:
        changes.append("replaces chmod 777 with 755")
    if any(re.match(r"^\s*FROM\s+python", line, re.IGNORECASE) for line in latest):
        changes.append("pins the base image")
    if not user_lines and lines:
        changes.append("adds and switches to a non-root user")
    patch_summary = ("[MOCK] Proposed patch " + ", ".join(changes) + ".") if patched_text and changes else ""

    reply = {
        "summary": f"[MOCK] {len(findings)} rule-based finding(s); {len(correlations)} correlation(s).",
        "findings": findings,
        "correlations": correlations,
        "patch": {"patched_dockerfile": patched_text, "diff": "", "summary": patch_summary},
        "limitations": ["Mock mode: simple pattern rules, not real AI analysis."],
        "next_steps": ["Run in live mode for model-based analysis.", "Validate the proposed patch in the backend."],
    }
    return json.dumps(reply)
