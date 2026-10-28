import json
import re
import sys
from pathlib import Path


# Project paths
BASE_DIR = Path(__file__).resolve().parent
TEST_DIR = BASE_DIR / "test_cases"

EXPECTED_FILE = TEST_DIR / "expected_findings.json"
DEFAULT_OUTPUT_FILE = TEST_DIR / "model_output.json"


VULNERABLE_DOCKERFILE = TEST_DIR / "vulnerable.Dockerfile"


# Keywords used for preliminary evaluation.
# Each pattern needs context, not just a keyword: e.g. "root" alone would also
# match an SSH finding about a failed root login, and "credential" alone would
# match SSH credential guessing.
FINDING_PATTERNS = {
    "SEC-001": (
        r"\b(run|runs|running|executes?|executing)\s+(as|with)\s+(the\s+|a\s+)?"
        r"(default\s+|privileged\s+)?root\b"
        r"|\bnon-root\b"
        r"|\bno\s+USER\s+(instruction|directive)\b"
        r"|\bUSER\s+(instruction|directive)\s+(is\s+)?"
        r"(missing|absent|not\s+(set|specified|defined))\b"
        r"|\bmissing\s+USER\b"
        r"|\b(does|do)\s+not\s+(set|specify|define)\s+(a\s+)?USER\b"
        r"|\bdefaults?\s+to\s+(the\s+)?root\b"
        r"|\bUID\s+0\b"
    ),
    "SEC-002": r"\bssh\b|openssh|\bport\s+22\b|\bEXPOSE\s+22\b",
    "SEC-003": (
        r"aws_secret_key"
        r"|hard-?coded\s+(\w+\s+)?(secret|credential|password|api[\s_-]?key|token|key)"
        r"|\b(secret|credential|password|api[\s_-]?key|token)s?\b[^.]{0,60}"
        r"\b(hard-?coded|in\s+(an?\s+)?ENV|ENV\s+instruction|embedded|plain-?text)"
        r"|\b(ENV|ARG)\s+\w*(SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*"
    ),
    # No leading \b before DEBUG: in "DEBUG_MODE" the underscore is a word character.
    "SEC-005": (
        r"debug[\s_-]?mode"
        r"|\bdebug(ging)?\s+(is\s+)?(enabled|on|true|settings?|flag)"
        r"|\bDEBUG\s*=\s*['\"]?(true|1|on)\b"
    ),
}

# A finding that explicitly says the container is NOT running as root does not
# report the root-user weakness, even if its evidence mentions USER.
ROOT_NEGATION_PATTERN = (
    r"\b(is|are|does|do)\s+not\s+(run|running)\s+as\s+root\b"
    r"|\bwithout\s+root\s+privileges\b"
    r"|\b(is|are)\s+(already\s+)?running\s+as\s+(a\s+)?non-root\b"
    # Subject directly before "runs", so "never runs" / "no longer runs as a
    # non-root user" (which report the weakness) are not excluded.
    r"|\b(it|container|application|app|process|image|service)\s+(already\s+)?"
    r"runs\s+as\s+(a\s+)?non-root\b"
)

# Users that exist in the official python base images without being created.
BASE_IMAGE_USERS = {"nobody", "daemon", "bin", "sys", "www-data"}


def load_json(file_path):
    """Read and parse a JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def validate_output(data):
    """Check required fields for legacy and current AI outputs."""

    legacy_fields = [
        "summary",
        "risk_level",
        "findings",
        "attack_analysis",
        "patch",
        "containment_actions",
        "tests"
    ]

    current_fields = [
        "summary",
        "findings",
        "correlations",
        "patch",
        "limitations",
        "next_steps"
    ]

    if is_legacy_format(data):
        required_fields = legacy_fields
    else:
        required_fields = current_fields

    missing = [
        field for field in required_fields
        if field not in data
    ]

    return missing


def is_legacy_format(data):
    """Legacy outputs use risk_level/attack_analysis instead of correlations."""

    return "risk_level" in data or "attack_analysis" in data


def schema_errors(data):
    """Validate a current-format output against ai/output_schema.json."""

    # Allow running as `python ai/evaluate.py` (repo root not on sys.path).
    repo_root = str(BASE_DIR.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from ai.schema_validation import validate_against_schema

    return validate_against_schema(data)


def detect_finding(finding, pattern):
    """Check whether a finding matches a security category."""

    title = str(finding.get("title", ""))
    description = str(finding.get("description", ""))
    # Avoid counting explicit negation as a root vulnerability.
    if pattern == FINDING_PATTERNS["SEC-001"]:
        if re.search(
            ROOT_NEGATION_PATTERN,
            title + " " + description,
            re.IGNORECASE
        ):
            return False
    evidence = finding.get("evidence", [])

    if isinstance(evidence, str):
        evidence = [evidence]
    elif not isinstance(evidence, list):
        evidence = []

    content = " ".join([
        title,
        description,
        " ".join(str(item) for item in evidence)
    ])

    return bool(re.search(pattern, content, re.IGNORECASE))


def evaluate_findings(actual, expected):
    """Compare detected findings with expected categories."""

    actual_findings = actual.get("findings", [])

    if not isinstance(actual_findings, list):
        actual_findings = []

    expected_findings = expected.get("expected_findings", [])

    detected = []
    missed = []

    for expected_finding in expected_findings:

        finding_id = expected_finding["id"]
        pattern = FINDING_PATTERNS.get(finding_id)

        if pattern is None:
            missed.append(expected_finding)
            continue

        found = any(
            isinstance(finding, dict)
            and detect_finding(finding, pattern)
            for finding in actual_findings
        )

        if found:
            detected.append(expected_finding)
        else:
            missed.append(expected_finding)

    return detected, missed


def original_secret_values(dockerfile=VULNERABLE_DOCKERFILE):
    """Literal values of secret-like ENV/ARG keys in the vulnerable test Dockerfile."""

    try:
        text = Path(dockerfile).read_text(encoding="utf-8")
    except OSError:
        return []

    values = re.findall(
        r"(?mi)^\s*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*"
        r"\s*[= ]\s*[\"']?([^\"'\s]+)",
        text
    )
    # Very short values would match unrelated text.
    return [value for value in values if len(value) >= 4]


def evaluate_patch(patch):
    """Check basic patch requirements without executing it."""

    # Support the structured patch format used by AI Integration.
    if isinstance(patch, dict):
        patch = patch.get("patched_dockerfile", "")

    # Keep compatibility with the previous string format.
    if not isinstance(patch, str) or not patch.strip():
        return ["No Dockerfile patch was provided."]

    users = re.findall(r"(?m)^\s*USER\s+(\S+)", patch)
    final_user = users[-1].split(":")[0] if users else ""
    final_user_line = (
        [m.start() for m in re.finditer(r"(?m)^\s*USER\s+", patch)][-1]
        if users else -1
    )
    creation = re.search(
        rf"(?m)^\s*RUN\b.*\b(useradd|adduser)\b.*(?<![\w-]){re.escape(final_user)}(?![\w-])",
        patch
    ) if final_user else None

    checks = {
        # USER root (or uid 0) is still root.
        "Non-root USER instruction":
            bool(final_user) and final_user.lower() not in ("root", "0"),

        # A named user must be created before USER, or the container won't start.
        "Non-root user is created before USER":
            bool(final_user) and (
                final_user.isdigit()
                or final_user.startswith("$")
                or final_user.lower() in BASE_IMAGE_USERS
                or (creation is not None and creation.start() < final_user_line)
            ),

        "Preserves WORKDIR":
            bool(re.search(r"(?m)^\s*WORKDIR\s+", patch)),

        "Preserves CMD":
            bool(re.search(r"(?m)^\s*CMD\s+", patch)),

        "Preserves EXPOSE 5000":
            bool(re.search(r"(?m)^\s*EXPOSE\s+5000\b", patch)),

        "Removes EXPOSE 22":
            not bool(re.search(r"(?m)^\s*EXPOSE\s+22\b", patch)),

        "Removes OpenSSH installation":
            "openssh-server" not in patch.lower(),

        "Removes hardcoded AWS_SECRET_KEY":
            not bool(
                re.search(
                    r"(?m)^\s*(ENV|ARG)\s+AWS_SECRET_KEY\s*[= ]",
                    patch,
                    re.IGNORECASE
                )
            ),

        "Does not reproduce the original secret value":
            not any(value in patch for value in original_secret_values()),
    }

    return [
        name for name, passed in checks.items()
        if not passed
    ]

def check_unsupported_claims(actual):
    """Detect unsupported security conclusions."""

    issues = []

    # Support both legacy and current AI output formats.
    analysis_parts = [
        actual.get("attack_analysis", ""),
        actual.get("summary", "")
    ]

    patch = actual.get("patch")
    if isinstance(patch, dict):
        analysis_parts.append(patch.get("summary", ""))

    findings = actual.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                analysis_parts.append(finding.get("description", ""))

    correlations = actual.get("correlations", [])
    if isinstance(correlations, list):
        for correlation in correlations:
            if isinstance(correlation, dict):
                analysis_parts.append(correlation.get("explanation", ""))

    analysis = "\n".join(
        part for part in analysis_parts
        if isinstance(part, str)
    )

    unsupported_patterns = [
        r"attacker successfully compromised",
        r"attack was successful",
        r"confirmed successful compromise"
    ]

    for pattern in unsupported_patterns:
        if re.search(pattern, analysis, re.IGNORECASE):
            issues.append(
                "Model claims successful compromise without sufficient evidence."
            )
            break
    # Detect incorrect assumptions about Docker EXPOSE
    expose_patterns = [
        r"EXPOSE\s+22\s+automatically\s+makes\s+SSH\s+publicly\s+accessible",
        r"EXPOSE\s+22\s+automatically\s+exposes\s+SSH\s+to\s+the\s+internet",
        r"EXPOSE\s+22\s+means\s+SSH\s+is\s+publicly\s+accessible"
    ]

    for pattern in expose_patterns:
        if re.search(pattern, analysis, re.IGNORECASE):
            issues.append(
                "Model incorrectly assumes EXPOSE 22 makes SSH publicly accessible."
            )
            break

    # The AI never builds or runs the patch, so it cannot claim it was tested.
    tested_patterns = [
        (
            r"\bpatch\s+(was|has\s+been|is)\s+(successfully\s+)?"
            r"(tested|validated|verified|applied)\b"
        ),
        r"\b(tests?|validation)\s+(passed|succeeded)\b"
    ]

    for pattern in tested_patterns:
        if re.search(pattern, analysis, re.IGNORECASE):
            issues.append(
                "Model claims the patch was tested or applied without external validation."
            )
            break

    # The example credential must not be treated as a confirmed real secret.
    valid_secret_patterns = [
        r"\b(credential|secret|key)\s+is\s+(a\s+)?(confirmed\s+)?(valid|active|live)\b",
        r"\bconfirmed\s+(valid|active|live)\s+(credential|secret|key)\b"
    ]

    for pattern in valid_secret_patterns:
        if re.search(pattern, analysis, re.IGNORECASE):
            issues.append(
                "Model claims the example credential is a confirmed valid secret."
            )
            break
    return issues

def evaluate_attack_correlation(actual):
    """Check whether the AI analysis identifies key attack events."""

    logs_file = TEST_DIR / "attack_logs.json"

    if not logs_file.exists():
        print("[ERROR] Attack logs file not found.")
        return

    logs = load_json(logs_file)

    # Support legacy attack analysis.
    analysis = str(actual.get("attack_analysis", "")).lower()

    # Support structured correlations from AI Integration.
    correlations = actual.get("correlations", [])

    if isinstance(correlations, list):
        for correlation in correlations:
            if isinstance(correlation, dict):
                for field in ("event_type", "source_ip"):
                    value = correlation.get(field)

                    if isinstance(value, str):
                        analysis += "\n" + value.lower()

    print("\n--- ATTACK CORRELATION CHECK ---")

    # Extract source IPs from the attack logs
    source_ips = {
        log.get("source_ip")
        for log in logs
        if isinstance(log, dict) and log.get("source_ip")
    }

    # Extract event types
    event_types = {
        log.get("event_type")
        for log in logs
        if isinstance(log, dict) and log.get("event_type")
    }

    checks = {}

    # Check whether AI mentions the source IPs
    for ip in source_ips:
        checks[f"Source IP: {ip}"] = ip.lower() in analysis

    # Check whether AI identifies attack events
    for event in event_types:
        checks[f"Attack Event: {event}"] = event.lower() in analysis

    passed = 0

    for name, result in checks.items():
        if result:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[MISSING] {name}")

    total = len(checks)

    score = (passed / total * 100) if total else 0

    print(f"\nAttack Evidence Coverage: {score:.1f}%")
    print(f"Evidence Identified: {passed}/{total}")

def evaluate_vulnerability_correlation(actual):
    """Check whether attack events are linked to relevant weaknesses."""

    analysis = str(actual.get("attack_analysis", "")).lower()

    print("\n--- ATTACK-TO-VULNERABILITY CORRELATION ---")

    # Split analysis into sentences
    sentences = re.split(r"[.!?]\s+", analysis)

    ssh_correlation = any(
        ("ssh" in sentence)
        and ("openssh-server" in sentence or "expose 22" in sentence)
        and ("relevant" in sentence or "related" in sentence or "linked" in sentence)
        for sentence in sentences
    )

    debug_correlation = any(
        ("debug endpoint" in sentence or "exploitation_attempt" in sentence)
        and ("debug_mode" in sentence or "credential" in sentence)
        and ("relevant" in sentence or "related" in sentence or "linked" in sentence)
        for sentence in sentences
    )
    # Evaluate structured correlations from AI Integration.
    if isinstance(actual.get("correlations"), list):

        ssh_correlation = False
        debug_correlation = False

        findings_by_id = {
            finding["id"]: finding
            for finding in actual.get("findings", [])
            if isinstance(finding, dict)
            and isinstance(finding.get("id"), str)
        }

        for correlation in actual["correlations"]:

            if not isinstance(correlation, dict):
                continue

            event_type = correlation.get("event_type")
            related_ids = correlation.get("related_finding_ids", [])

            if not isinstance(related_ids, list):
                continue

            for finding_id in related_ids:

                finding = findings_by_id.get(finding_id)

                if not finding:
                    continue

                finding_text = (
                    str(finding.get("title", "")) + " " +
                    str(finding.get("description", ""))
                ).lower()

                if event_type == "AUTH_ATTEMPT":
                    if "ssh" in finding_text or "openssh" in finding_text:
                        ssh_correlation = True

                # The logged attempt targets the debug endpoint to extract
                # AWS_SECRET_KEY, so only a linked finding that is itself a
                # hardcoded-secret (SEC-003) or debug (SEC-005) finding counts.
                if event_type == "EXPLOITATION_ATTEMPT" and (
                    detect_finding(finding, FINDING_PATTERNS["SEC-003"])
                    or detect_finding(finding, FINDING_PATTERNS["SEC-005"])
                ):
                    debug_correlation = True
    checks = {
        "SSH attack linked to SSH configuration": ssh_correlation,
        "Debug attack linked to sensitive configuration": debug_correlation
    }

    passed = 0

    for name, result in checks.items():
        if result:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[MISSING] {name}")

    total = len(checks)

    print(f"\nCorrelation Coverage: {passed / total * 100:.1f}%")
    print(f"Correlations Identified: {passed}/{total}")

def evaluate_terraform():
    """Evaluate Terraform security findings."""

    expected_file = TEST_DIR / "terraform_expected_findings.json"
    output_file = TEST_DIR / "terraform_model_output.json"

    print("\n--- TERRAFORM SECURITY EVALUATION ---")

    if not expected_file.exists():
        print("[ERROR] Terraform expected findings file not found.")
        return

    if not output_file.exists():
        print("[INFO] Terraform model output not available yet.")
        print("Terraform evaluation will run when output is provided.")
        return

    try:
        expected = load_json(expected_file)
        actual = load_json(output_file)

    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Could not read Terraform JSON: {error}")
        return

    if not isinstance(expected, dict) or not isinstance(actual, dict):
        print("[ERROR] Terraform data must be JSON objects.")
        return

    expected_findings = expected.get("expected_findings", [])
    actual_findings = actual.get("findings", [])

    if not isinstance(expected_findings, list) or not isinstance(actual_findings, list):
        print("[ERROR] Findings must be lists.")
        return

    detected = 0

    for expected_finding in expected_findings:

        title = expected_finding.get("title", "")

        found = any(
            isinstance(finding, dict)
            and finding.get("title", "").strip().lower() == title.lower()
            for finding in actual_findings
            if isinstance(finding.get("title", ""), str)
        )

        if found:
            print(f"[DETECTED] {title}")
            detected += 1
        else:
            print(f"[MISSED] {title}")

    total = len(expected_findings)

    score = (detected / total * 100) if total else 0

    print(f"\nTerraform Detection Coverage: {score:.1f}%")
    print(f"Detected: {detected}/{total}")

    print("\nNote: This is a preliminary title-matching evaluation.")
def service_result_to_model_output(result):
    """Convert an ai.service.analyze_evidence() result back into the AI
    Reasoning output format (ai/output_schema.json) so it can be evaluated."""

    ai = result.get("ai", {})
    evidence = ai.get("finding_evidence", {})
    patch = result.get("patch", {})

    return {
        "summary": ai.get("summary", ""),
        "findings": [
            {**finding, "evidence": evidence.get(finding.get("id"), "")}
            for finding in result.get("findings", [])
        ],
        "correlations": result.get("correlations", []),
        "patch": {
            "patched_dockerfile": patch.get("patched_dockerfile", ""),
            # The service computes its own diff; the model is asked for "".
            "diff": "",
            "summary": patch.get("summary", ""),
        },
        "limitations": ai.get("limitations", []),
        "next_steps": ai.get("next_steps", []),
    }


def run_pipeline(mode):
    """Run the real analysis pipeline on the test case and return its output.

    mode "live" calls the Nebius model configured in .env; "mock" uses the
    offline rule-based mock (useful only to check the pipeline, not the AI).
    Returns None if the analysis failed (the error is printed).
    """

    import dataclasses

    repo_root = str(BASE_DIR.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from ai.config import get_settings
    from ai.service import analyze_evidence

    settings = dataclasses.replace(get_settings(), mode=mode)
    dockerfile = VULNERABLE_DOCKERFILE.read_text(encoding="utf-8")
    logs = load_json(TEST_DIR / "attack_logs.json")

    print(f"Running analysis pipeline (mode={mode}, model={settings.model or 'n/a'})...")
    result = analyze_evidence(dockerfile, logs, settings=settings)

    if result["status"] != "completed":
        error = result["ai"].get("error") or {}
        print(f"ERROR: analysis failed [{error.get('code')}]: {error.get('message')}")
        return None

    schema = result["ai"].get("schema_validation", {})
    if not schema.get("valid", True):
        print("Raw model reply did not fully match ai/output_schema.json:")
        for error in schema.get("errors", []):
            print(f"  - {error}")

    print(f"Source: {result['ai']['source']}  Model: {result['ai']['model']}")
    return service_result_to_model_output(result)



def strict_quality_issues(actual, expected):
    """Preliminary quality gate; does not verify real-world security."""
    issues = []

    if is_legacy_format(actual):
        issues.append(
            "Legacy output format cannot pass the current strict schema."
        )
        return issues

    missing = validate_output(actual)
    if missing:
        issues.append("Missing required fields: " + ", ".join(missing))

    for error in schema_errors(actual):
        issues.append("Schema violation: " + error)

    _, missed = evaluate_findings(actual, expected)
    for finding in missed:
        issues.append(
            "Expected finding missing: " + finding["title"]
        )

    for issue in evaluate_patch(actual.get("patch")):
        issues.append("Patch check failed: " + issue)

    for issue in check_unsupported_claims(actual):
        issues.append("Unsupported claim: " + issue)

    return issues


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate AI security analysis output.")
    parser.add_argument(
        "output_file", nargs="?", default=str(DEFAULT_OUTPUT_FILE),
        help="saved model output JSON (default: test_cases/model_output.json)"
    )
    parser.add_argument(
        "--run", choices=["mock", "live"],
        help="run the analysis pipeline on test_cases/ and evaluate its output "
             "instead of reading a saved file (live uses the Nebius API)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a nonzero exit code when preliminary quality checks fail",
    )
    args = parser.parse_args()

    if not EXPECTED_FILE.exists():
        print("ERROR: expected_findings.json not found.")
        return 1

    expected = load_json(EXPECTED_FILE)

    if args.run:
        actual = run_pipeline(args.run)
        if actual is None:
            return 1
    else:
        output_file = Path(args.output_file)

        if not output_file.exists():
            print("Nemotron output file not found yet.")
            print(f"Expected path: {output_file}")
            print("Save the model response as model_output.json.")
            return 1

        try:
            actual = load_json(output_file)

        except (json.JSONDecodeError, OSError) as error:
            print(f"ERROR reading JSON: {error}")
            return 1

    if not isinstance(actual, dict):
        print("ERROR: Model output must be a JSON object.")
        return 1

    print("\n===== CYBER DEFENSE AI EVALUATION =====\n")

    # Check output structure
    missing_fields = validate_output(actual)

    if missing_fields:
        print("Missing output fields:")
        for field in missing_fields:
            print(f"  - {field}")
    else:
        print("[PASS] Required output fields are present.")

    # Current-format outputs must also match ai/output_schema.json.
    if not is_legacy_format(actual):
        errors = schema_errors(actual)
        if errors:
            print("Output schema issues (ai/output_schema.json):")
            for error in errors:
                print(f"  - {error}")
        else:
            print("[PASS] Output matches ai/output_schema.json.")

    # Evaluate security findings
    detected, missed = evaluate_findings(actual, expected)

    total = len(expected.get("expected_findings", []))
    score = len(detected) / total * 100 if total else 0

    print("\n--- SECURITY FINDINGS ---")

    for finding in detected:
        print(f"[DETECTED] {finding['title']}")

    for finding in missed:
        print(f"[MISSED]   {finding['title']}")

    print(f"\nPreliminary detection coverage: {score:.1f}%")
    print(f"Detected: {len(detected)} / {total}")

    # Evaluate generated patch
    print("\n--- PATCH CHECKS ---")

    patch_issues = evaluate_patch(actual.get("patch"))

    if patch_issues:
        for issue in patch_issues:
            print(f"[CHECK] {issue}")
    else:
        print("[PASS] Basic patch checks passed.")

    print("\nNote: These are static checks only.")
    print("A successful Docker build and runtime test")
    print("are still required to verify the patch.")
    print("\n--- UNSUPPORTED CLAIMS CHECK ---")

    claim_issues = check_unsupported_claims(actual)

    if claim_issues:
        for issue in claim_issues:
            print(f"[WARNING] {issue}")
    else:
        print("[PASS] No predefined unsupported claims detected.")
    evaluate_attack_correlation(actual)
    evaluate_vulnerability_correlation(actual)
    evaluate_terraform()
    print("\n===== EVALUATION COMPLETE =====")

    if args.strict:
        issues = strict_quality_issues(actual, expected)
        if issues:
            print("\n[STRICT] FAILED:")
            for issue in issues:
                print(f"  - {issue}")
            return 1
        print("\n[STRICT] PASSED: preliminary quality checks")

    return 0


if __name__ == "__main__":
    sys.exit(main())