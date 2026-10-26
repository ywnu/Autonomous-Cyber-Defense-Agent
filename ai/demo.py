"""
Run an analysis on the sample (harmless) inputs and print the JSON result.

    python -m ai.demo                       # uses AI_MODE from .env (default: mock)
    python -m ai.demo --mode mock
    python -m ai.demo --mode live           # real Nebius call, uses credits
    python -m ai.demo --dockerfile path/to/Dockerfile --logs path/to/logs.json

    # Security Engineer's scenario, read from another branch without checking it out:
    python -m ai.demo --mode mock --git-ref origin/feature/security \
        --dockerfile security/vulnerable.Dockerfile --logs security/attack_logs.json

Files are only read as text (via `git show` when --git-ref is set). Nothing is executed.
"""

import argparse
import dataclasses
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

from ai.config import get_settings
from ai.response_parser import to_json
from ai.service import analyze_evidence

SAMPLES = Path(__file__).resolve().parent / "samples"


def read_input(path: str, git_ref: Optional[str] = None) -> str:
    """Read a file from disk, or read-only from a git ref (`git show REF:PATH`)."""
    if not git_ref:
        return Path(path).read_text(encoding="utf-8")
    spec = f"{git_ref}:{Path(path).as_posix()}"
    try:
        out = subprocess.run(["git", "show", spec], cwd=REPO_ROOT, capture_output=True, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"Could not read {spec}: {exc.stderr.decode(errors='replace').strip()}")
    return out.stdout.decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["mock", "live"])
    parser.add_argument("--dockerfile", default=str(SAMPLES / "Dockerfile.insecure"))
    parser.add_argument("--logs", default=str(SAMPLES / "suspicious_logins.json"))
    parser.add_argument("--no-logs", action="store_true")
    parser.add_argument("--git-ref", help="read --dockerfile/--logs (repo-relative paths) from this git ref")
    args = parser.parse_args()

    settings = get_settings()
    if args.mode:
        settings = dataclasses.replace(settings, mode=args.mode)

    dockerfile_text = read_input(args.dockerfile, args.git_ref)
    logs = None if args.no_logs else json.loads(read_input(args.logs, args.git_ref))

    result = analyze_evidence(dockerfile_text, logs, settings=settings)
    print(to_json(result))
    print(f"\n# source={result['ai']['source']} model={result['ai']['model']} status={result['status']}",
          file=sys.stderr)
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
