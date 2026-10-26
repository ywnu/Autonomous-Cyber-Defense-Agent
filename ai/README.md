# AI

Owners: AI Reasoning (`feature/ai-reasoning`) and AI Integration (`feature/ai-integration`). Keep prompts, schemas, evaluation, and Nebius integration here. Never commit API keys.

## What's here

| File | Purpose |
|---|---|
| `service.py` | **Backend entry point**: `analyze_evidence(dockerfile_text, attack_logs)` |
| `nebius_client.py` | Nebius Token Factory HTTP client (timeouts, bounded retries, error codes) |
| `prompts.py` | System prompt + user prompt builder (inputs treated as untrusted data) |
| `response_parser.py` | Validates/normalizes model JSON (model output is untrusted) |
| `mock.py` | Offline rule-based mock, so no credits are used during development |
| `config.py` | Reads env vars / `.env` (key is never printed) |
| `check_connection.py` | Verifies key + lists available Nemotron models |
| `demo.py` | Runs an analysis on the harmless samples in `samples/` |
| `tests/` | Unit tests (network is faked) + one opt-in live test |

Standard library only, so there are no runtime dependencies. Tests need `pytest`.

## Setup

1. Copy `.env.example` to `.env` at the repo root (already git-ignored) and fill in:
   ```
   NEBIUS_API_KEY=<your key>
   NEBIUS_MODEL=<model id from step 2>
   AI_MODE=mock        # switch to "live" for real requests
   ```
2. List the models your key can use (free, no tokens):
   ```
   python -m ai.check_connection
   ```
   Copy a Nemotron ID from the output into `NEBIUS_MODEL`.
3. Test one tiny chat request (uses a few tokens):
   ```
   python -m ai.check_connection --chat
   ```

Nebius API facts (from https://docs.tokenfactory.nebius.com/):
base URL `https://api.tokenfactory.nebius.com/v1`, `Authorization: Bearer <key>`,
OpenAI-compatible `POST /chat/completions`, JSON mode via `response_format: {"type": "json_object"}`
(support varies by model; the client retries once without it if the model rejects it).

## Usage / demo

```
python -m ai.demo --mode mock                 # offline
python -m ai.demo --mode live                 # real Nemotron call (uses credits)
python -m ai.demo --mode mock --dockerfile ai/samples/Dockerfile.hardened --no-logs

# Security Engineer's scenario, read-only from the security branch (no checkout needed):
python -m ai.demo --mode mock --git-ref origin/feature/security --dockerfile security/vulnerable.Dockerfile --logs security/attack_logs.json
```

Offline copies of that scenario live in `ai/tests/fixtures/security_scenario/`; a test checks they
still match `origin/feature/security`.

## Tests

```
pip install pytest
python -m pytest ai/tests -q                  # unit tests, no network
RUN_LIVE_TESTS=1 python -m pytest ai/tests -q -k live    # one real API call (bash)
$env:RUN_LIVE_TESTS="1"; python -m pytest ai/tests -q -k live   # same, PowerShell
```

## Backend contract

```python
from starlette.concurrency import run_in_threadpool
from ai.service import analyze_evidence

result = await run_in_threadpool(analyze_evidence, docker_text, logs)  # never raises
result["tests"] = {"status": "completed", "passed": ..., "details": [...]}  # backend's own validation
result["response"] = simulate_response(logs)                               # backend's simulation
return result
```

Input: the Dockerfile as UTF-8 text (already size/encoding-validated by the backend), plus the
parsed attack-logs JSON (`dict`/`list`) or `None`.

Output matches `contracts/example_response.json`:

| Field | Owner | Notes |
|---|---|---|
| `status` | AI | `"completed"` or `"ai_error"` |
| `findings[]` | AI | Exactly `id, title, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), description, recommendation` |
| `correlations[]` | AI | Exactly `event_type, source_ip, related_finding_ids[], explanation`. One per (event_type, source_ip). `event_type`/`source_ip` are copied from the logs or `null`, never invented: model values not found in the logs are set to `null` with a warning. Empty when there are no logs |
| `patch` | AI | Exactly `patched_dockerfile` (proposal only, never executed), `diff` (computed locally), `summary` (what the patch changes; `""` when there is no patch) |
| `tests` | **Backend** | AI always returns `not_run`. Backend should run `validate_dockerfile` on the original **and** on `patch.patched_dockerfile` |
| `response` | **Backend** | AI always returns `{"mode": "simulation", "actions": []}` |
| `ai` (additive) | AI | `source` (`"nebius"` real / `"mock"`), `model`, `summary`, `limitations[]`, `next_steps[]`, `warnings[]`, `finding_evidence {finding_id: quoted line}`, `patch_status`, `patch_review`, `error {code, message}`, `usage` |

The parser still accepts the pre-agreement names `issue` (→ `title`) and `finding_ids` (→ `related_finding_ids`).
`contracts/example_response.json` (team-owned) shows the agreed `findings`, `correlations` and `patch` fields.
It does not include the additive `ai` key or the `"ai_error"` status.

`patch_status`: `none` (no patch), `proposed_failed_static_review` (static issues found, see
`patch_review.issues`), or `proposed_not_validated` (static checks passed, but nothing was built or run).
`patch_review` (`ai/patch_review.py`) is a **static text check only**: leftover hardcoded secrets,
`USER` accounts never created in the final stage, finding evidence left unchanged, and comments
claiming the file is "fixed"/"verified". Passing it does not mean the patch is secure or works.

Error codes in `ai.error.code`: `config_error`, `auth_error`, `rate_limited`, `timeout`,
`network_error`, `bad_request`, `not_found`, `server_error`, `invalid_response`.
A live failure never silently falls back to mock data.

## Safety rules implemented

- Uploaded files and logs are wrapped in `<untrusted_*>` tags; the model is told to ignore instructions inside them.
- Model output is parsed as data only. Nothing is executed. Fields from the model for `tests`/`response` are discarded.
- Patches are labelled `proposed_not_validated` until the backend validates them.
- The API key is read from env only and never logged, printed, or put in error messages.

## Limitations

- Findings are model opinions with quoted evidence. They are not verified vulnerabilities.
- Mock mode uses simple pattern rules and is clearly labelled `source: "mock"`.
- `analyze_evidence` is blocking; use a thread pool from async routes.
