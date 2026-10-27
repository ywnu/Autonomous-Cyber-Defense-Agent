# SafeHeal-Cloud — Autonomous Cyber Defense Agent (prototype)

SafeHeal-Cloud analyzes a container's configuration together with its security logs, explains which weaknesses the observed attack activity is targeting, and proposes a fix — without ever executing anything the AI suggests.

## The problem

Container misconfigurations (running as root, hardcoded secrets, debug mode left on, unnecessary SSH) are common, and security alerts usually arrive separately from the configuration they relate to. Connecting "this IP is scanning port 22" to "this Dockerfile installs an SSH server" is manual work, and AI tools that answer this kind of question can invent findings or claim fixes that were never tested.

## What it does

`POST /api/analyze` takes a `Dockerfile` and optional attack logs (JSON) and returns one result:

1. **Findings** — security weaknesses in the Dockerfile, with the evidence for each.
2. **Correlations** — which logged events (by event type and source IP) relate to which findings.
3. **Proposed patch** — a corrected Dockerfile and a diff computed locally.
4. **Backend checks** — an independent static review of the original Dockerfile and of the proposed patch.
5. **Simulated response** — defensive actions (e.g. "block IP") that are only simulated, never executed.

`GET /api/attack-events` serves the demo attack logs for display.

## Role of the AI

- The analysis is done by an NVIDIA Nemotron model through the **Nebius Token Factory** API (OpenAI-compatible chat completions). The model is chosen with `NEBIUS_MODEL`; the live test below used `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`.
- The model produces the findings, correlations and proposed patch. Everything else is done by code.
- Model output is treated as untrusted:
  - uploaded files and logs are sent as data inside delimited blocks, and the model is told not to follow instructions found in them;
  - the reply must be one JSON object; it is parsed, validated and normalized, and malformed replies return `status: "ai_error"` instead of a guess;
  - event types and IPs in correlations are kept only if they appear in the uploaded logs;
  - secret values from the Dockerfile and the patch are replaced with `[REDACTED]` in the response;
  - the proposed patch is only statically reviewed (text checks) — it is never built, run or applied;
  - a failed live call is reported as an error; it never silently falls back to mock results.
- `ai.source` is `nebius` or `mock` according to the configured mode. A genuine model answer is `status: "completed"` with `ai.source: "nebius"` and an `ai.usage` token count.

## Repository layout

| Path | Contents |
|---|---|
| `backend/` | FastAPI app (`main.py`), Dockerfile validator, response simulation, attack-event endpoint, tests |
| `ai/` | Nebius client, prompts, response parser, patch review, offline mock, tests — see `ai/README.md` |
| `security/` | Synthetic demo inputs: `vulnerable.Dockerfile`, `attack_logs.json` (dummy secret only) |
| `contracts/` | API contract and example response |

## Requirements

- Python **3.10 or newer** (the code uses `X | None` type syntax).
- Packages: `backend/requirements.txt` (FastAPI, Uvicorn, python-multipart). Tests also need `pytest` and `httpx`.
- A Nebius Token Factory API key and model ID for live mode only. Mock mode needs no key.

## Setup (Windows PowerShell, from the repository root)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt pytest httpx
Copy-Item .env.example .env
```

Then edit `.env` (it is gitignored — never commit it):

- `AI_MODE=mock` runs fully offline with a rule-based mock (no key, no cost).
- For the real model set `AI_MODE=live`, `NEBIUS_API_KEY` and `NEBIUS_MODEL`. `NEBIUS_MAX_OUTPUT_TOKENS` defaults to 16384; do not lower it much — at 4096 the Nemotron reply was cut off and rejected. If a key appears twice in `.env`, the last value is used, and real environment variables override `.env`.

Check the live configuration without printing the key (adding `--chat` sends one small request and uses a few tokens):

```powershell
.\.venv\Scripts\python.exe -m ai.check_connection
```

## Run

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Interactive API docs: <http://127.0.0.1:8000/docs>. Analyze the demo inputs (the upload must be named `Dockerfile`):

```powershell
curl.exe -sS -X POST "http://127.0.0.1:8000/api/analyze" `
  -F "dockerfile=@security/vulnerable.Dockerfile;filename=Dockerfile" `
  -F "attack_logs=@security/attack_logs.json;type=application/json"
```

In live mode each analyze request calls Nebius and uses credits.

## Tests

Run the tests in mock mode. Some backend tests call `/api/analyze` without faking the AI, so with `AI_MODE=live` in `.env` they would make real Nebius calls:

```powershell
$env:AI_MODE = "mock"
.\.venv\Scripts\python.exe -m pytest backend ai/tests -q
Remove-Item Env:AI_MODE
```

Result on this branch: 209 passed, 1 skipped (the opt-in live test, enabled with `RUN_LIVE_TESTS=1`).

## Verified so far

- Offline: the test suite above, and the mock-mode server (health, attack events, analyze).
- Live: one end-to-end request through `POST /api/analyze` to Nebius returned `status: "completed"`, `ai.source: "nebius"`, 4 findings and 3 correlations. The model's proposed patch came back on a single line and did not switch to a non-root user; the backend's static review rejected it. The parser and patch review were then fixed (commit `d980b61`) and covered by offline tests; that fix has not yet been re-run against the live model.

## Limitations of this prototype

- Inputs are synthetic demo files; there is no live log source or cloud integration.
- Patch validation is static text checking only. Passing it does not mean a patch is secure or works: nothing is built or run, and file permissions, base-image vulnerabilities and dependencies are not checked.
- Response actions are simulated only; nothing is blocked.
- Model output varies between runs; findings can be missed or worded differently.
- There is no user interface on this branch (API and Swagger docs only), and no authentication or rate limiting on the API.
