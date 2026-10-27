# AI Integration — SafeHeal-Cloud

**Owner:** AI API & Integration Specialist (Sara)  
**Feature branch:** `feature/ai-integration`  
**Shared integration/test branch:** `test/backend-ai-integration`

This README documents the **AI API & Integration** work. Prompt design and reasoning rules are a separate team responsibility; their final integration should be verified before release.

## Completed work

- Implemented integration with the **Nebius Token Factory API** to call an available NVIDIA Nemotron model.
- Added environment-based configuration for model, credentials, and mock/live mode; API keys are not committed to the repository.
- Implemented `ai/nebius_client.py` with request handling, timeouts, bounded retries, and structured error reporting.
- Implemented `ai/service.py` as the backend entry point: `analyze_evidence(dockerfile_text, attack_logs)`.
- Implemented JSON response parsing and normalization in `ai/response_parser.py`, treating model output as untrusted data.
- Added grounding of correlations against actual event types and source IPs in the supplied attack logs.
- Added safety checks and secret redaction so secret-like Dockerfile values do not leak in returned strings.
- Added regression tests for response handling, parsing, and secret redaction.
- Maintained offline mock mode for repeatable development and live Nebius mode for real-model integration testing.
- Synced the latest AI fixes to the shared test branch and verified compatibility with the backend.

## Key files

| File | Purpose |
|---|---|
| `service.py` | Backend-facing analysis entry point and response assembly. |
| `nebius_client.py` | Nebius API client and network/error handling. |
| `response_parser.py` | Parses, validates, and normalizes model JSON. |
| `config.py` | Reads AI settings and environment variables. |
| `prompts.py` | Current system prompt and user-prompt builder used by the service. |
| `patch_review.py` | Static review of proposed Dockerfile changes. |
| `mock.py` | Offline mock responses for development and tests. |
| `check_connection.py` | Checks Nebius access and available models. |
| `tests/` | AI unit and regression tests. |

**Important:** `ai/service.py` currently imports `SYSTEM_PROMPT` and `build_user_prompt` from `ai/prompts.py`. Separate Prompt & Reasoning text files are **not automatically loaded**. Confirm with the Prompt & Reasoning Engineer that the final approved prompts are actually used by the live service.

## Configuration

Copy the repository's `.env.example` to `.env` and configure:

```dotenv
NEBIUS_API_KEY=your_api_key_here
NEBIUS_MODEL=your_available_model_id
AI_MODE=mock
```

Set `AI_MODE=live` to use the real Nebius model. Keep `.env` out of version control. Never paste API keys into source code, logs, or documentation.

To check the configured Nebius connection (`--chat` sends one small request and uses a few tokens):

```powershell
py -m ai.check_connection
py -m ai.check_connection --chat
```

To run a mock or live demo (`--mode live` calls Nebius and uses credits):

```powershell
py -m ai.demo --mode mock
py -m ai.demo --mode live
```

## Backend contract

The backend calls:

```python
from starlette.concurrency import run_in_threadpool
from ai.service import analyze_evidence

result = await run_in_threadpool(analyze_evidence, docker_text, logs)
```

The returned object includes:

- `status`: `completed` or `ai_error`.
- `findings`: validated vulnerability findings.
- `correlations`: links between findings and supplied attack-log events.
- `patch`: `patched_dockerfile`, locally computed `diff`, and `summary`.
- `tests`: initially `not_run`; populated by the **backend**, not the AI.
- `response`: simulated response actions populated by the **backend**, not the AI.
- `ai`: source (`nebius` or `mock`), model, warnings, limitations, patch review, and error metadata. `source` reflects the configured mode and is `nebius` even when the live call failed; a genuine model answer is `status: "completed"` with `source: "nebius"`.

The agreed `findings`, `correlations`, and `patch` fields match the current backend integration contract. Model output is never executed as code.

## Verified testing

- Sara reported **133 AI tests passed and 1 skipped** after the AI fixes.
- The shared integration branch subsequently passed **158 tests and 1 skipped**, with **0 failures**, using:

  ```powershell
  py -m pytest backend ai/tests -q
  ```

- A **real Nebius** request through the backend's `/api/analyze` endpoint returned HTTP **200**, `status: "completed"`, and `ai.source: "nebius"`.
- The observed live response included **3 findings** and **2 correlations**. The backend produced **2 simulated actions**.
- A subsequent real-model patch passed the backend's static review; this does **not** mean the patched image was built or executed.

The sample Dockerfile and attack logs used in these tests were **synthetic**. The model invocation was **real**, not a mock. These are different facts and should not be conflated.

## Safety and limitations

- The service treats Dockerfile content and attack logs as untrusted inputs.
- Model responses are parsed and checked rather than blindly trusted.
- Sensitive literal values are redacted from returned results.
- Model-generated findings and patches remain **proposals**, not proof of exploitation or production-ready fixes.
- Proposed patches are only **statically reviewed**; they are not built, run, or deployed.
- Defensive response actions are simulated by the backend.
- A failed live request does not silently fall back to mock results.

## Remaining work

- Verify that the final Prompt & Reasoning files are reflected in the prompts actually sent to Nebius.
- Retest with the team's latest Security scenario and finalized prompts.
- Support final frontend/backend/Nebius end-to-end integration and investigate any regressions.
- Merge only after team approval.
