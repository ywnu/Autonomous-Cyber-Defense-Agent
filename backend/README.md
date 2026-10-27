# Backend — SafeHeal-Cloud

**Owner:** Backend Developer  
**Branch:** `feature/backend`  
**Integration/test branch:** `test/backend-ai-integration`

## Completed work

The backend is implemented with **FastAPI** and connects the security scenario, AI analysis service, static validation, and simulated defensive response.

- Implemented `GET /api/health` for a basic service health check.
- Implemented `POST /api/analyze` to accept a Dockerfile and optional JSON attack logs as multipart uploads.
- Added validation for the Dockerfile filename, UTF-8 content, empty uploads, JSON structure, and a **1 MB per-file limit**.
- Integrated `ai.service.analyze_evidence()` using `run_in_threadpool` so the blocking AI call does not block the async request loop.
- Added independent static checks for the uploaded Dockerfile and proposed patched Dockerfile via `backend/validator.py`.
- Added simulated defensive response actions via `backend/simulation.py`. **No real firewall rules or IP blocks are applied.**
- Kept patch checks separate from AI-generated claims: the backend performs its own review and reports `tests.proposed_patch`.
- Integrated and tested the backend with the AI Integration implementation on a dedicated test branch without modifying the team's `main` branch.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Returns `{"status":"ok"}`. |
| `POST` | `/api/analyze` | Analyzes the uploaded Dockerfile and optional attack logs. |
| `GET` | `/api/attack-events` | Returns the demo attack logs from `security/attack_logs.json` (`mode: "simulation"`). |

### `POST /api/analyze` request

Send `multipart/form-data` with:

- `dockerfile` (**required**): an uploaded file whose filename must be exactly `Dockerfile`.
- `attack_logs` (**optional**): a `.json` file containing a JSON object or array.

Example (PowerShell):

```powershell
curl.exe -sS -X POST "http://127.0.0.1:8000/api/analyze" `
  -F "dockerfile=@security/vulnerable.Dockerfile;filename=Dockerfile" `
  -F "attack_logs=@security/attack_logs.json;type=application/json"
```

The response includes `status`, `findings`, `correlations`, `patch`, `tests`, `response`, and `ai` metadata. The `ai.source` field shows the configured mode (`nebius` or `mock`); it is `nebius` even when the live call failed, so a genuine model answer is `status: "completed"` with `ai.source: "nebius"`. The `patch.diff` field is computed locally rather than trusted from the model.

## Validation and safety boundaries

- The original Dockerfile is statically checked by the backend.
- A proposed patched Dockerfile is independently statically reviewed, with results under `tests.proposed_patch` and `status: "static_review_only"`.
- **Passing static review does not prove that the Docker image builds, runs, or is secure in production.**
- Defensive actions are **simulated only**. The project does not actually isolate a server or block an attacker.
- AI/network errors are surfaced as structured results rather than silently replaced with mock output.

## Verified tests and integration

- The backend test suite passed **25/25** tests in the earlier integration review.
- After syncing the latest AI fixes and `.gitignore`, the combined test command passed **158 tests, with 1 skipped and 0 failures**:

  ```powershell
  py -m pytest backend ai/tests -q
  ```

- A real end-to-end **backend-to-Nebius** request returned HTTP **200**, `status: "completed"`, and `ai.source: "nebius"`, with **3 findings**, **2 correlations**, and **2 simulated actions** in the observed run.
- In a subsequent live run, the proposed Dockerfile patch passed the backend's **static-only** review (`tests.proposed_patch.passed: true`). Model outputs may vary across runs.

These checks use **sample Dockerfiles and mock attack logs** as inputs, even when the AI model itself is real. A full frontend-to-backend-to-Nebius test and production deployment/security validation are **not** claimed as complete.

## Run and test

From the repository root, install the project's dependencies and configure AI settings as described in `ai/README.md`, then start the FastAPI app:

```powershell
py -m uvicorn backend.main:app --reload
```

Run the tests with `AI_MODE=mock` (see the root `README.md`): some tests in `test_main.py` call `/api/analyze` without faking the AI, so a `.env` set to `live` would make real Nebius calls.

Run backend tests:

```powershell
py -m pytest backend -q
```

Run combined backend and AI tests:

```powershell
py -m pytest backend ai/tests -q
```

## Remaining integration work

- Coordinate with the Frontend Developer to connect the UI to `POST /api/analyze`.
- Review and test any new Security or Prompt & Reasoning updates before final integration.
- Repeat the complete team-level end-to-end test after all components are ready.
- Merge to `main` only after team review and approval.
