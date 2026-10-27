# API Contract (draft)

## GET /api/health
Response: `{"status":"ok"}`

## POST /api/analyze
Request: `multipart/form-data` with `dockerfile` (required file) and `attack_logs` (optional JSON file).
Response: JSON matching `contracts/example_response.json`. `findings` and `correlations` are arrays; `patch` contains proposed Dockerfile and diff. `tests` is set by the backend after validation, not fabricated by the AI. `response.actions` contains simulated actions only.

### Status and errors
- `status` is `"completed"` or `"ai_error"`; both return HTTP 200. Invalid uploads return 400/413 before any AI call.
- On `"ai_error"`: `findings` and `correlations` are `[]`, all `patch` fields are `""`, and `ai.error` is `{"code": ..., "message": ...}` (for example `config_error`, `auth_error`, `rate_limited`, `timeout`, `invalid_response`). `tests` and `response` are still filled by the backend. There is no silent fallback to mock output.

### `tests.proposed_patch` (backend)
Present only when a patch was proposed: `{"status": "static_review_only", "passed": ..., "details": [...]}`. A text review only; the patch is never built, run or applied.

### `ai` object (AI metadata)
- Always: `source`, `model`, `summary`, `limitations`, `next_steps`, `warnings`, `finding_evidence` (`{finding_id: evidence}`), `patch_status` (`"none"`, `"proposed_not_validated"` or `"proposed_failed_static_review"`), `error` (`null` on success).
- `source` is the configured mode: `"nebius"` (`AI_MODE=live`) or `"mock"`. It is `"nebius"` even when the live call failed, so a genuine model answer is `status: "completed"` with `source: "nebius"`.
- Only when `status` is `"completed"`: `patch_review` (the AI side's static patch check). `usage` (`prompt_tokens`, `completion_tokens`, `total_tokens`) appears only after a successful live call.
- `"proposed_not_validated"` means the static checks passed but nothing was built or run; it never means the fix works.

**Team agreement required before implementation.** Never execute untrusted AI-generated commands or use real firewall blocking for the demo.
