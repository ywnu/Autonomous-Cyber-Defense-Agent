import json

from fastapi import FastAPI, UploadFile, File, HTTPException
from starlette.concurrency import run_in_threadpool
from backend.simulation import simulate_response
from backend.validator import validate_dockerfile
from ai.service import analyze_evidence
from backend.attack_monitor import router as attack_monitor_router

app = FastAPI(
    title="Autonomous Cyber Defense Agent",
    version="0.1.0"
)

app.include_router(attack_monitor_router)

MAX_FILE_SIZE = 1024 * 1024  # 1 MB


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(
    dockerfile: UploadFile = File(...),
    attack_logs: UploadFile | None = File(None)
):

    # 1. Validate Dockerfile filename
    if dockerfile.filename != "Dockerfile":
        raise HTTPException(
            status_code=400,
            detail="File must be named Dockerfile"
        )

    # 2. Read Dockerfile with size limit
    docker_content = await dockerfile.read(MAX_FILE_SIZE + 1)

    if len(docker_content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Dockerfile exceeds 1 MB limit"
        )

    if not docker_content.strip():
        raise HTTPException(
            status_code=400,
            detail="Dockerfile is empty"
        )

    # 3. Validate text encoding
    try:
        docker_text = docker_content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Dockerfile must be UTF-8 text"
        )

    # 4. Validate optional JSON attack logs
    logs = None

    if attack_logs is not None:

        if not attack_logs.filename.lower().endswith(".json"):
            raise HTTPException(
                status_code=400,
                detail="Attack logs must be a JSON file"
            )

        logs_content = await attack_logs.read(MAX_FILE_SIZE + 1)

        if len(logs_content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Attack logs exceed 1 MB limit"
            )

        try:
            logs = json.loads(logs_content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON attack logs"
            )

        if not isinstance(logs, (dict, list)):
            raise HTTPException(
                status_code=400,
                detail="Attack logs must contain an object or array"
            )

    # 5. Analyze evidence without blocking the async request loop.
    # The AI service returns ai_error metadata instead of silently using mock.
    result = await run_in_threadpool(analyze_evidence, docker_text, logs)

    # 6. Validate the uploaded Dockerfile independently of AI.
    original_review = validate_dockerfile(docker_text)
    result["tests"] = {
        "status": "completed",
        "passed": original_review["passed"],
        "details": original_review["details"],
    }

    # 7. A proposed patch is only statically reviewed, never executed.
    proposed = result.get("patch", {}).get("patched_dockerfile", "")
    if isinstance(proposed, str) and proposed.strip():
        patch_review = validate_dockerfile(proposed)
        result["tests"]["proposed_patch"] = {
            "status": "static_review_only",
            "passed": patch_review["passed"],
            "details": patch_review["details"],
        }
        # A passing text review is not a Docker build/runtime validation.
        if not patch_review["passed"] and result.get("ai", {}).get("patch_status") == "proposed_not_validated":
            result["ai"]["patch_status"] = "proposed_failed_static_review"
            result["ai"].setdefault("warnings", []).append(
                "Backend static review found issues in the proposed Dockerfile."
            )

    # 8. Only the backend owns simulated response actions.
    result["response"] = simulate_response(logs)
    return result
