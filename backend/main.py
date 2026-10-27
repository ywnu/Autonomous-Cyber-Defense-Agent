import json

from fastapi import FastAPI, UploadFile, File, HTTPException

from backend.simulation import simulate_response
from backend.validator import validate_dockerfile
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

    if dockerfile.filename != "Dockerfile":
        raise HTTPException(
            status_code=400,
            detail="File must be named Dockerfile"
        )

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

    try:
        docker_text = docker_content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Dockerfile must be UTF-8 text"
        )

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

    simulation_result = simulate_response(logs)

    validation_result = validate_dockerfile(docker_text)

    return {
        "status": "completed",
        "findings": [],
        "correlations": [],
        "patch": {
            "patched_dockerfile": "",
            "diff": ""
        },
        "tests": {
            "status": "completed",
            "passed": validation_result["passed"],
            "details": validation_result["details"]
        },
        "response": simulation_result
    }