import json
from pathlib import Path
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api", tags=["Attack Monitor"])

LOGS_PATH = Path(__file__).resolve().parent.parent / "security" / "attack_logs.json"


@router.get("/attack-events")
def get_attack_events():
    if not LOGS_PATH.is_file():
        raise HTTPException(
            status_code=503,
            detail="Demo attack logs are unavailable"
        )

    try:
        with LOGS_PATH.open("r", encoding="utf-8") as file:
            events = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise HTTPException(
            status_code=503,
            detail="Unable to load demo attack logs"
        )

    if not isinstance(events, list):
        raise HTTPException(
            status_code=422,
            detail="Attack logs must be a JSON array"
        )

    return {
        "mode": "simulation",
        "total": len(events),
        "events": events
    }