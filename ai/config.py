"""
Settings for the AI integration, read from environment variables.

A local `.env` file at the repository root is loaded if present.
Real environment variables always win over `.env` values.
Secret values are never printed or logged by this module.
"""

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1"
VALID_MODES = ("mock", "live")
VALID_JSON_MODES = ("json_object", "none")


def load_dotenv(path: Path = REPO_ROOT / ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines). Does not override existing env vars."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, "") or default)
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, "") or default)
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class Settings:
    mode: str
    api_key: str
    base_url: str
    model: str
    timeout_seconds: float
    max_retries: int
    max_output_tokens: int
    json_mode: str

    def __repr__(self) -> str:  # never leak the key
        return (
            f"Settings(mode={self.mode!r}, base_url={self.base_url!r}, "
            f"model={self.model!r}, api_key_set={bool(self.api_key)})"
        )

    __str__ = __repr__


def get_settings() -> Settings:
    load_dotenv()
    mode = (os.getenv("AI_MODE") or "mock").strip().lower()
    if mode not in VALID_MODES:
        mode = "mock"
    json_mode = (os.getenv("NEBIUS_JSON_MODE") or "json_object").strip().lower()
    if json_mode not in VALID_JSON_MODES:
        json_mode = "json_object"
    return Settings(
        mode=mode,
        api_key=(os.getenv("NEBIUS_API_KEY") or "").strip(),
        base_url=(os.getenv("NEBIUS_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/"),
        model=(os.getenv("NEBIUS_MODEL") or "").strip(),
        timeout_seconds=_float_env("NEBIUS_TIMEOUT_SECONDS", 60.0, 5.0, 300.0),
        max_retries=_int_env("NEBIUS_MAX_RETRIES", 2, 0, 5),
        max_output_tokens=_int_env("NEBIUS_MAX_OUTPUT_TOKENS", 4096, 256, 32768),
        json_mode=json_mode,
    )
