"""
Minimal client for the Nebius Token Factory API (OpenAI-compatible).

Docs: https://docs.tokenfactory.nebius.com/
  - Base URL:  https://api.tokenfactory.nebius.com/v1
  - Auth:      Authorization: Bearer <NEBIUS_API_KEY>
  - Chat:      POST /chat/completions
  - Models:    GET  /models
  - JSON mode: response_format={"type": "json_object"} (support varies by model)

Standard library only. The API key is never included in errors or logs.
"""

import json
import random
import socket
import time
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ai.config import Settings, get_settings
from ai.response_parser import parse_model_response

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_BACKOFF_SECONDS = 20.0


class AIIntegrationError(Exception):
    """Raised for any AI integration failure. `code` is a stable, machine-readable label."""

    def __init__(self, code: str, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.status = status


def _error_for_status(status: int) -> AIIntegrationError:
    if status in (401, 403):
        return AIIntegrationError(
            "auth_error",
            f"Nebius rejected the API key (HTTP {status}). Check NEBIUS_API_KEY.",
            status,
        )
    if status == 404:
        return AIIntegrationError(
            "not_found",
            "Nebius returned HTTP 404. Check NEBIUS_BASE_URL and NEBIUS_MODEL.",
            status,
        )
    if status == 429:
        return AIIntegrationError("rate_limited", "Nebius rate limit or quota reached (HTTP 429).", status)
    if status >= 500:
        return AIIntegrationError("server_error", f"Nebius server error (HTTP {status}).", status)
    return AIIntegrationError("bad_request", f"Nebius rejected the request (HTTP {status}).", status)


class NebiusClient:
    def __init__(self, settings: Optional[Settings] = None, sleep=time.sleep):
        self.settings = settings or get_settings()
        self._sleep = sleep  # injectable for tests

    # ---- low-level HTTP -------------------------------------------------

    def _require_key(self) -> None:
        if not self.settings.api_key:
            raise AIIntegrationError("config_error", "NEBIUS_API_KEY is not configured.")

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> dict:
        self._require_key()
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"

        attempts = self.settings.max_retries + 1
        last_error: Optional[AIIntegrationError] = None

        for attempt in range(attempts):
            request = Request(
                f"{self.settings.base_url}{path}", data=data, headers=headers, method=method
            )
            retry_after: Optional[float] = None
            try:
                with urlopen(request, timeout=self.settings.timeout_seconds) as response:
                    body = response.read().decode("utf-8", errors="replace")
                try:
                    result = json.loads(body)
                except json.JSONDecodeError:
                    raise AIIntegrationError(
                        "invalid_response", "Nebius returned a non-JSON HTTP body."
                    ) from None
                if not isinstance(result, dict):
                    raise AIIntegrationError("invalid_response", "Nebius returned an unexpected body.")
                return result

            except HTTPError as exc:
                last_error = _error_for_status(exc.code)
                if exc.code not in RETRYABLE_STATUS:
                    raise last_error from None
                header = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    retry_after = float(header) if header else None
                except ValueError:
                    retry_after = None
            except (TimeoutError, socket.timeout):
                last_error = AIIntegrationError("timeout", "Nebius API request timed out.")
            except URLError as exc:
                if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
                    last_error = AIIntegrationError("timeout", "Nebius API request timed out.")
                else:
                    last_error = AIIntegrationError("network_error", "Could not connect to Nebius API.")
            except (ConnectionError, OSError):
                last_error = AIIntegrationError("network_error", "Network error while calling Nebius API.")

            if attempt < attempts - 1:
                delay = retry_after if retry_after is not None else (2 ** attempt) + random.uniform(0, 0.5)
                self._sleep(min(delay, MAX_BACKOFF_SECONDS))

        assert last_error is not None
        raise last_error

    # ---- public API -----------------------------------------------------

    def list_models(self) -> list[str]:
        """Return model IDs available to this key. Does not consume tokens."""
        result = self._request("GET", "/models")
        items = result.get("data")
        if not isinstance(items, list):
            raise AIIntegrationError("invalid_response", "Unexpected /models response.")
        return sorted(str(m.get("id")) for m in items if isinstance(m, dict) and m.get("id"))

    def chat(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """
        Send one chat request and return {"content": str, "model": str, "usage": dict}.
        Falls back once to plain mode if the model rejects JSON mode (HTTP 400).
        """
        if not self.settings.model:
            raise AIIntegrationError("config_error", "NEBIUS_MODEL is not configured.")
        if not user_prompt or not user_prompt.strip():
            raise AIIntegrationError("bad_request", "Prompt cannot be empty.")

        payload: dict[str, Any] = {
            "model": self.settings.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": self.settings.max_output_tokens,
        }
        if self.settings.json_mode == "json_object":
            payload["response_format"] = {"type": "json_object"}

        try:
            result = self._request("POST", "/chat/completions", payload)
        except AIIntegrationError as exc:
            if exc.code == "bad_request" and "response_format" in payload:
                payload.pop("response_format")
                result = self._request("POST", "/chat/completions", payload)
            else:
                raise

        try:
            choice = result["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise AIIntegrationError(
                "invalid_response", "Nebius returned an unexpected response structure."
            ) from None

        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            if choice.get("finish_reason") == "length":
                raise AIIntegrationError(
                    "invalid_response",
                    "Model output was cut off (max tokens). Increase NEBIUS_MAX_OUTPUT_TOKENS.",
                )
            refusal = message.get("refusal") if isinstance(message, dict) else None
            raise AIIntegrationError(
                "invalid_response",
                "Model refused the request." if refusal else "Model returned empty content.",
            )

        return {
            "content": content,
            "model": str(result.get("model") or self.settings.model),
            "usage": result.get("usage") if isinstance(result.get("usage"), dict) else {},
            "finish_reason": choice.get("finish_reason"),
        }


def analyze_with_nebius(prompt: str) -> dict:
    """
    Backward-compatible helper: send a ready-made prompt and return the
    validated AI portion of the response. Prefer `ai.service.analyze_evidence`.
    """
    from ai.prompts import SYSTEM_PROMPT

    reply = NebiusClient().chat(SYSTEM_PROMPT, prompt)
    try:
        return parse_model_response(reply["content"])
    except ValueError as exc:
        raise AIIntegrationError("invalid_response", str(exc)) from None
