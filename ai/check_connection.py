"""
Check the Nebius setup without printing secrets.

    python -m ai.check_connection          # list models (no tokens used)
    python -m ai.check_connection --chat   # also send one tiny chat request (uses a few tokens)
"""

import argparse
import sys

from ai.config import get_settings
from ai.nebius_client import AIIntegrationError, NebiusClient


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--chat", action="store_true", help="send one tiny chat request")
    args = parser.parse_args()

    settings = get_settings()
    print(f"AI_MODE         : {settings.mode}")
    print(f"NEBIUS_BASE_URL : {settings.base_url}")
    print(f"NEBIUS_API_KEY  : {'set' if settings.api_key else 'NOT SET'}")
    print(f"NEBIUS_MODEL    : {settings.model or 'NOT SET'}")
    if not settings.api_key:
        print("\nAdd NEBIUS_API_KEY to the .env file at the repo root, then rerun.")
        return 1

    client = NebiusClient(settings)
    try:
        models = client.list_models()
    except AIIntegrationError as exc:
        print(f"\nModel list failed [{exc.code}]: {exc}")
        return 1

    nemotron = [m for m in models if "nemotron" in m.lower()]
    print(f"\nConnected. {len(models)} models available. Nemotron models:")
    for model_id in nemotron or ["(none found)"]:
        print(f"  - {model_id}")

    if settings.model and settings.model not in models:
        print(f"\nWARNING: NEBIUS_MODEL '{settings.model}' is not in the model list.")

    if args.chat:
        if not settings.model:
            print("\nSet NEBIUS_MODEL before using --chat.")
            return 1
        try:
            reply = client.chat(
                'Reply with JSON only: {"ok": true}',
                "Connection test. Reply with the JSON object only.",
            )
        except AIIntegrationError as exc:
            print(f"\nChat request failed [{exc.code}]: {exc}")
            return 1
        print(f"\nChat OK. model={reply['model']} usage={reply['usage']}")
        print(f"Reply: {reply['content'][:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
