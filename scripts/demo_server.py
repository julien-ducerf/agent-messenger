"""Run the local synthetic demo with an in-process callback simulator."""

import json
from pathlib import Path

import uvicorn

from agent_messenger.app import build_app
from agent_messenger.config import load_config
from agent_messenger.webhooks import CallbackResponse

PROJECT = Path(__file__).resolve().parents[1]
CONFIG = PROJECT / ".local" / "demo" / "config.toml"


class LocalCallbackSimulator:
    async def __call__(self, _url, body, _headers, *, verification=False):
        payload = json.loads(body)
        if verification:
            return CallbackResponse(
                200, json.dumps({"challenge": payload["challenge"]}).encode()
            )
        return CallbackResponse(202)


def main():
    if not CONFIG.is_file():
        raise SystemExit("Demo data is missing; run scripts/create_demo_data.py first.")
    uvicorn.run(
        build_app(load_config(CONFIG), LocalCallbackSimulator()),
        host="127.0.0.1",
        port=8765,
    )


if __name__ == "__main__":
    main()
