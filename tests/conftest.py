from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient
from test_delivery import KEY, Receiver

from agent_messenger.app import build_app
from agent_messenger.config import Agent, Config
from agent_messenger.delivery import Destination
from agent_messenger.domain import Messenger
from agent_messenger.storage import Storage

TOKENS = {agent: (agent + "0" * 32) for agent in ("agent_b", "agent_c", "agent_a")}
ADMIN = "test-admin-password" + "0" * 32


@pytest.fixture
def config(tmp_path: Path):
    agents = tuple(
        Agent(
            agent,
            f"assistant-{agent[-1]}@example.test",
            f"Assistant {agent[-1].upper()}",
            "mcp_event" if agent == "agent_a" else "webhook",
            agent,
        )
        for agent in TOKENS
    )
    destinations = {
        name: Destination(f"https://{name}.example/wake", KEY)
        for name in ("agent_b", "agent_c")
    }
    return Config(
        tmp_path / "data" / "messages.sqlite3",
        "https://messenger.example/mcp",
        b"test-cursor-key" * 3,
        Fernet(Fernet.generate_key()),
        agents,
        destinations,
        TOKENS,
        ADMIN,
    )


@pytest.fixture
def receiver():
    return Receiver()


@pytest.fixture
def client(config, receiver):
    app = build_app(config, receiver, background=False)
    with TestClient(
        app, client=("127.0.0.1", 50000), base_url="http://localhost"
    ) as test_client:
        yield test_client


@pytest.fixture
def rpc():
    def call(client, principal, method, params=None, **headers):
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params or {},
            },
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {TOKENS[principal]}",
                **headers,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    return call


@pytest.fixture
def mailbox(tmp_path):
    storage = Storage(tmp_path / "data" / "messages.sqlite3")
    storage.initialize()
    with storage.transaction() as db:
        for agent in ("agent_b", "agent_c", "agent_a"):
            db.execute(
                "INSERT INTO agents VALUES (?,?,?,1,?)",
                (
                    agent,
                    f"assistant-{agent[-1]}@example.test",
                    agent,
                    "mcp_event" if agent == "agent_a" else "webhook",
                ),
            )
            db.execute("INSERT INTO principals VALUES (?,?,1)", (agent, agent))
            if agent != "agent_a":
                db.execute("INSERT INTO destinations VALUES (?,1)", (agent,))
    return Messenger(storage, b"test-cursor-key" * 3, "https://messenger.example/mcp")
