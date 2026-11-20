import asyncio
import socket
from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from agent_messenger import webhooks
from agent_messenger.app import build_app


@pytest.mark.parametrize(
    "url",
    [
        "http://receiver.example/hook",
        "https://localhost/hook",
        "https://service.local/callback",
        "https://receiver.example:444/endpoint",
        "https://user@receiver.example/hook",
        "https://receiver.example/hook#fragment",
    ],
)
def test_ac15_unsafe_urls(url):
    with pytest.raises(webhooks.CallbackError, match="unsafe_url"):
        webhooks.validate_url(url)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.5.0.1", "169.254.1.1", "::1", "224.0.0.1", "100.64.0.1"],
)
def test_ac15_private_dns_cannot_connect(monkeypatch, address):
    async def exercise():
        async def getaddrinfo(*args, **kwargs):
            return [
                (socket.AF_INET, 0, 0, "", ("93.184.216.34", 443)),
                (socket.AF_INET, 0, 0, "", (address, 443)),
            ]

        async def must_not_connect(*args, **kwargs):
            pytest.fail("Dialed a mixed public/private DNS result")

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(asyncio, "open_connection", must_not_connect)
        with pytest.raises(webhooks.CallbackError, match="unsafe_address"):
            await webhooks.post_callback(
                "https://callback.example/hook", b"{}", {}, verification=True
            )

    asyncio.run(exercise())


def test_ac15_tls_keeps_hostname_and_blocks_redirect(monkeypatch):
    async def exercise():
        async def getaddrinfo(*args, **kwargs):
            return [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 443))]

        class Writer:
            def write(self, data):
                assert b"Host: callback.example" in data

            async def drain(self):
                pass

            def close(self):
                pass

        async def connect(address, port, **kwargs):
            assert address == "93.184.216.34"
            assert kwargs["flags"] == socket.AI_NUMERICHOST
            assert kwargs["server_hostname"] == "callback.example"
            assert kwargs["ssl"].check_hostname
            reader = asyncio.StreamReader()
            reader.feed_data(
                b"HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 0\r\n\r\n"
            )
            reader.feed_eof()
            return reader, Writer()

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(asyncio, "open_connection", connect)
        with pytest.raises(webhooks.CallbackError, match="redirect_blocked"):
            await webhooks.post_callback(
                "https://callback.example/hook", b"{}", {}, verification=True
            )

    asyncio.run(exercise())


def test_rates_are_per_principal(config, rpc):
    config = replace(config, send_limit=1, tools_limit=2)
    with TestClient(
        build_app(config, background=False),
        client=("127.0.0.1", 9),
        base_url="http://localhost",
    ) as client:
        send = {
            "name": "send",
            "arguments": {
                "as_address": "assistant-b@example.test",
                "text": "hello",
                "to_addresses": ["assistant-a@example.test"],
                "idempotency_key": "once",
            },
        }
        assert (
            rpc(client, "agent_b", "tools/call", send)["result"]["structuredContent"][
                "status"
            ]
            == "sent"
        )
        second = rpc(client, "agent_b", "tools/call", send)["result"]
        assert second["isError"] and second["structuredContent"]["retry_after"] > 0
        assert rpc(client, "agent_b", "tools/call", {"name": "get_account"})["result"][
            "isError"
        ]
        assert not rpc(client, "agent_a", "tools/call", {"name": "get_account"})[
            "result"
        ]["isError"]


def test_ac28_sensitive_content_absent_from_logs_wake_and_backup_scope(
    client, rpc, receiver, caplog
):
    import logging
    from pathlib import Path

    from test_events import run_once, subscription

    caplog.set_level(logging.INFO)
    params = subscription()
    assert rpc(client, "agent_a", "events/subscribe", params)["result"]["id"]
    secret = params["delivery"]["secret"]
    callback = params["delivery"]["url"]
    text = "AC28_private_marker_17589"
    subject = "AC28_private_subject_17589"
    args = {
        "as_address": "assistant-b@example.test",
        "to_addresses": ["assistant-a@example.test"],
        "text": text,
        "subject": subject,
        "idempotency_key": "privacy",
    }
    assert rpc(client, "agent_b", "tools/call", {"name": "send", "arguments": args})[
        "result"
    ]["structuredContent"]
    assert run_once(client)
    assert "delivery agent=agent_a" in caplog.text
    assert not any(value in caplog.text for value in (text, subject, secret, callback))
    assert not any(
        value in str(receiver.calls) for value in (text, subject, secret, callback)
    )
    project = Path(__file__).resolve().parents[1]
    assert (
        "/var/lib/agent-messenger"
        in (project / "deploy" / "restic.exclude.example").read_text().splitlines()
    )
    assert "LimitCORE=0" in (project / "deploy" / "agent-messenger.service").read_text()
    with client.app.state.mailbox.storage.connection() as db:
        assert "body" not in {
            row["name"] for row in db.execute("PRAGMA table_info(outbox)")
        }
