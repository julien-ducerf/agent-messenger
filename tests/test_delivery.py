import asyncio
import base64
import hmac
import json

from cryptography.fernet import Fernet
from test_domain import agent_c, send

from agent_messenger.delivery import Destination, Dispatcher
from agent_messenger.webhooks import CallbackResponse

KEY = b"test-receiver-signature-key-32!!"


class Receiver:
    """Model the signature and deduplication contract without external calls."""

    def __init__(self, *statuses, key=KEY):
        self.statuses = list(statuses)
        self.key = key
        self.calls = []
        self.accepted = set()

    async def __call__(self, url, body, headers, *, verification=False):
        notification = headers["webhook-id"]
        signing_input = (
            notification + "." + headers["webhook-timestamp"] + "."
        ).encode() + body
        expected = (
            "v1,"
            + base64.b64encode(hmac.digest(self.key, signing_input, "sha256")).decode()
        )
        self.calls.append((notification, json.loads(body), headers))
        if not hmac.compare_digest(headers["webhook-signature"], expected):
            return CallbackResponse(401)
        status = self.statuses.pop(0) if self.statuses else 200
        if 200 <= status < 300:
            self.accepted.add(notification)
        return CallbackResponse(status, body if verification else b"")


def dispatcher(mailbox, receiver, **options):
    return Dispatcher(
        mailbox,
        {"agent_c": Destination("https://agent_c.example/wake", KEY)},
        Fernet(Fernet.generate_key()),
        receiver,
        **options,
    )


def due(mailbox):
    with mailbox.storage.connection() as db:
        return db.execute("SELECT min(due_at) FROM outbox").fetchone()[0]


def test_ac08_ac09_ac18_restart_and_retry(mailbox):
    now = [2_000_000]
    mailbox.clock = lambda: now[0]
    send(mailbox, text="unique private payload")
    first = Receiver(503)
    assert asyncio.run(dispatcher(mailbox, first).run_once())
    now[0] = due(mailbox) + 1000
    second = Receiver()
    assert asyncio.run(dispatcher(mailbox, second).run_once())
    first_id, first_payload, first_headers = first.calls[0]
    new_id, new_payload, new_headers = second.calls[0]
    assert first_id == new_id
    assert first_payload == new_payload
    assert first_headers["webhook-timestamp"] != new_headers["webhook-timestamp"]
    assert first_headers["webhook-signature"] != new_headers["webhook-signature"]
    assert "unique private payload" not in json.dumps(new_payload)
    assert new_payload["scope"] == {"kind": "addresses", "addresses": [agent_c]}


def test_ac10_ac11_coalescence_recovery_and_ack(mailbox):
    now = [2_000_000]
    mailbox.clock = lambda: now[0]
    send(mailbox)
    send(mailbox, "two")
    receiver = Receiver()
    delivery = dispatcher(mailbox, receiver)
    assert asyncio.run(delivery.run_once())
    assert not asyncio.run(delivery.run_once())
    assert len(receiver.accepted) == 1
    assert mailbox.get_reception("agent_c", agent_c)["last_wake_accepted"]
    assert mailbox.get_reception("agent_c", agent_c)["handled_through_event_seq"] == 0
    now[0] = due(mailbox)
    assert asyncio.run(delivery.run_once())
    assert len(receiver.accepted) == 2
    snapshot = mailbox.check_messages("agent_c", agent_c)
    feed = mailbox.check_messages("agent_c", agent_c, snapshot["next_cursor"])
    assert len(feed["events"]) == 2
    mailbox.check_messages("agent_c", agent_c, feed["next_cursor"])
    now[0] = due(mailbox)
    assert not asyncio.run(delivery.run_once())
    assert len(receiver.calls) == 2


def test_agent_b_bearer_gate_and_signature(mailbox):
    class agent_bReceiver(Receiver):
        async def __call__(self, url, body, headers, **kwargs):
            if headers.get("Authorization") != "Bearer simulated-agent_b":
                return CallbackResponse(403)
            return await super().__call__(url, body, headers, **kwargs)

    mailbox.send("agent_c", agent_c, "private", "agent_b", to_addresses=["assistant-b@example.test"])
    receiver = agent_bReceiver()
    delivery = Dispatcher(
        mailbox,
        {"agent_b": Destination("https://agent_b.example/wake", KEY, "simulated-agent_b")},
        Fernet(Fernet.generate_key()),
        receiver,
    )
    assert asyncio.run(delivery.run_once())
    assert receiver.calls[0][1]["addresses"][0]["address"] == "assistant-b@example.test"
    assert len(receiver.accepted) == 1


def test_ac08_real_process_exit_after_commit(mailbox):
    import subprocess
    import sys

    child = """
import os
import sys
from pathlib import Path
from agent_messenger.domain import Messenger
from agent_messenger.storage import Storage

domain = Messenger(Storage(Path(sys.argv[1])), b"x" * 32, "https://local.example/mcp")
domain.send("agent_b", "assistant-b@example.test", "committed", "crash", to_addresses=["assistant-c@example.test"])
os._exit(21)
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(mailbox.storage.path)],
        check=False,
        timeout=10,
    )
    assert result.returncode == 21
    receiver = Receiver()
    assert asyncio.run(dispatcher(mailbox, receiver).run_once())
    assert len(receiver.accepted) == 1
    assert send(mailbox, "crash", text="committed")["seq"] == 1


def test_coalesced_wake_stays_live_until_last_message_expires(mailbox):
    from agent_messenger.domain import TTL

    origin = 2_000_000
    now = [origin]
    mailbox.clock = lambda: now[0]
    send(mailbox)
    now[0] += 2000
    send(mailbox, "second")
    second_expiry = now[0] + TTL
    now[0] = origin + TTL - 1
    delivery = dispatcher(mailbox, Receiver())
    group, destination = delivery.prepare("agent_c")
    assert destination is not None
    assert group["expires_at"] == second_expiry
