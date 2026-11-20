import base64
import json

from starlette.testclient import TestClient
from test_delivery import KEY

from agent_messenger.app import build_app
from agent_messenger.webhooks import CallbackResponse


def subscription(**overrides):
    return {
        "name": "message.created",
        "arguments": {"address": "assistant-a@example.test"},
        "delivery": {
            "mode": "webhook",
            "url": "https://agent_a.example/subscription/path-token",
            "secret": "whsec_" + base64.b64encode(KEY).decode(),
        },
        **overrides,
    }


def incoming(client, rpc):
    return rpc(
        client,
        "agent_b",
        "tools/call",
        {
            "name": "send",
            "arguments": {
                "as_address": "assistant-b@example.test",
                "to_addresses": ["assistant-a@example.test"],
                "text": "private message <script>",
                "subject": "private subject",
                "idempotency_key": "message",
            },
        },
    )["result"]["structuredContent"]


def run_once(client):
    return client.portal.call(client.app.state.dispatcher.run_once)


def test_ac12_refresh_is_stable_and_encrypted(client, rpc, receiver):
    params = subscription()
    result = rpc(client, "agent_a", "events/subscribe", params)["result"]
    assert (
        rpc(client, "agent_a", "events/subscribe", params)["result"]["id"]
        == result["id"]
    )
    assert len(receiver.calls) == 1
    with client.app.state.mailbox.storage.connection() as db:
        rows = db.execute("SELECT * FROM event_subscriptions").fetchall()
        assert len(rows) == 1
        assert rows[0]["active"] == 1
        assert KEY not in rows[0]["encrypted_secret"]
        assert b"path-token" not in rows[0]["encrypted_callback"]
    assert rpc(
        client, "agent_a", "events/subscribe", subscription(cursor="unsupported")
    )["result"]["truncated"]
    params["delivery"]["secret"] = (
        "whsec_" + base64.b64encode(b"replacement-valid-secret" * 2).decode()
    )
    assert rpc(client, "agent_a", "events/subscribe", params)["error"]["code"] == -32015
    assert len(receiver.calls) == 2


def test_ac13_challenge_must_be_echoed(client, rpc):
    async def bad_challenge(*args, **kwargs):
        return CallbackResponse(200, b'{"challenge":"wrong"}')

    client.app.state.dispatcher.transport = bad_challenge
    result = rpc(client, "agent_a", "events/subscribe", subscription())
    assert result["error"]["code"] == -32015
    assert result["error"]["data"]["reason"] == "challenge_failed"
    incoming(client, rpc)
    assert not run_once(client)
    with client.app.state.mailbox.storage.connection() as db:
        assert db.execute("SELECT count(*) FROM event_subscriptions").fetchone()[0] == 0


def test_ac14_wrong_secret_and_unauthorized_network(client, rpc, receiver):
    result = rpc(client, "agent_b", "events/subscribe", subscription())
    assert result["error"]["data"]["code"] == "forbidden"
    assert not receiver.calls
    params = subscription()
    params["delivery"]["secret"] = (
        "whsec_" + base64.b64encode(b"incorrect-secret" * 2).decode()
    )
    assert (
        rpc(client, "agent_a", "events/subscribe", params)["error"]["data"]["reason"]
        == "http_rejected"
    )
    incoming(client, rpc)
    assert not run_once(client)
    assert len(receiver.calls) == 1


def test_ac16_unsubscribe_is_idempotent(client, rpc, receiver):
    params = subscription()
    rpc(client, "agent_a", "events/subscribe", params)
    incoming(client, rpc)
    del params["delivery"]["secret"]
    for _ in range(2):
        assert rpc(client, "agent_a", "events/unsubscribe", params)["result"] == {}
    assert not run_once(client)
    assert len(receiver.calls) == 1


def test_ac17_signature_and_callback_metadata(client, rpc, receiver):
    # Subscribe after commit to exercise catch-up without bypassing the inbox.
    expected = incoming(client, rpc)
    sub = rpc(client, "agent_a", "events/subscribe", subscription())["result"]
    assert run_once(client)
    notification, payload, headers = receiver.calls[-1]
    assert notification in receiver.accepted
    assert notification == payload["eventId"]
    assert payload["name"] == "message.created"
    assert payload["data"] == {
        "address": "assistant-a@example.test",
        "thread_id": expected["thread_id"],
        "message_seq": 1,
        "cursor": None,
    }
    assert headers["X-MCP-Subscription-Id"] == sub["id"]
    assert "private" not in json.dumps(payload)
    assert payload["cursor"] is None


def test_ac26_expired_subscription_preserves_inbox(client, rpc):
    mailbox = client.app.state.mailbox
    now = [mailbox.clock()]
    mailbox.clock = lambda: now[0]
    rpc(client, "agent_a", "events/subscribe", subscription(ttlMs=1000))
    expected = incoming(client, rpc)
    now[0] += 1000
    assert not run_once(client)
    args = {"as_address": "assistant-a@example.test"}
    snapshot = mailbox.check_messages("agent_a", **args)
    feed = mailbox.check_messages("agent_a", **args, cursor=snapshot["next_cursor"])
    assert [event["message_id"] for event in feed["events"]] == [expected["message_id"]]


def test_ac27_restart_keeps_backlog_and_subscription(config, rpc, receiver):
    with TestClient(
        build_app(config, receiver, background=False),
        client=("127.0.0.1", 1),
        base_url="http://localhost",
    ) as before:
        sub = rpc(before, "agent_a", "events/subscribe", subscription())["result"]
        incoming(before, rpc)
    with TestClient(
        build_app(config, receiver, background=False),
        client=("127.0.0.1", 1),
        base_url="http://localhost",
    ) as after:
        assert run_once(after)
        assert receiver.calls[-1][2]["X-MCP-Subscription-Id"] == sub["id"]
        assert after.app.state.mailbox.get_reception("agent_a", "assistant-a@example.test")[
            "last_wake_accepted"
        ]


def test_verified_refresh_replaces_key_and_respects_ttl(client, rpc, receiver):
    import base64
    from datetime import datetime

    mailbox = client.app.state.mailbox
    now = [1_900_000_000_000]
    mailbox.clock = lambda: now[0]
    params = subscription(ttlMs=None)
    original = rpc(client, "agent_a", "events/subscribe", params)["result"]
    assert (
        datetime.fromisoformat(original["refreshBefore"]).timestamp() * 1000 - now[0]
        == 86_400_000
    )
    replacement = b"verified-replacement-key" * 2
    receiver.key = replacement
    params["delivery"]["secret"] = "whsec_" + base64.b64encode(replacement).decode()
    params["ttlMs"] = 4000
    now[0] += 200
    renewed = rpc(client, "agent_a", "events/subscribe", params)["result"]
    assert renewed["id"] == original["id"]
    assert (
        datetime.fromisoformat(renewed["refreshBefore"]).timestamp() * 1000 - now[0]
        == 4000
    )
    incoming(client, rpc)
    assert run_once(client)
    assert receiver.calls[-1][0] in receiver.accepted


def test_prune_keeps_live_subscription_and_clears_expired_inbox(client, rpc, receiver):
    from agent_messenger.domain import TTL
    from agent_messenger.maintenance import prune

    mailbox = client.app.state.mailbox
    time_ms = [1_900_000_000_000]
    mailbox.clock = lambda: time_ms[0]
    old = incoming(client, rpc)
    time_ms[0] += TTL
    subscription_id = rpc(client, "agent_a", "events/subscribe", subscription())[
        "result"
    ]["id"]

    assert prune(mailbox.storage, time_ms[0]) == 1
    fresh = incoming(client, rpc)
    assert fresh["message_id"] != old["message_id"]
    assert run_once(client)
    assert receiver.calls[-1][2]["X-MCP-Subscription-Id"] == subscription_id
    assert receiver.calls[-1][1]["data"]["thread_id"] == fresh["thread_id"]
