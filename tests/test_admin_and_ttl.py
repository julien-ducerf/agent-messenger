from conftest import ADMIN, TOKENS

from agent_messenger.admin import badge
from agent_messenger.domain import TTL, iso
from agent_messenger.maintenance import prune

A = "assistant-b@example.test"
B = "assistant-c@example.test"
AUTH = ("admin", ADMIN)


def deposit(mailbox, **options):
    return mailbox.send(
        "agent_b",
        A,
        options.pop("text", "private-body-marker"),
        options.pop("key", "key"),
        **({"to_addresses": [B], **options} if "thread_id" not in options else options),
    )


def test_ac20_exact_ttl_keeps_config_and_current_thread(client):
    mailbox = client.app.state.mailbox
    now = [1_900_000_000_000]
    origin = now[0]
    mailbox.clock = lambda: now[0]
    first = deposit(mailbox)
    snapshot = mailbox.check_messages("agent_c", B)
    feed = mailbox.check_messages("agent_c", B, snapshot["next_cursor"])
    assert feed["events"][0]["message_id"] == first["message_id"]
    now[0] += 1000
    second = deposit(mailbox, key="later", thread_id=first["thread_id"])
    now[0] = origin + TTL - 1
    assert prune(mailbox.storage, now[0]) == 0
    now[0] += 1
    assert (
        mailbox.read_thread("agent_c", B, first["thread_id"])["results"][0]["seq"]
        == second["seq"]
        == 2
    )
    assert prune(mailbox.storage, now[0]) == 1
    with mailbox.storage.connection() as db:
        for table in ("messages", "inbox_events", "outbox", "idempotency_receipts"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT 1 FROM inbox_fetches WHERE event_id=?",
                (feed["events"][0]["event_seq"],),
            ).fetchone()
            is None
        )
        assert db.execute("SELECT count(*) FROM agents").fetchone()[0] == 3
        assert db.execute("SELECT count(*) FROM destinations").fetchone()[0] == 2
    now[0] += 1000
    assert prune(mailbox.storage, now[0]) == 1
    with mailbox.storage.connection() as db:
        assert db.execute("SELECT count(*) FROM threads").fetchone()[0] == 0


def test_ac07_ac21_absent_agent_and_stale_cursor(client):
    mailbox = client.app.state.mailbox
    now = [1_900_000_000_000]
    origin = now[0]
    mailbox.clock = lambda: now[0]
    pos = mailbox.check_messages("agent_c", B)["next_cursor"]
    deposit(mailbox)
    now[0] = origin + TTL - 1
    data = client.get("/admin/api/v1/summary", auth=AUTH).json()
    assert data == {
        "active_messages": 1,
        "unhandled": 1,
        "expiring": 1,
        "delivery_errors": 0,
        "next_expiry": iso(origin + TTL),
    }
    now[0] += 1
    assert prune(mailbox.storage, now[0]) == 1
    from pytest import raises

    from agent_messenger.domain import DomainError

    with raises(DomainError, match="invalid_cursor"):
        mailbox.check_messages("agent_c", B, pos)
    fresh = mailbox.check_messages("agent_c", B)
    assert fresh["truncated"] and fresh["threads"] == []
    assert mailbox.check_messages("agent_c", B, fresh["next_cursor"])["events"] == []
    assert mailbox.get_reception("agent_c", B)["handled_through_event_seq"] == 0
    assert client.get("/admin/api/v1/summary", auth=AUTH).json()["active_messages"] == 0


def test_ac22_ac23_readonly_admin_escape_and_auth(client):
    mailbox = client.app.state.mailbox
    receipt = deposit(
        mailbox,
        text="<script>alert(1)</script>",
        subject='"><img src=x onerror=alert(2)>',
    )
    thread = receipt["thread_id"]
    path = f"/admin/api/v1/threads/{thread}/messages"
    for url in ("/admin", "/admin/", "/admin/style.css", "/admin/api/v1/summary", path):
        assert client.get(url).status_code == 401
        assert (
            client.get(
                url,
                headers={
                    "authorization": f"Bearer {TOKENS['agent_b']}",
                    "x-agent-messenger-admin": "true",
                },
            ).status_code
            == 401
        )
    assert client.post(path, auth=AUTH).status_code == 405
    result = client.get(path, auth=AUTH)
    assert result.headers["cache-control"] == "no-store"
    assert result.json()["results"][0]["text"] == "<script>alert(1)</script>"
    for url in ("/admin/", f"/admin/thread/{thread}"):
        result = client.get(url, auth=AUTH)
        assert result.status_code == 200
        assert "<script>" not in result.text
        assert "<img" not in result.text
        assert "&lt;script&gt;" in result.text
        assert "default-src 'none'" in result.headers["content-security-policy"]
    assert mailbox.get_reception("agent_c", B)["last_fetch"] is None
    assert mailbox.get_reception("agent_c", B)["handled_through_event_seq"] == 0
    assert client.get("/admin/api/v1/agents", auth=AUTH).status_code == 200
    assert (
        client.get("/admin/api/v1/deliveries?status=queued", auth=AUTH).json()[
            "results"
        ][0]["address"]
        == B
    )


def test_admin_status_labels_reflect_config_read_and_ack(client):
    mailbox = client.app.state.mailbox
    deposit(mailbox, text="status-display-check")

    page = client.get("/admin/", auth=AUTH).text
    assert "Notifications MCP" in page
    assert "Notifications automatiques" in page
    assert "Configuration" in page and "Fonctionnement" in page
    assert "Notifications activées" in page
    assert "Dernière notification" in page
    assert "Dernière consultation" in page
    assert "Conversations récentes" in page
    assert "Historique des 7 derniers jours" in page
    assert "En attente de notification" in page

    snapshot = mailbox.check_messages("agent_c", B)
    feed = mailbox.check_messages("agent_c", B, snapshot["next_cursor"])
    page = client.get("/admin/", auth=AUTH).text
    assert '<span class="badge info">Consulté</span>' in page
    mailbox.check_messages("agent_c", B, feed["next_cursor"])
    page = client.get("/admin/", auth=AUTH).text
    assert '<span class="badge success">Confirmé</span>' in page

    assert "Réception automatique indisponible" in badge(
        "attention", error_code="subscription_unavailable"
    )
    assert "Notification reçue" in badge("wake_accepted", http_status=200)
    assert "HTTP 200" in badge("wake_accepted", http_status=200)
    assert "Notification acceptée" in badge("wake_accepted", http_status=202)
    assert "HTTP 202" in badge("wake_accepted", http_status=202)
