from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_messenger.domain import DomainError, Messenger

agent_b, agent_c, agent_a = (
    f"assistant-{agent[-1]}@example.test" for agent in ("agent_b", "agent_c", "agent_a")
)


def send(mailbox, key="one", text="hello", **arguments):
    if not arguments:
        arguments = {"to_addresses": [agent_c]}
    return mailbox.send("agent_b", agent_b, text, key, **arguments)


def test_ac02_ac03_idempotence(mailbox):
    receipt = send(mailbox)
    assert send(mailbox) == receipt
    with pytest.raises(DomainError, match="idempotency_conflict"):
        send(mailbox, text="other")
    with mailbox.storage.connection() as db:
        for table in ("messages", "inbox_events", "outbox"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1


def test_configured_message_retention_is_applied_to_new_threads(mailbox):
    now = [1_900_000_000_000]
    messenger = Messenger(
        mailbox.storage,
        mailbox.cursors.key,
        mailbox.resource_uri,
        clock=lambda: now[0],
        message_retention_days=2,
    )
    send(messenger, "short-retention")
    with mailbox.storage.connection() as db:
        expiry = db.execute("SELECT expires_at FROM threads").fetchone()[0]
    assert expiry == now[0] + 2 * 24 * 60 * 60 * 1000


def test_configured_message_retention_has_safe_bounds(mailbox):
    with pytest.raises(ValueError, match="message_retention_days"):
        Messenger(
            mailbox.storage,
            mailbox.cursors.key,
            mailbox.resource_uri,
            message_retention_days=0,
        )


def test_ac04_binding(mailbox):
    with pytest.raises(DomainError, match="forbidden"):
        mailbox.check_messages("agent_c", agent_b)
    thread = send(mailbox)["thread_id"]
    with pytest.raises(DomainError, match="not_found"):
        mailbox.read_thread("agent_a", agent_a, thread)
    with pytest.raises(DomainError, match="not_found"):
        mailbox.send("agent_a", agent_a, "intruder", "bad", thread_id=thread)


def test_ac05_ac06_snapshot_restart(mailbox):
    for key in range(23):
        send(mailbox, str(key))
    first = mailbox.check_messages("agent_c", agent_c)
    assert len(first["threads"]) == 20 and first["has_more"]
    later = send(mailbox, "later")
    restarted = Messenger(mailbox.storage, mailbox.cursors.key, mailbox.resource_uri)
    second = restarted.check_messages("agent_c", agent_c, first["next_cursor"])
    assert len(second["threads"]) == 3 and second["has_more"]
    feed = restarted.check_messages("agent_c", agent_c, second["next_cursor"])
    assert len(feed["events"]) == 24
    assert feed["events"][-1]["message_id"] == later["message_id"]
    assert restarted.get_reception("agent_c", agent_c)["handled_through_event_seq"] == 0
    ack = restarted.check_messages("agent_c", agent_c, feed["next_cursor"])
    assert ack["events"] == []
    assert (
        restarted.get_reception("agent_c", agent_c)["handled_through_event_seq"]
        == feed["events"][-1]["event_seq"]
    )


def test_ac07_cursor_scope_integrity(mailbox):
    token = mailbox.check_messages("agent_c", agent_c)["next_cursor"]
    for actor, address, cursor in [
        ("agent_c", agent_c, token + "x"),
        ("agent_b", agent_b, token),
    ]:
        with pytest.raises(DomainError, match="invalid_cursor") as error:
            mailbox.check_messages(actor, address, cursor)
        assert error.value.data["catch_up"] == "check_messages"


@pytest.mark.parametrize("text", ["", "  ", "é" * 32769, "\ud800"])
def test_ac19_text(mailbox, text):
    with pytest.raises(DomainError, match="invalid_text"):
        send(mailbox, text=text)
    with mailbox.storage.connection() as db:
        assert db.execute("SELECT count(*) FROM messages").fetchone()[0] == 0


def test_ac24_group_positions_are_independent(mailbox):
    receipt = send(mailbox, to_addresses=[agent_c, agent_a])
    for whom, address in [("agent_c", agent_c), ("agent_a", agent_a)]:
        snapshot = mailbox.check_messages(whom, address)
        feed = mailbox.check_messages(whom, address, snapshot["next_cursor"])
        assert [event["message_id"] for event in feed["events"]] == [
            receipt["message_id"]
        ]
        if whom == "agent_c":
            mailbox.check_messages(whom, address, feed["next_cursor"])
    assert mailbox.get_reception("agent_c", agent_c)["handled_through_event_seq"] > 0
    assert mailbox.get_reception("agent_a", agent_a)["handled_through_event_seq"] == 0


def test_ac25_concurrent_sequence(mailbox):
    thread = send(mailbox)["thread_id"]
    with ThreadPoolExecutor(max_workers=8) as workers:
        seqs = list(
            workers.map(
                lambda i: send(mailbox, str(i), thread_id=thread)["seq"], range(18)
            )
        )
    assert sorted(seqs) == list(range(2, 20))
    assert [
        item["seq"] for item in mailbox.read_thread("agent_c", agent_c, thread)["results"]
    ] == list(range(1, 20))


def test_read_does_not_ack_and_satisfied_does_not_purge(mailbox):
    thread = send(mailbox)["thread_id"]
    assert (
        mailbox.read_thread("agent_c", agent_c, thread, seq=1)["results"][0]["text"]
        == "hello"
    )
    assert mailbox.get_reception("agent_c", agent_c)["last_fetch"]
    assert mailbox.get_reception("agent_c", agent_c)["handled_through_event_seq"] == 0
    assert mailbox.set_satisfied("agent_c", agent_c, thread, "done")["satisfied"]
    assert mailbox.read_thread("agent_c", agent_c, thread)["results"]


def test_feed_byte_budget_without_gaps(mailbox):
    first = send(mailbox, text="é" * 32768)
    for i in range(1, 3):
        send(mailbox, key=f"max-{i}", text="é" * 32768, thread_id=first["thread_id"])
    page = mailbox.check_messages("agent_c", agent_c)
    page = mailbox.check_messages("agent_c", agent_c, page["next_cursor"])
    assert page["has_more"]
    assert [event["seq"] for event in page["events"]] == [1, 2]
    page = mailbox.check_messages("agent_c", agent_c, page["next_cursor"])
    assert not page["has_more"]
    assert [event["seq"] for event in page["events"]] == [3]
