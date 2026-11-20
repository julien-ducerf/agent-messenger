def test_ac01_new_thread(client, rpc):
    result = rpc(
        client,
        "agent_b",
        "tools/call",
        {
            "name": "send",
            "arguments": {
                "as_address": "assistant-b@example.test",
                "to_addresses": ["assistant-c@example.test"],
                "text": "test",
                "idempotency_key": "one",
            },
        },
    )
    assert result["result"]["structuredContent"]["status"] == "sent"

    with client.app.state.mailbox.storage.connection() as db:
        assert db.execute("SELECT count(*) FROM messages").fetchone()[0] == 1
        assert [
            row[0] for row in db.execute("SELECT recipient_agent_id FROM inbox_events")
        ] == ["agent_c"]
        assert [
            row[0] for row in db.execute("SELECT recipient_agent_id FROM outbox")
        ] == ["agent_c"]


def test_event_discovery(client, rpc):
    assert (
        rpc(
            client,
            "agent_a",
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "contract", "version": "1"},
            },
        )["result"]["capabilities"]["events"]
        == {}
    )
    assert (
        rpc(client, "agent_a", "events/list")["result"]["events"][0]["name"]
        == "message.created"
    )
    assert rpc(client, "agent_b", "events/list")["result"]["events"] == []


def test_mcp_2_discovery_and_event_methods(client, rpc):
    version = "2026-07-28"
    meta = {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "contract", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    params = {"_meta": meta}
    result = rpc(
        client,
        "agent_a",
        "server/discover",
        params,
        **{"mcp-protocol-version": version, "mcp-method": "server/discover"},
    )
    assert result["result"]["capabilities"]["events"] == {}
    events = rpc(
        client,
        "agent_a",
        "events/list",
        params,
        **{"mcp-protocol-version": version, "mcp-method": "events/list"},
    )
    assert events["result"]["events"][0]["name"] == "message.created"


def test_real_sdk_legacy_client(client, config):
    import asyncio

    import httpx
    from conftest import TOKENS
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def exercise():
        transport = httpx.ASGITransport(app=client.app, client=("127.0.0.1", 50000))
        async with httpx.AsyncClient(
            transport=transport,
            headers={
                "authorization": f"Bearer {TOKENS['agent_b']}",
            },
        ) as http:
            async with streamable_http_client(
                "http://localhost/mcp", http_client=http
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    assert {tool.name for tool in tools.tools} == {
                        "get_account",
                        "send",
                        "check_messages",
                        "read_thread",
                        "set_satisfied",
                        "get_reception",
                    }
                    account = await session.call_tool("get_account")
                    assert (
                        account.structured_content["connection"]["resource_uri"]
                        == config.resource_uri
                    )

    asyncio.run(exercise())


def test_long_poll_wakes_after_commit(client, rpc, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    observed = Event()
    mailbox = client.app.state.mailbox
    check = mailbox.check_messages

    def observe(principal, **args):
        result = check(principal, **args)
        if args.get("wait_seconds") and result["wait_outcome"] == "empty":
            observed.set()
        return result

    monkeypatch.setattr(mailbox, "check_messages", observe)
    args = {"as_address": "assistant-c@example.test"}
    initial = rpc(
        client, "agent_c", "tools/call", {"name": "check_messages", "arguments": args}
    )
    cursor = initial["result"]["structuredContent"]["next_cursor"]

    def read():
        return rpc(
            client,
            "agent_c",
            "tools/call",
            {
                "name": "check_messages",
                "arguments": {**args, "cursor": cursor, "wait_seconds": 5},
            },
        )["result"]["structuredContent"]

    with ThreadPoolExecutor() as workers:
        result = workers.submit(read)
        assert observed.wait(timeout=2)
        test_ac01_new_thread(client, rpc)
        assert result.result(timeout=2)["events"][0]["text"] == "test"
