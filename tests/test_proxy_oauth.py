from dataclasses import replace
from time import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from starlette.testclient import TestClient

from agent_messenger import auth
from agent_messenger.app import build_app
from agent_messenger.config import ProxyOAuth, load_proxy_oauth

ISSUER = "https://messenger.example/"
CHANNEL = "staging-shared-channel-" + "c" * 32
OWNER = "shared-OIDC-subject"


@pytest.fixture(scope="module")
def signer():
    return generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def oauth(config, signer, monkeypatch):
    agents = tuple(
        replace(agent, oauth_client_id="client-" + agent.id, oauth_subject=OWNER)
        for agent in config.agents
    )
    proxy = ProxyOAuth(
        ISSUER, signer.public_key(), CHANNEL.encode(), 18766, b"inspector:" + b"x" * 32
    )
    config = replace(config, agents=agents, local_tokens={}, proxy_oauth=proxy)
    issued = {}
    calls = []

    def token(agent, *, signing_key=None, response_fields=None, **overrides):
        now = int(time())
        claims = {
            "iss": ISSUER,
            "aud": [ISSUER],
            "sub": OWNER,
            "iat": now - 30,
            "nbf": now - 30,
            "exp": now + 100,
            "jti": agent,
            **overrides,
        }
        access_token = jwt.encode(claims, signing_key or signer, algorithm="RS256")
        issued[access_token] = {
            **{key: claims[key] for key in ("aud", "sub", "iat", "exp")},
            "active": True,
            "client_id": "client-" + agent,
            **(response_fields or {}),
        }
        return access_token

    def introspect(supplied_proxy, supplied_token):
        assert supplied_proxy == proxy
        calls.append(supplied_token)
        return issued.get(supplied_token)

    monkeypatch.setattr(auth, "introspect", introspect)
    with TestClient(
        build_app(config, background=False),
        client=("127.0.0.1", 9),
        base_url="http://localhost",
        headers={"accept": "application/json, text/event-stream"},
    ) as client:
        yield client, token, calls


def call(client, token=None, channel=CHANNEL, **params):
    headers = list(params.pop("headers", []))
    if token is not None:
        headers.append(("Authorization", "Bearer " + token))
    if channel is not None:
        headers.append(("X-Agent-Messenger-Proxy-Channel", channel))
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": params or {"name": "get_account"},
        },
        headers=headers,
    )


def content(response):
    assert response.status_code == 200
    return response.json()["result"]["structuredContent"]


def test_same_oauth_subject_with_three_distinct_client_ids(oauth):
    client, token, _ = oauth
    for agent in ("agent_a", "agent_b", "agent_c"):
        result = content(call(client, token(agent), headers=[("X-Agent-Id", "other")]))
        assert result["addresses"][0]["address"] == f"{agent}@example.test"
    other = {"as_address": "assistant-c@example.test"}
    assert (
        content(call(client, token("agent_b"), name="check_messages", arguments=other))[
            "code"
        ]
        == "forbidden"
    )
    assert (
        content(
            call(
                client,
                token("agent_b"),
                name="send",
                arguments={
                    **other,
                    "to_addresses": ["assistant-a@example.test"],
                    "text": "synthetic",
                    "idempotency_key": "forbidden",
                },
            )
        )["code"]
        == "forbidden"
    )
    receipt = content(
        call(
            client,
            token("agent_b"),
            name="send",
            arguments={
                "as_address": "assistant-b@example.test",
                "to_addresses": ["assistant-c@example.test"],
                "text": "synthetic",
                "idempotency_key": "sent",
            },
        )
    )
    assert (
        content(
            call(
                client,
                token("agent_a"),
                name="read_thread",
                arguments={
                    "as_address": "assistant-a@example.test",
                    "thread_id": receipt["thread_id"],
                },
            )
        )["code"]
        == "not_found"
    )


def test_direct_loopback_and_invalid_jwt_are_rejected_before_introspection(oauth):
    client, token, calls = oauth
    valid = token("agent_b")
    other_key = generate_private_key(public_exponent=65537, key_size=2048)
    for response in (
        call(client, channel=None),
        call(client, valid, channel=None),
        call(client, valid, channel="unknown"),
        call(client, valid, headers=[("X-Agent-Messenger-Proxy-Channel", CHANNEL)]),
        call(client, token("agent_b", signing_key=other_key)),
        call(client, token("agent_b", exp=int(time()) - 1)),
        call(client, token("agent_b", nbf=int(time()) + 30)),
        call(client, token("agent_b", iat=int(time()) + 30)),
        call(client, token("agent_b", iss="https://elsewhere.example/")),
        call(client, token("agent_b", aud=["https://elsewhere.example/"])),
        call(client, token("agent_b", aud=[ISSUER, "https://elsewhere.example/"])),
    ):
        assert response.status_code == 401
    assert not calls


def test_introspection_is_mandatory_and_jwt_client_claim_is_ignored(oauth):
    client, token, _ = oauth
    denied = (
        token("unknown", client_id="client-agent_b", azp="client-agent_b"),
        token("agent_c", sub="unknown"),
        token("agent_b", response_fields={"active": False}, jti="inactive"),
        token("agent_b", response_fields={"exp": 0}, jti="mismatch"),
        token("agent_b", response_fields={"client_id": None}, jti="no-id"),
    )
    assert all(call(client, item).status_code == 401 for item in denied)
    assert (
        content(call(client, token("agent_c", client_id="client-agent_b")))["addresses"][0][
            "address"
        ]
        == "assistant-c@example.test"
    )


def test_introspection_request_time_can_differ_from_signed_issuance_time(oauth):
    client, token, _ = oauth
    issued = token("agent_b", response_fields={"iat": int(time()) - 60})
    assert content(call(client, issued))["addresses"][0]["address"] == "assistant-b@example.test"


def test_oauth_configuration_rejects_reusing_a_client_id(config):
    agents = [
        replace(agent, oauth_client_id="same-id", oauth_subject=OWNER)
        for agent in config.agents
    ]
    with pytest.raises(ValueError, match="distinct OAuth client ID"):
        load_proxy_oauth({}, config.resource_uri, agents, b"cursor", lambda _: None)
