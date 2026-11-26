import base64
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import monotonic, time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from starlette.testclient import TestClient

from agent_messenger import auth
from agent_messenger.app import build_app
from agent_messenger.config import load_proxy_oauth

ISSUER = "https://messenger.example/"
CHANNEL = "staging-shared-channel-" + "c" * 32
OWNER = "shared-OIDC-subject"


def _base64url_uint(value):
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _rsa_jwk(private_key, kid):
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _base64url_uint(numbers.n),
        "e": _base64url_uint(numbers.e),
    }


class _JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.fetch_count += 1
        if self.server.failure_status is not None:
            self.send_response(self.server.failure_status)
            self.end_headers()
            return
        body = json.dumps({"keys": self.server.keys}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _JWKSServer(ThreadingHTTPServer):
    def __init__(self):
        self.keys = []
        self.fetch_count = 0
        self.failure_status = None
        super().__init__(("127.0.0.1", 0), _JWKSHandler)


@pytest.fixture(scope="module")
def signer():
    return generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwks_server(signer):
    server = _JWKSServer()
    server.keys = [_rsa_jwk(signer, "key-a")]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=1)


@pytest.fixture
def oauth(config, signer, jwks_server, monkeypatch):
    agents = tuple(
        replace(agent, oauth_client_id="client-" + agent.id, oauth_subject=OWNER)
        for agent in config.agents
    )
    runtime = {
        "proxy_introspection_port": jwks_server.server_port,
        "proxy_public_key_credential": "legacy-key-is-ignored",
        "proxy_channel_credential": "channel-key",
        "proxy_introspection_credential": "introspection-client",
    }
    credentials = {
        "channel-key": CHANNEL.encode(),
        "introspection-client": b"inspector:" + b"x" * 32,
    }
    proxy = load_proxy_oauth(
        runtime,
        ISSUER,
        agents,
        b"cursor-" + b"0" * 32,
        lambda name: credentials[name],
    )
    config = replace(config, agents=agents, local_tokens={}, proxy_oauth=proxy)
    issued = {}
    calls = []

    def token(
        agent,
        *,
        signing_key=None,
        kid="key-a",
        algorithm="RS256",
        response_fields=None,
        **overrides,
    ):
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
        headers = None if kid is None else {"kid": kid}
        access_token = jwt.encode(
            claims,
            signing_key or signer,
            algorithm=algorithm,
            headers=headers,
        )
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
        yield client, token, calls, proxy


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
    client, token, _, _ = oauth
    for agent in ("agent_a", "agent_b", "agent_c"):
        result = content(call(client, token(agent), headers=[("X-Agent-Id", "other")]))
        assert (
            result["addresses"][0]["address"] == f"assistant-{agent[-1]}@example.test"
        )
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
    client, token, calls, _ = oauth
    valid = token("agent_b")
    other_key = generate_private_key(public_exponent=65537, key_size=2048)
    for response in (
        call(client, channel=None),
        call(client, valid, channel=None),
        call(client, valid, channel="unknown"),
        call(client, valid, headers=[("X-Agent-Messenger-Proxy-Channel", CHANNEL)]),
        call(client, token("agent_b", signing_key=other_key)),
        call(
            client,
            token(
                "agent_b",
                signing_key=b"not-an-rsa-key-" + b"x" * 32,
                algorithm="HS256",
            ),
        ),
        call(client, token("agent_b", kid=None)),
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
    client, token, _, _ = oauth
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
    client, token, _, _ = oauth
    issued = token("agent_b", response_fields={"iat": int(time()) - 60})
    assert content(call(client, issued))["addresses"][0]["address"] == "assistant-b@example.test"


def test_rotation_refreshes_jwks_and_selects_new_kid_after_cooldown(
    oauth, jwks_server
):
    client, token, calls, proxy = oauth
    assert content(call(client, token("agent_b")))["addresses"][0]["address"] == (
        "assistant-b@example.test"
    )
    assert jwks_server.fetch_count == 1

    rotated_signer = generate_private_key(public_exponent=65537, key_size=2048)
    jwks_server.keys = [_rsa_jwk(rotated_signer, "key-b")]
    rotated_token = token("agent_b", signing_key=rotated_signer, kid="key-b")
    introspections_before = len(calls)

    # An unknown kid is rejected during PyJWKClient's cooldown, not accepted
    # using a different key or by skipping signature verification.
    assert call(client, rotated_token).status_code == 401
    assert jwks_server.fetch_count == 1
    assert len(calls) == introspections_before

    past_cooldown = monotonic() - 31
    proxy.jwks_client._last_successful_fetch = past_cooldown
    proxy.jwks_client._last_fetch_attempt = past_cooldown
    assert content(call(client, rotated_token))["addresses"][0]["address"] == (
        "assistant-b@example.test"
    )
    assert jwks_server.fetch_count == 2
    assert len(calls) == introspections_before + 1


def test_jwks_outage_fails_closed_and_failed_fetches_are_rate_limited(
    oauth, jwks_server
):
    client, token, calls, proxy = oauth
    valid = token("agent_b")
    assert content(call(client, valid))["addresses"][0]["address"] == (
        "assistant-b@example.test"
    )
    assert jwks_server.fetch_count == 1

    # A cached, still-valid key can verify tokens while the JWKS endpoint is
    # unavailable; an unlisted kid must still fail closed.
    jwks_server.failure_status = 503
    assert content(call(client, valid))["addresses"][0]["address"] == (
        "assistant-b@example.test"
    )
    assert jwks_server.fetch_count == 1
    calls.clear()

    unknown_key = generate_private_key(public_exponent=65537, key_size=2048)
    unknown = token("agent_b", signing_key=unknown_key, kid="unknown-kid")
    past_cooldown = monotonic() - 31
    proxy.jwks_client._last_successful_fetch = past_cooldown
    proxy.jwks_client._last_fetch_attempt = past_cooldown

    assert call(client, unknown).status_code == 401
    assert jwks_server.fetch_count == 2
    second_unknown = token(
        "agent_b", signing_key=unknown_key, kid="another-unknown-kid"
    )
    assert call(client, second_unknown).status_code == 401
    assert jwks_server.fetch_count == 2
    assert not calls


def test_oauth_configuration_rejects_reusing_a_client_id(config):
    agents = [
        replace(agent, oauth_client_id="same-id", oauth_subject=OWNER)
        for agent in config.agents
    ]
    with pytest.raises(ValueError, match="distinct OAuth client ID"):
        load_proxy_oauth({}, config.resource_uri, agents, b"cursor", lambda _: None)
