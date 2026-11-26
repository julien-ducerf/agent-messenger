import asyncio
import base64
import hmac
import ipaddress
import json
from collections import defaultdict, deque
from http.client import HTTPConnection, HTTPException
from time import monotonic, time
from urllib.parse import urlencode

import jwt
from starlette.datastructures import Headers

from .domain import DomainError


def loopback(scope):
    peer = scope.get("client")
    try:
        return bool(peer and ipaddress.ip_address(peer[0]).is_loopback)
    except ValueError:
        return False


def single_header(headers, name):
    values = headers.getlist(name)
    return values[0] if len(values) == 1 and len(values[0]) <= 4096 else ""


PROXY_CHANNEL_HEADER = "x-agent-messenger-proxy-channel"


def introspect(proxy, token):
    connection = HTTPConnection("127.0.0.1", proxy.introspection_port, timeout=2)
    try:
        connection.request(
            "POST",
            "/.idp/introspect",
            urlencode({"token": token, "token_type_hint": "access_token"}).encode(),
            {
                "Authorization": "Basic "
                + base64.b64encode(proxy.introspection_credential).decode(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        with connection.getresponse() as response:
            if response.status != 200:
                return None
            body = response.read(8193)
        return json.loads(body) if len(body) <= 8192 else None
    except (OSError, HTTPException, ValueError, RecursionError):
        return None
    finally:
        connection.close()


class Auth:
    def __init__(self, config):
        self.config = config
        self.principals = {agent.principal for agent in config.agents if agent.enabled}
        self.oauth_principals = {
            (agent.oauth_client_id, agent.oauth_subject): agent.principal
            for agent in config.agents
            if agent.enabled
        }

    async def principal(self, scope):
        if not loopback(scope):
            return None
        headers = Headers(scope=scope)
        scheme, _, token = single_header(headers, "authorization").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        if self.config.proxy_oauth is not None:
            return await self.proxy_principal(headers, token)
        for subject, expected in self.config.local_tokens.items():
            if subject in self.principals and hmac.compare_digest(
                token.encode("latin-1"), expected.encode()
            ):
                return subject
        return None

    async def proxy_principal(self, headers, token):
        proxy = self.config.proxy_oauth
        channel = single_header(headers, PROXY_CHANNEL_HEADER).encode("latin-1")
        if not hmac.compare_digest(channel, proxy.channel_key):
            return None
        try:
            signing_key = await asyncio.to_thread(
                proxy.jwks_client.get_signing_key_from_jwt, token
            )
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=proxy.issuer,
                issuer=proxy.issuer,
                options={"require": ["sub", "aud", "iss", "iat", "nbf", "exp"]},
            )
        except (
            jwt.InvalidTokenError,
            jwt.PyJWKClientError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ):
            return None
        if claims["aud"] != [proxy.issuer] or any(
            type(claims[key]) is not int for key in ("iat", "nbf", "exp")
        ):
            return None
        result = await asyncio.to_thread(introspect, proxy, token)
        # The proxy reports the OAuth request time as iat. Validate the token's
        # issuance time from the signed JWT, independently of that timestamp.
        if (
            not isinstance(result, dict)
            or result.get("active") is not True
            or not isinstance(result.get("client_id"), str)
            or any(
                result.get(key) != claims[key] for key in ("sub", "aud", "exp")
            )
            or claims["exp"] <= time()
        ):
            return None
        # The proxy exposes the OAuth client ID through introspection.
        # Use mcp-auth-proxy v2.10.3 or later (v2.11.0 validated).
        return self.oauth_principals.get((result["client_id"], claims["sub"]))

    def admin(self, scope):
        if not loopback(scope) or not self.config.admin_password:
            return False
        scheme, _, value = single_header(
            Headers(scope=scope), "authorization"
        ).partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            supplied = base64.b64decode(value, validate=True)
        except ValueError:
            return False
        return hmac.compare_digest(
            supplied, f"admin:{self.config.admin_password}".encode()
        )


class RateLimit:
    def __init__(self, tools, send):
        self.limits = {"tools": tools, "send": send}
        self.timestamps = defaultdict(deque)

    def check(self, principal, bucket):
        times = self.timestamps[principal, bucket]
        now = monotonic()
        while times and times[0] <= now - 60:
            times.popleft()
        if len(times) >= self.limits[bucket]:
            raise DomainError(
                "rate_limited", retry_after=max(1, int(61 - (now - times[0])))
            )
        times.append(now)
