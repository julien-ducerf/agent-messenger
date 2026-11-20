import asyncio
import base64
import hmac
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

import h11

from .domain import canonical

MAX_RESPONSE = 4096
TLS = ssl.create_default_context()
GLOBAL_V6 = ipaddress.IPv6Network("2000::/3")
SPECIAL_NETWORKS = tuple(
    map(
        ipaddress.ip_network,
        (
            "192.0.0.0/24",
            "192.88.99.0/24",
            "2001::/23",
            "3fff::/20",
        ),
    )
)
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")


class CallbackError(Exception):
    pass


@dataclass(frozen=True)
class CallbackResponse:
    status: int
    body: bytes = b""


def webhook_key(secret):
    if (
        not isinstance(secret, str)
        or not secret.startswith("whsec_")
        or len(secret) > 100
    ):
        raise ValueError("invalid webhook secret")
    key = base64.b64decode(secret[6:], validate=True)
    if not 24 <= len(key) <= 64:
        raise ValueError("invalid webhook secret")
    return key


def signed(payload, notification_id, key, now, subscription=None, bearer=None):
    body = canonical(payload).encode()
    if len(body) > 256 * 1024:
        raise ValueError("callback payload too large")
    timestamp = str(now // 1000)
    digest = hmac.digest(
        key, f"{notification_id}.{timestamp}.".encode() + body, "sha256"
    )
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Agent-Messenger-wake/1",
        "webhook-id": notification_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": "v1," + base64.b64encode(digest).decode(),
    }
    if subscription:
        headers["X-MCP-Subscription-Id"] = subscription
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    return body, headers


def validate_url(url):
    try:
        if (
            not isinstance(url, str)
            or not 0 < len(url) <= 2048
            or any(not 33 <= ord(char) <= 126 or char in "\\#" for char in url)
        ):
            raise ValueError
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.port not in (None, 443)
        ):
            raise ValueError
        if not HOST.fullmatch(parts.hostname):
            ipaddress.IPv6Address(parts.hostname)
        if parts.hostname == "localhost" or parts.hostname.endswith(
            (".localhost", ".local")
        ):
            raise ValueError
        return parts
    except ValueError:
        raise CallbackError("unsafe_url") from None


def public_address(value):
    address = ipaddress.ip_address(value)
    if address.version == 6:
        if (
            address not in GLOBAL_V6
            or address.sixtofour is not None
            or address.teredo is not None
        ):
            return False
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not any(address in network for network in SPECIAL_NETWORKS)
    )


async def targets(host):
    loop = asyncio.get_running_loop()
    answers = await loop.getaddrinfo(
        host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    addresses = tuple(
        dict.fromkeys((family, sockaddr[0]) for family, _, _, _, sockaddr in answers)
    )
    if not addresses or any(not public_address(address) for _, address in addresses):
        raise CallbackError("unsafe_address")
    return addresses


async def post_callback(url, body, headers, *, verification=False):
    parts = validate_url(url)
    try:
        async with asyncio.timeout(5):
            addresses = await targets(parts.hostname)
            for family, address in addresses:
                try:
                    reader, writer = await asyncio.open_connection(
                        address,
                        443,
                        family=family,
                        flags=socket.AI_NUMERICHOST,
                        ssl=TLS,
                        server_hostname=parts.hostname,
                    )
                    break
                except OSError:
                    continue
            else:
                raise CallbackError("connection_failed")
            try:
                target = parts.path or "/"
                if parts.query:
                    target += "?" + parts.query
                http = h11.Connection(h11.CLIENT, max_incomplete_event_size=8192)
                request = h11.Request(
                    method="POST",
                    target=target,
                    headers=[
                        ("Host", parts.netloc),
                        ("Connection", "close"),
                        ("Content-Length", str(len(body))),
                        *headers.items(),
                    ],
                )
                writer.write(
                    http.send(request)
                    + http.send(h11.Data(data=body))
                    + http.send(h11.EndOfMessage())
                )
                await writer.drain()
                status = None
                response = bytearray()
                while True:
                    event = http.next_event()
                    if event is h11.NEED_DATA:
                        http.receive_data(await reader.read(4096))
                    elif isinstance(event, h11.Response):
                        status = event.status_code
                        if 300 <= status <= 399:
                            raise CallbackError("redirect_blocked")
                        if not verification or not 200 <= status < 300:
                            return CallbackResponse(status)
                    elif isinstance(event, h11.Data):
                        response.extend(event.data)
                        if len(response) > MAX_RESPONSE:
                            raise CallbackError("response_too_large")
                    elif isinstance(event, h11.EndOfMessage) and status is not None:
                        return CallbackResponse(status, bytes(response))
                    elif event is h11.PAUSED or isinstance(event, h11.ConnectionClosed):
                        raise CallbackError("invalid_response")
            finally:
                writer.close()
    except TimeoutError:
        raise CallbackError("timeout") from None
    except (OSError, h11.ProtocolError, UnicodeError):
        raise CallbackError("connection_failed") from None
