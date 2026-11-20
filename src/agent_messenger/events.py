import hashlib
import hmac
import json
import secrets

from cryptography.fernet import InvalidToken

from .domain import DomainError, canonical, identifier, iso
from .webhooks import CallbackError, signed, validate_url, webhook_key

EVENT = "message.created"
DEFAULT_TTL = 86_400_000
VERIFICATION_CACHE = 600_000
EVENT_DEFINITION = {
    "name": EVENT,
    "description": "Un message a été déposé dans une boîte Agent Messenger autorisée.",
    "delivery": ["webhook"],
    "inputSchema": {
        "type": "object",
        "properties": {"address": {"type": "string"}},
        "required": ["address"],
        "additionalProperties": False,
    },
    "payloadSchema": {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "thread_id": {"type": "string"},
            "message_seq": {"type": "integer"},
            "cursor": {"type": ["string", "null"]},
        },
        "required": ["address", "thread_id", "message_seq", "cursor"],
        "additionalProperties": False,
    },
}


class Events:
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.mailbox = dispatcher.mailbox
        self.cipher = dispatcher.cipher

    def list(self, principal):
        with self.mailbox.storage.transaction(write=False) as db:
            actor = self.mailbox.actor(db, principal)
            return {
                "events": [EVENT_DEFINITION] if actor["mode"] == "mcp_event" else []
            }

    def request(self, principal, params):
        arguments = params.get("arguments")
        delivery = params.get("delivery")
        if (
            params.get("name") != EVENT
            or not isinstance(arguments, dict)
            or set(arguments) != {"address"}
            or not isinstance(arguments["address"], str)
            or not isinstance(delivery, dict)
            or delivery.get("mode") != "webhook"
        ):
            raise DomainError("invalid_arguments")
        address = arguments["address"]
        with self.mailbox.storage.transaction(write=False) as db:
            actor = self.mailbox.actor(db, principal, address)
            if actor["mode"] != "mcp_event":
                raise DomainError("forbidden")
            agent = actor["id"]
        url = delivery.get("url")
        validate_url(url)
        sub_id = (
            "sub_"
            + hashlib.sha256(
                canonical([principal, url, EVENT, arguments]).encode()
            ).hexdigest()
        )
        if "id" in params and params["id"] != sub_id:
            raise DomainError("invalid_arguments")
        return address, agent, url, sub_id, delivery

    async def verify(self, url, sub_id, key, now):
        challenge = secrets.token_urlsafe(32)
        body, headers = signed(
            {"type": "verification", "challenge": challenge},
            identifier("verify_"),
            key,
            now,
            sub_id,
        )
        response = await self.dispatcher.transport(
            url, body, headers, verification=True
        )
        if not 200 <= response.status < 300:
            raise CallbackError("http_rejected")
        try:
            returned = json.loads(response.body)["challenge"]
            if isinstance(returned, str) and hmac.compare_digest(
                returned.encode(), challenge.encode()
            ):
                return
        except (KeyError, TypeError, ValueError):
            pass
        raise CallbackError("challenge_failed")

    async def subscribe(self, principal, params):
        address, agent, url, sub_id, delivery = self.request(principal, params)
        duration = params.get("ttlMs")
        if duration is not None and (type(duration) is not int or duration < 1):
            raise DomainError("invalid_arguments")
        cursor = params.get("cursor")
        if cursor is not None and not isinstance(cursor, str):
            raise DomainError("invalid_arguments")
        try:
            key = webhook_key(delivery.get("secret"))
        except ValueError:
            raise DomainError("invalid_arguments") from None
        duration = min(DEFAULT_TTL, duration) if duration is not None else DEFAULT_TTL
        async with self.dispatcher.agent_locks[agent]:
            now = self.mailbox.clock()
            with self.mailbox.storage.transaction(write=False) as db:
                previous = db.execute(
                    "SELECT * FROM event_subscriptions WHERE id=?", (sub_id,)
                ).fetchone()
            verified = False
            verified_at = now
            if previous and previous["active"] and previous["expires_at"] > now:
                try:
                    verified = 0 <= now - previous[
                        "verified_at"
                    ] < VERIFICATION_CACHE and hmac.compare_digest(
                        self.cipher.decrypt(previous["encrypted_secret"]), key
                    )
                except InvalidToken:
                    pass
            if verified:
                verified_at = previous["verified_at"]
            else:
                await self.verify(url, sub_id, key, now)
                verified_at = self.mailbox.clock()
            expires = self.mailbox.clock() + duration
            with self.mailbox.storage.transaction() as db:
                self.mailbox.actor(db, principal, address)
                db.execute(
                    """
                    INSERT INTO event_subscriptions VALUES (?,?,?,?,?,?,?,1)
                    ON CONFLICT(id) DO UPDATE SET encrypted_callback=excluded.encrypted_callback,
                        encrypted_secret=excluded.encrypted_secret,verified_at=excluded.verified_at,
                        expires_at=excluded.expires_at,active=1
                """,
                    (
                        sub_id,
                        principal,
                        agent,
                        self.cipher.encrypt(url.encode()),
                        self.cipher.encrypt(key),
                        verified_at,
                        expires,
                    ),
                )
                db.execute(
                    """
                    UPDATE outbox SET state='queued',due_at=?,error_code=NULL,attempts=0,
                        notification_time=NULL
                    WHERE destination_id=? AND state='attention' AND error_code='subscription_unavailable'
                """,
                    (now, sub_id),
                )
                db.execute(
                    """
                    INSERT OR IGNORE INTO outbox(event_id,recipient_agent_id,destination_id,
                                                 kind,notification_id,state,due_at)
                    SELECT e.id,e.recipient_agent_id,?,'mcp_event','evt_'||lower(hex(randomblob(16))),'queued',?
                    FROM inbox_events e WHERE e.recipient_agent_id=? AND e.id>? AND e.expires_at>?
                """,
                    (
                        sub_id,
                        now,
                        agent,
                        self.mailbox.position(db, principal),
                        self.mailbox.clock(),
                    ),
                )
                db.execute(
                    "DELETE FROM outbox WHERE recipient_agent_id=? AND kind='mcp_event' AND destination_id=?",
                    (agent, agent),
                )
        self.dispatcher.wake.set()
        return {
            "id": sub_id,
            "refreshBefore": iso(expires),
            "cursor": None,
            "truncated": cursor is not None,
        }

    async def unsubscribe(self, principal, params):
        address, agent, _, sub_id, _ = self.request(principal, params)
        async with self.dispatcher.agent_locks[agent]:
            with self.mailbox.storage.transaction() as db:
                self.mailbox.actor(db, principal, address)
                db.execute(
                    "DELETE FROM event_subscriptions WHERE id=? AND principal_id=?",
                    (sub_id, principal),
                )
                db.execute(
                    """
                    UPDATE outbox SET state='attention',error_code='subscription_unavailable'
                    WHERE destination_id=?
                """,
                    (sub_id,),
                )
        self.dispatcher.wake.set()
        return {}
