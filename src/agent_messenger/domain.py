import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime

TTL = 7 * 24 * 60 * 60 * 1000
MAX_TEXT = 65536


def now_ms():
    return time.time_ns() // 1_000_000


def iso(value):
    return (
        datetime.fromtimestamp(value / 1000, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    )


def identifier(prefix=""):
    return prefix + str(uuid.uuid4())


class DomainError(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.data = {"code": code, **details}


class CursorCodec:
    def __init__(self, key):
        self.key = key

    def encode(self, value):
        data = base64.urlsafe_b64encode(canonical(value).encode()).rstrip(b"=")
        return (
            data + b"." + hmac.new(self.key, data, "sha256").hexdigest().encode()
        ).decode()

    def decode(self, token, scope, now):
        try:
            if not isinstance(token, str) or len(token) > 2048:
                raise ValueError
            data, signature = token.encode("ascii").split(b".")
            if not hmac.compare_digest(
                signature, hmac.new(self.key, data, "sha256").hexdigest().encode()
            ):
                raise ValueError
            value = json.loads(base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4)))
            if value[:2] != [1, scope] or not now - TTL < value[2] <= now:
                raise ValueError
            return value[3:]
        except (ValueError, TypeError, IndexError):
            raise DomainError("invalid_cursor", catch_up="check_messages") from None


class Messenger:
    def __init__(
        self, storage, cursor_key, resource_uri, clock=now_ms, message_retention_days=7
    ):
        if type(message_retention_days) is not int or not 1 <= message_retention_days <= 365:
            raise ValueError("message_retention_days must be an integer between 1 and 365")
        self.storage = storage
        self.cursors = CursorCodec(cursor_key)
        self.resource_uri = resource_uri
        self.clock = clock
        self.message_ttl = message_retention_days * 24 * 60 * 60 * 1000

    @staticmethod
    def actor(db, principal, address=...):
        actor = db.execute(
            """
            SELECT a.*, p.active AS principal_active FROM principals p
            JOIN agents a ON a.id=p.agent_id WHERE p.id=?
        """,
            (principal,),
        ).fetchone()
        if (
            actor is None
            or not actor["principal_active"]
            or address not in (..., actor["address"])
        ):
            raise DomainError("forbidden")
        if not actor["active"]:
            raise DomainError("inactive_address")
        return actor

    def get_account(self, principal):
        with self.storage.transaction(write=False) as db:
            actor = self.actor(db, principal)
            return {
                "connection": {"resource_uri": self.resource_uri},
                "addresses": [
                    {
                        "address": actor["address"],
                        "name": actor["display_name"],
                        "status": "active",
                    }
                ],
                "service": {"name": "Agent Messenger", "version": "1.0.0"},
            }

    @staticmethod
    def participant(db, thread_id, agent_id, now):
        if not isinstance(thread_id, str) or not thread_id.isascii():
            raise DomainError("invalid_arguments")
        thread = db.execute(
            """
            SELECT t.*, p.satisfied FROM threads t JOIN thread_participants p ON p.thread_id=t.id
            WHERE t.id=? AND t.expires_at>? AND p.agent_id=?
        """,
            (thread_id, now, agent_id),
        ).fetchone()
        if thread is None:
            raise DomainError("not_found")
        return thread

    @staticmethod
    def receipt(db, principal, key, request, now):
        if not isinstance(key, str) or not 1 <= len(key) <= 200:
            raise DomainError("invalid_arguments")
        try:
            key.encode()
        except UnicodeError:
            raise DomainError("invalid_arguments") from None
        digest = hashlib.sha256(canonical(request).encode()).hexdigest()
        row = db.execute(
            """
            SELECT * FROM idempotency_receipts WHERE principal_id=? AND key=?
        """,
            (principal, key),
        ).fetchone()
        if row and row["expires_at"] > now:
            if row["digest"] != digest:
                raise DomainError("idempotency_conflict")
            return digest, json.loads(row["receipt"])
        return digest, None

    @staticmethod
    def save_receipt(db, principal, key, digest, result, expires):
        db.execute(
            """
            INSERT INTO idempotency_receipts VALUES (?,?,?,?,?)
            ON CONFLICT(principal_id,key) DO UPDATE SET
                digest=excluded.digest,receipt=excluded.receipt,expires_at=excluded.expires_at
        """,
            (principal, key, digest, canonical(result), expires),
        )

    def send(
        self,
        principal,
        as_address,
        text,
        idempotency_key,
        to_addresses=None,
        thread_id=None,
        subject=None,
        reply_to=None,
        satisfied=False,
    ):
        try:
            valid_text = (
                isinstance(text, str)
                and text.strip()
                and len(text.encode()) <= MAX_TEXT
            )
        except UnicodeError:
            valid_text = False
        if not valid_text:
            raise DomainError("invalid_text")
        if (to_addresses is None) == (thread_id is None) or type(satisfied) is not bool:
            raise DomainError("invalid_arguments")
        creating = thread_id is None
        if creating:
            if (
                not isinstance(to_addresses, list)
                or not 1 <= len(to_addresses) <= 7
                or any(
                    not isinstance(address, str) or not address.isascii()
                    for address in to_addresses
                )
                or len(set(to_addresses)) != len(to_addresses)
                or as_address in to_addresses
                or reply_to is not None
            ):
                raise DomainError("invalid_arguments")
            to_addresses = sorted(to_addresses)
            if subject is not None and (
                not isinstance(subject, str)
                or len(subject) > 120
                or (subject and subject.splitlines() != [subject])
            ):
                raise DomainError("invalid_arguments")
            if subject is not None:
                try:
                    subject.encode()
                except UnicodeError:
                    raise DomainError("invalid_arguments") from None
        elif (
            subject is not None
            or not isinstance(thread_id, str)
            or (
                reply_to is not None
                and (not isinstance(reply_to, str) or not reply_to.isascii())
            )
        ):
            raise DomainError("invalid_arguments")
        with self.storage.transaction() as db:
            now = self.clock()
            sender = self.actor(db, principal, as_address)
            digest, existing = self.receipt(
                db,
                principal,
                idempotency_key,
                [
                    "send",
                    as_address,
                    text,
                    to_addresses,
                    thread_id,
                    subject,
                    reply_to,
                    satisfied,
                ],
                now,
            )
            if existing:
                return existing
            expires = now + self.message_ttl
            if creating:
                thread_id = identifier()
                recipients = [
                    db.execute(
                        "SELECT * FROM agents WHERE address=? AND active=1", (address,)
                    ).fetchone()
                    for address in to_addresses
                ]
                if None in recipients:
                    raise DomainError("recipient_unavailable")
                db.execute(
                    "INSERT INTO threads(id,subject,created_at,expires_at) VALUES (?,?,?,?)",
                    (thread_id, subject, now, expires),
                )
                db.executemany(
                    "INSERT INTO thread_participants(thread_id,agent_id) VALUES (?,?)",
                    [(thread_id, row["id"]) for row in [sender, *recipients]],
                )
            else:
                self.participant(db, thread_id, sender["id"], now)
                recipients = db.execute(
                    """
                    SELECT a.* FROM thread_participants p JOIN agents a ON p.agent_id=a.id
                    WHERE p.thread_id=? AND a.id<>? ORDER BY a.address
                """,
                    (thread_id, sender["id"]),
                ).fetchall()
                if any(not row["active"] for row in recipients):
                    raise DomainError("recipient_unavailable")
                if (
                    reply_to is not None
                    and not db.execute(
                        "SELECT 1 FROM messages WHERE id=? AND thread_id=? AND expires_at>?",
                        (reply_to, thread_id, now),
                    ).fetchone()
                ):
                    raise DomainError("not_found")
            seq = db.execute(
                """
                UPDATE threads SET last_seq=last_seq+1, expires_at=max(expires_at,?) WHERE id=? RETURNING last_seq
            """,
                (expires, thread_id),
            ).fetchone()[0]
            message_id = identifier()
            db.execute(
                "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)",
                (
                    message_id,
                    thread_id,
                    seq,
                    sender["id"],
                    reply_to,
                    text,
                    now,
                    expires,
                ),
            )
            db.execute(
                "UPDATE thread_participants SET satisfied=? WHERE thread_id=? AND agent_id=?",
                (satisfied, thread_id, sender["id"]),
            )
            for recipient in recipients:
                event_id = db.execute(
                    """
                    INSERT INTO inbox_events(recipient_agent_id,message_id,created_at,expires_at) VALUES (?,?,?,?)
                """,
                    (recipient["id"], message_id, now, expires),
                ).lastrowid
                self.enqueue(db, recipient, event_id, now)
            result = {
                "status": "sent",
                "thread_id": thread_id,
                "message_id": message_id,
                "event_id": message_id,
                "seq": seq,
                "as_address": as_address,
                "audience": [as_address, *(r["address"] for r in recipients)],
                "receipt_id": identifier(),
            }
            self.save_receipt(db, principal, idempotency_key, digest, result, expires)
        return result

    @staticmethod
    def enqueue(db, recipient, event_id, now):
        agent = recipient["id"]
        if recipient["mode"] == "webhook":
            destination = db.execute(
                "SELECT enabled FROM destinations WHERE agent_id=?", (agent,)
            ).fetchone()
            targets = [
                (agent, "queued" if destination and destination[0] else "attention")
            ]
        else:
            targets = [
                (row[0], "queued")
                for row in db.execute(
                    """
                SELECT s.id FROM event_subscriptions s JOIN principals p ON p.id=s.principal_id
                WHERE s.agent_id=? AND s.active=1 AND s.expires_at>? AND p.active=1 AND p.agent_id=s.agent_id
            """,
                    (agent, now),
                )
            ]
            if not targets:
                targets = [(agent, "attention")]
        db.executemany(
            """
            INSERT INTO outbox(event_id,recipient_agent_id,destination_id,kind,notification_id,state,due_at,error_code)
            VALUES (?,?,?,?,?,?,?,?)
        """,
            [
                (
                    event_id,
                    agent,
                    target,
                    recipient["mode"],
                    identifier("wake_" if recipient["mode"] == "webhook" else "evt_"),
                    state,
                    now,
                    (
                        "subscription_unavailable"
                        if recipient["mode"] == "mcp_event"
                        else "destination_unavailable"
                    )
                    if state == "attention"
                    else None,
                )
                for target, state in targets
            ],
        )

    @staticmethod
    def position(db, principal):
        row = db.execute(
            "SELECT handled_through FROM inbox_positions WHERE principal_id=?",
            (principal,),
        ).fetchone()
        return row[0] if row else 0

    @staticmethod
    def floor(db, agent, now):
        return db.execute(
            """
            SELECT max(coalesce((SELECT expired_through FROM inbox_floor WHERE agent_id=?),0),
                       coalesce((SELECT max(id) FROM inbox_events WHERE recipient_agent_id=? AND expires_at<=?),0))
        """,
            (agent, agent, now),
        ).fetchone()[0]

    @staticmethod
    def fetched(db, principal, agent, messages, now):
        db.executemany(
            """
            INSERT OR IGNORE INTO inbox_fetches
            SELECT ?,id,? FROM inbox_events WHERE recipient_agent_id=? AND message_id=?
        """,
            [(principal, now, agent, message) for message in messages],
        )

    def check_messages(self, principal, as_address, cursor=None, wait_seconds=0):
        if type(wait_seconds) is not int or not 0 <= wait_seconds <= 25:
            raise DomainError("invalid_arguments")
        scope = ["inbox", principal, as_address]
        with self.storage.transaction() as db:
            now = self.clock()
            actor = self.actor(db, principal, as_address)
            agent = actor["id"]
            floor = self.floor(db, agent, now)
            handled = self.position(db, principal)
            if cursor is None:
                bound = db.execute(
                    "SELECT coalesce(max(number),0) FROM threads"
                ).fetchone()[0]
                phase, position, baseline, floor_seen = (
                    "snapshot",
                    bound + 1,
                    handled,
                    floor,
                )
            else:
                phase, position, baseline, floor_seen = self.cursors.decode(
                    cursor, scope, now
                )
                if floor > max(floor_seen, position if phase == "feed" else baseline):
                    raise DomainError("invalid_cursor", catch_up="check_messages")
            if phase == "snapshot":
                rows = db.execute(
                    """
                    SELECT t.number,t.id AS thread_id,t.subject,t.last_seq,t.expires_at,
                           (SELECT max(e.id) FROM inbox_events e JOIN messages m ON m.id=e.message_id
                            WHERE m.thread_id=t.id AND e.recipient_agent_id=p.agent_id AND e.expires_at>?) AS event_seq
                    FROM threads t JOIN thread_participants p ON p.thread_id=t.id
                    WHERE p.agent_id=? AND t.number<? AND t.expires_at>?
                    ORDER BY t.number DESC LIMIT 21
                """,
                    (now, agent, position, now),
                ).fetchall()
                more = len(rows) > 20
                threads = [dict(row) for row in rows[:20]]
                position = threads[-1]["number"] if more else baseline
                for row in threads:
                    row.pop("number")
                    row["expires_at"] = iso(row["expires_at"])
                next_phase = "snapshot" if more else "feed"
                more = (
                    more
                    or db.execute(
                        """
                    SELECT 1 FROM inbox_events WHERE recipient_agent_id=? AND id>? AND expires_at>? LIMIT 1
                """,
                        (agent, baseline, now),
                    ).fetchone()
                    is not None
                )
                result = {
                    "threads": threads,
                    "events": [],
                    "has_more": more,
                    "wait_outcome": "ready",
                    "truncated": floor > handled,
                }
            else:
                # Every active event up to a server-issued feed cursor was delivered in order.
                if position > handled:
                    db.execute(
                        """
                        INSERT INTO inbox_positions VALUES (?,?) ON CONFLICT(principal_id) DO UPDATE SET
                        handled_through=max(handled_through,excluded.handled_through)
                    """,
                        (principal, position),
                    )
                rows = db.execute(
                    """
                    SELECT e.id AS event_seq,m.thread_id,m.id AS message_id,m.seq,a.address AS from_address,
                           m.body AS text,m.created_at
                    FROM inbox_events e JOIN messages m ON m.id=e.message_id JOIN agents a ON a.id=m.sender_agent_id
                    WHERE e.recipient_agent_id=? AND e.id>? AND e.expires_at>? ORDER BY e.id LIMIT 101
                """,
                    (agent, position, now),
                )
                events = []
                more = False
                size = 0
                for row in rows:
                    size += len(row["text"].encode())
                    if size > 128 * 1024 or len(events) == 100:
                        more = True
                        break
                    events.append(
                        {
                            **dict(row),
                            "kind": "message",
                            "created_at": iso(row["created_at"]),
                        }
                    )
                self.fetched(
                    db, principal, agent, [event["message_id"] for event in events], now
                )
                if events:
                    position = events[-1]["event_seq"]
                next_phase = "feed"
                result = {
                    "threads": [],
                    "events": events,
                    "has_more": more,
                    "wait_outcome": "ready" if events else "empty",
                }
            token = self.cursors.encode(
                [1, scope, now, next_phase, position, baseline, floor_seen]
            )
            return {"phase": phase, "next_cursor": token, **result}

    def read_thread(self, principal, as_address, thread_id, cursor=None, seq=None):
        if seq is not None and (
            cursor is not None or type(seq) is not int or not 0 < seq < 2**63
        ):
            raise DomainError("invalid_arguments")
        scope = ["thread", principal, as_address, thread_id]
        with self.storage.transaction() as db:
            now = self.clock()
            actor = self.actor(db, principal, as_address)
            self.participant(db, thread_id, actor["id"], now)
            position = (
                self.cursors.decode(cursor, scope, now)[0] if cursor is not None else 0
            )
            rows = db.execute(
                """
                SELECT m.id AS message_id,m.seq,m.body AS text,m.reply_to,a.address AS from_address,
                       m.created_at,m.expires_at
                FROM messages m JOIN agents a ON a.id=m.sender_agent_id
                WHERE m.thread_id=? AND m.expires_at>? AND m.seq>? AND (? IS NULL OR m.seq=?)
                ORDER BY m.seq LIMIT 51
            """,
                (thread_id, now, position, seq, seq),
            ).fetchall()
            if seq is not None and not rows:
                raise DomainError("not_found")
            results = [dict(row) for row in rows[:50]]
            next_cursor = (
                self.cursors.encode([1, scope, now, results[-1]["seq"]])
                if len(rows) > 50
                else None
            )
            self.fetched(
                db, principal, actor["id"], [row["message_id"] for row in results], now
            )
            for row in results:
                row["created_at"] = iso(row["created_at"])
                row["expires_at"] = iso(row["expires_at"])
            return {
                "results": results,
                "has_more": next_cursor is not None,
                "next_cursor": next_cursor,
            }

    def set_satisfied(
        self, principal, as_address, thread_id, idempotency_key, satisfied=True
    ):
        if type(satisfied) is not bool:
            raise DomainError("invalid_arguments")
        with self.storage.transaction() as db:
            now = self.clock()
            actor = self.actor(db, principal, as_address)
            digest, existing = self.receipt(
                db,
                principal,
                idempotency_key,
                ["set_satisfied", as_address, thread_id, satisfied],
                now,
            )
            if existing:
                return existing
            thread = self.participant(db, thread_id, actor["id"], now)
            db.execute(
                "UPDATE thread_participants SET satisfied=? WHERE thread_id=? AND agent_id=?",
                (satisfied, thread_id, actor["id"]),
            )
            result = {
                "thread_id": thread_id,
                "as_address": as_address,
                "satisfied": satisfied,
            }
            self.save_receipt(
                db,
                principal,
                idempotency_key,
                digest,
                result,
                min(now + self.message_ttl, thread["expires_at"]),
            )
            return result

    def get_reception(self, principal, as_address):
        with self.storage.transaction(write=False) as db:
            actor = self.actor(db, principal, as_address)
            now = self.clock()
            delivery = db.execute(
                """
                SELECT max(o.accepted_at), (SELECT error_code FROM outbox d JOIN inbox_events i ON i.id=d.event_id
                  WHERE d.recipient_agent_id=? AND d.error_code IS NOT NULL AND i.expires_at>?
                  ORDER BY d.last_attempt_at DESC LIMIT 1)
                FROM outbox o JOIN inbox_events e ON e.id=o.event_id
                WHERE o.recipient_agent_id=? AND e.expires_at>?
            """,
                (actor["id"], now, actor["id"], now),
            ).fetchone()
            fetched = db.execute(
                """
                SELECT max(f.fetched_at) FROM inbox_fetches f JOIN inbox_events e ON e.id=f.event_id
                WHERE f.principal_id=? AND e.expires_at>?
            """,
                (principal, now),
            ).fetchone()[0]
            return {
                "mode": actor["mode"],
                "last_wake_accepted": iso(delivery[0]) if delivery[0] else None,
                "last_fetch": iso(fetched) if fetched else None,
                "last_error": delivery[1],
                "handled_through_event_seq": self.position(db, principal),
            }
