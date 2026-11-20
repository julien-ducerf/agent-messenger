import html
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from .domain import DomainError, iso

PARIS = ZoneInfo("Europe/Paris")
DAY = 86_400_000
STATUS = {
    "queued": "En attente de notification",
    "retrying": "Nouvel essai en cours",
    "wake_accepted": "Notification reçue",
    "fetched": "Consulté",
    "handled": "Confirmé",
    "attention": "À vérifier",
}
DELIVERIES = """
    SELECT e.id AS event_seq, e.message_id, m.thread_id, e.created_at, e.expires_at, a.address,
           a.display_name, o.id AS job_id, o.attempts, o.http_status, o.accepted_at, o.last_attempt_at,
           o.error_code, f.fetched_at,
           CASE WHEN e.id<=coalesce(pos.handled_through,0) THEN 'handled'
                WHEN f.fetched_at IS NOT NULL THEN 'fetched'
                WHEN a.active=0 OR p.active=0 OR p.id IS NULL THEN 'attention'
                WHEN o.kind='mcp_event' AND NOT EXISTS (
                    SELECT 1 FROM event_subscriptions s
                    WHERE s.id=o.destination_id AND s.active=1 AND s.expires_at>:now
                ) THEN 'attention'
                ELSE coalesce(o.state,'attention') END AS status
    FROM inbox_events e JOIN messages m ON m.id=e.message_id JOIN agents a ON a.id=e.recipient_agent_id
    LEFT JOIN outbox o ON o.event_id=e.id
    LEFT JOIN principals p ON p.agent_id=a.id
    LEFT JOIN inbox_positions pos ON pos.principal_id=p.id
    LEFT JOIN inbox_fetches f ON f.event_id=e.id AND f.principal_id=p.id
    WHERE e.expires_at>:now
"""
SQL_THREADS = """
    SELECT t.id AS thread_id,t.subject,t.number,m.body,m.created_at,m.expires_at,m.id AS message_id
    FROM threads t JOIN messages m ON m.thread_id=t.id AND m.seq=t.last_seq
    WHERE m.expires_at>:now
"""


def e(value):
    return html.escape(str(value), quote=True)


def date(value):
    if value is None:
        return "—"
    return datetime.fromisoformat(value).astimezone(PARIS).strftime("%d/%m/%Y %H:%M")


def dates(row):
    return {
        name: iso(value) if value is not None else None
        for name, value in row.items()
        if name.endswith("_at")
    }


def badge(status, http_status=None, error_code=None):
    tones = {
        "queued": "pending",
        "retrying": "pending",
        "wake_accepted": "success",
        "fetched": "info",
        "handled": "success",
        "attention": "error" if error_code else "pending",
        "configured": "neutral",
        "not_configured": "pending",
        "disabled": "neutral",
        "unknown": "neutral",
    }
    labels = {
        "configured": "Notifications activées",
        "not_configured": "Notifications non configurées",
        "disabled": "Raccordement désactivé",
        "unknown": "Aucune notification connue",
    }
    label = labels.get(status, STATUS.get(status, "État inconnu"))
    tone = tones.get(status, "neutral")
    if status == "wake_accepted":
        label = "Notification acceptée" if http_status == 202 else "Notification reçue"
    elif status == "attention" and error_code == "subscription_unavailable":
        label = "Réception automatique indisponible"
    elif status == "attention" and error_code:
        label = "Notification en échec"
    details = []
    if http_status is not None:
        if status != "wake_accepted" and http_status in {200, 202}:
            details.append(
                "Notification acceptée"
                if http_status == 202
                else "Notification reçue"
            )
        details.append(f"HTTP {http_status}")
    if error_code:
        details.append(error_code)
    detail = (
        f'<small class="status-detail">{e(" · ".join(details))}</small>'
        if details
        else ""
    )
    return f'<span class="badge {tone}">{e(label)}</span>{detail}'


class Admin:
    def __init__(self, mailbox):
        self.mailbox = mailbox

    @staticmethod
    def summarize(db, now):
        row = db.execute(
            f"""
            WITH deliveries AS ({DELIVERIES})
            SELECT (SELECT count(*) FROM messages WHERE expires_at>:now) AS active_messages,
                   count(DISTINCT CASE WHEN status<>'handled' THEN event_seq END) AS unhandled,
                   count(DISTINCT CASE WHEN status<>'handled' AND expires_at<=:risk THEN event_seq END) AS expiring,
                   count(CASE WHEN status='attention' OR error_code IS NOT NULL THEN 1 END) AS delivery_errors,
                   min(CASE WHEN status<>'handled' THEN expires_at END) AS next_expiry
            FROM deliveries
        """,
            {"now": now, "risk": now + DAY},
        ).fetchone()
        result = dict(row)
        result["next_expiry"] = (
            iso(result["next_expiry"]) if result["next_expiry"] is not None else None
        )
        return result

    @staticmethod
    def agents(db, now):
        rows = db.execute(
            """
            SELECT a.id,a.display_name,a.address,a.mode,a.active,
                   max(o.accepted_at) AS last_wake_at,max(f.fetched_at) AS last_fetch_at,
                   max(CASE WHEN e.expires_at>:now AND e.id<=coalesce(pos.handled_through,0) THEN 1 ELSE 0 END)
                       AS recent_handled,
                   (SELECT x.error_code FROM outbox x JOIN inbox_events y ON y.id=x.event_id
                    WHERE x.recipient_agent_id=a.id AND y.expires_at>:now AND x.error_code IS NOT NULL
                    ORDER BY x.last_attempt_at DESC LIMIT 1) AS last_error,
                   CASE WHEN a.mode='webhook' THEN coalesce(d.enabled,0) ELSE EXISTS (
                       SELECT 1 FROM event_subscriptions s WHERE s.agent_id=a.id AND s.principal_id=p.id
                       AND s.active=1 AND s.expires_at>:now
                   ) END AS configured
            FROM agents a LEFT JOIN destinations d ON d.agent_id=a.id
            LEFT JOIN principals p ON p.agent_id=a.id AND p.active=1
            LEFT JOIN inbox_positions pos ON pos.principal_id=p.id
            LEFT JOIN inbox_events e ON e.recipient_agent_id=a.id AND e.expires_at>:now
            LEFT JOIN outbox o ON o.event_id=e.id LEFT JOIN inbox_fetches f ON f.event_id=e.id AND f.principal_id=p.id
            GROUP BY a.id ORDER BY a.display_name
        """,
            {"now": now},
        ).fetchall()
        results = []
        for item in rows:
            row = dict(item)
            results.append({**row, **dates(row)})
        return results

    @staticmethod
    def people(db, thread_id):
        return [
            dict(row)
            for row in db.execute(
                """
            SELECT a.address,a.display_name,p.satisfied FROM thread_participants p JOIN agents a ON a.id=p.agent_id
            WHERE p.thread_id=? ORDER BY a.display_name
        """,
                (thread_id,),
            )
        ]

    @staticmethod
    def deliveries(db, now, limit, status=None, since=0):
        if status is not None and status not in STATUS:
            raise DomainError("invalid_arguments")
        rows = db.execute(
            f"""
            SELECT * FROM ({DELIVERIES}) WHERE (:status IS NULL OR status=:status)
              AND created_at>=:since ORDER BY event_seq DESC,job_id DESC LIMIT :limit
        """,
            {"now": now, "status": status, "limit": limit, "since": since},
        ).fetchall()
        return [{**dict(row), **dates(dict(row))} for row in rows]

    def threads(self, db, now, limit, cursor):
        scope = ["admin", "threads"]
        position = (
            self.mailbox.cursors.decode(cursor, scope, now)
            if cursor
            else [2**63 - 1, 2**63 - 1]
        )
        rows = db.execute(
            SQL_THREADS
            + """
            AND (m.created_at,t.number)<(:created,:number)
            ORDER BY m.created_at DESC,t.number DESC LIMIT :limit
        """,
            {
                "now": now,
                "created": position[0],
                "number": position[1],
                "limit": limit + 1,
            },
        ).fetchall()
        next_cursor = (
            self.mailbox.cursors.encode(
                [
                    1,
                    scope,
                    now,
                    rows[limit - 1]["created_at"],
                    rows[limit - 1]["number"],
                ]
            )
            if len(rows) > limit
            else None
        )
        results = [self.thread_info(db, now, row) for row in rows[:limit]]
        return {
            "results": results,
            "next_cursor": next_cursor,
            "has_more": next_cursor is not None,
        }

    def thread_info(self, db, now, row):
        metadata = {name: row[name] for name in ("thread_id", "subject", "message_id")}
        deliveries = db.execute(
            f"""
            SELECT address,status FROM ({DELIVERIES}) WHERE message_id=:message
        """,
            {"now": now, "message": row["message_id"]},
        )
        return {
            **metadata,
            **dates(dict(row)),
            "participants": self.people(db, row["thread_id"]),
            "preview": row["body"][:240],
            "delivery": [dict(d) for d in deliveries],
        }

    @staticmethod
    def delivery_status_details(db, now, message_id):
        rows = db.execute(
            f"""SELECT address,status,http_status,error_code FROM ({DELIVERIES})
                WHERE message_id=:message ORDER BY address""",
            {"now": now, "message": message_id},
        )
        return [dict(row) for row in rows]

    def thread(self, db, now, thread_id):
        row = db.execute(
            SQL_THREADS + " AND t.id=:thread", {"now": now, "thread": thread_id}
        ).fetchone()
        if row is None:
            raise DomainError("not_found")
        return self.thread_info(db, now, row)

    def messages(self, db, now, thread_id, limit, cursor):
        thread = db.execute(
            "SELECT 1 FROM threads WHERE id=? AND expires_at>?", (thread_id, now)
        ).fetchone()
        if not thread:
            raise DomainError("not_found")
        scope = ["admin", "messages", thread_id]
        position = self.mailbox.cursors.decode(cursor, scope, now)[0] if cursor else 0
        rows = db.execute(
            """
            SELECT m.id AS message_id,m.seq,m.body AS text,m.reply_to,m.created_at,m.expires_at,a.address AS from_address
            FROM messages m JOIN agents a ON a.id=m.sender_agent_id
            WHERE m.thread_id=? AND m.expires_at>? AND m.seq>? ORDER BY m.seq LIMIT ?
        """,
            (thread_id, now, position, limit + 1),
        )
        results = []
        size = 0
        for row in rows:
            size += len(row["text"].encode())
            if size > 128 * 1024 or len(results) == limit:
                break
            results.append({**dict(row), **dates(dict(row)), "delivery": []})
        else:
            return self.attach_status(db, now, thread_id, results, None)
        return self.attach_status(
            db,
            now,
            thread_id,
            results,
            self.mailbox.cursors.encode([1, scope, now, results[-1]["seq"]]),
        )

    @staticmethod
    def attach_status(db, now, thread_id, results, cursor):
        delivered = defaultdict(list)
        if results:
            rows = db.execute(
                f"""
                SELECT message_id,address,status,attempts,http_status FROM ({DELIVERIES})
                WHERE thread_id=:thread AND message_id IN ({",".join(f":msg{i}" for i in range(len(results)))})
                ORDER BY address
            """,
                {
                    "now": now,
                    "thread": thread_id,
                    **{f"msg{i}": row["message_id"] for i, row in enumerate(results)},
                },
            )
            for row in rows:
                delivered[row["message_id"]].append(
                    {name: row[name] for name in row.keys() if name != "message_id"}
                )
        for row in results:
            row["delivery"] = delivered[row["message_id"]]
        return {
            "results": results,
            "next_cursor": cursor,
            "has_more": cursor is not None,
        }

    def route(self, request):
        action = request.path_params.get("action")
        thread_id = request.path_params.get("thread_id")
        query = request.query_params
        now = self.mailbox.clock()
        try:
            limit = int(query.get("limit", "50"))
            cursor = query.get("cursor")
            since = int(query.get("since_ms", "0"))
            if (
                not 1 <= limit <= 50
                or not 0 <= since < 2**63
                or thread_id is not None
                and not thread_id.isascii()
            ):
                raise DomainError("invalid_arguments")
            with self.mailbox.storage.transaction(write=False) as db:
                if request.url.path in {"/admin", "/admin/"}:
                    data = self.home(db, now, cursor)
                    return HTMLResponse(data)
                if request.url.path.startswith("/admin/thread/"):
                    data = self.detail(db, now, thread_id, cursor)
                    return HTMLResponse(data)
                if thread_id is not None:
                    data = (
                        self.messages(db, now, thread_id, limit, cursor)
                        if request.url.path.endswith("/messages")
                        else (self.thread(db, now, thread_id))
                    )
                elif action == "summary":
                    data = self.summarize(db, now)
                elif action == "agents":
                    data = {"results": self.agents(db, now)}
                elif action == "threads":
                    data = self.threads(db, now, limit, cursor)
                elif action == "deliveries":
                    data = {
                        "results": self.deliveries(
                            db, now, limit, query.get("status"), since
                        )
                    }
                elif action == "version":
                    data = {
                        "version": "1.0.0",
                        "schema": db.execute("PRAGMA user_version").fetchone()[0],
                    }
                else:
                    raise DomainError("not_found")
            return JSONResponse(data)
        except ValueError:
            return JSONResponse({"code": "invalid_arguments"}, 400)
        except DomainError as error:
            return JSONResponse(
                error.data, 404 if error.data["code"] == "not_found" else 400
            )

    @staticmethod
    def page(title, content):
        return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} · Agent Messenger</title><link rel="stylesheet" href="/admin/style.css"></head>
<body><main><header><a class="brand" href="/admin/">Agent Messenger</a>
<a href="">Actualiser</a></header>{content}</main></body></html>"""

    def home(self, db, now, cursor):
        summary = self.summarize(db, now)
        threads = self.threads(db, now, 20, cursor)
        agents = self.agents(db, now)
        cards = []
        for agent in agents:
            if not agent["active"]:
                configuration = badge("disabled")
            elif agent["configured"]:
                configuration = badge("configured")
            else:
                configuration = badge("not_configured")
            latest = db.execute(
                f"""SELECT status,http_status,error_code FROM ({DELIVERIES})
                    WHERE address=:address ORDER BY event_seq DESC,job_id DESC LIMIT 1""",
                {"now": now, "address": agent["address"]},
            ).fetchone()
            functioning = (
                badge(
                    latest["status"],
                    latest["http_status"],
                    latest["error_code"],
                )
                if latest
                else badge("unknown")
            )
            mode = (
                "Notifications MCP"
                if agent["mode"] == "mcp_event"
                else "Notifications automatiques"
            )
            cards.append(f"""<section class="agent-card">
<div class="agent-heading"><div><p class="eyebrow">{e(mode)}</p><h2>{e(agent["display_name"])}</h2></div></div>
<p class="agent-address">{e(agent["address"])}</p>
<dl class="agent-state"><div><dt>Configuration</dt><dd>{configuration}</dd></div>
<div><dt>Fonctionnement</dt><dd>{functioning}</dd></div></dl>
<dl class="agent-activity"><div><dt>Dernière notification</dt><dd>{date(agent["last_wake_at"])}</dd></div>
<div><dt>Dernière consultation</dt><dd>{date(agent["last_fetch_at"])}</dd></div></dl></section>""")
        items = []
        for row in threads["results"]:
            people = " · ".join(
                person["display_name"] for person in row["participants"]
            )
            statuses = " ".join(
                badge(item["status"], item["http_status"], item["error_code"])
                for item in self.delivery_status_details(db, now, row["message_id"])
            )
            items.append(f"""<li class="conversation"><div class="conversation-heading">
<a href="/admin/thread/{e(row["thread_id"])}">{e(row["subject"] or "Conversation sans titre")}</a>
<time>{date(row["created_at"])}</time></div>
<p class="meta">{e(people)}</p><p class="preview">{e(row["preview"])}</p>
<div class="badge-row">{statuses}</div></li>""")
        diagnostics = []
        for row in self.deliveries(db, now, 8):
            diagnostics.append(
                f"<li><span>{e(row['display_name'])}</span><span>{badge(row['status'], row['http_status'], row['error_code'])}</span></li>"
            )
        next_page = (
            "<p><a href='?"
            + e(urlencode({"cursor": threads["next_cursor"]}))
            + "'>Fils plus anciens</a></p>"
            if threads["next_cursor"]
            else ""
        )
        conversation_items = "".join(items) or '<li class="empty-state">Aucune conversation active.</li>'
        configured_agents = " · ".join(
            e(agent["display_name"]) for agent in agents
        )
        return self.page(
            "Conversations",
            f"""<div class="page-intro"><p class="eyebrow">Messagerie entre assistants IA</p>
<h1>Conversations</h1><p class="intro-copy">Échanges récents entre {configured_agents}.</p></div>
<section class="agent-section" aria-labelledby="agents-title"><div class="section-heading">
<h2 id="agents-title">Raccordements</h2><span class="meta">Configuration et dernières notifications connues</span></div>
<div class="agents">{"".join(cards)}</div></section><div class="columns">
<section class="conversation-section"><div class="section-heading"><h2>Conversations récentes</h2>
<span class="meta">Triés par dernier message</span></div><ul class="threads">{conversation_items}</ul>{next_page}</section>
<aside><p class="eyebrow">Conservation</p><h2>Historique des 7 derniers jours</h2><p class="meta">Les messages et événements expirés ne sont plus affichés.</p>
<dl class="summary"><div><dt>Messages conservés</dt><dd>{summary["active_messages"]}</dd></div>
<div><dt>En attente de confirmation</dt><dd>{summary["unhandled"]}</dd></div>
<div><dt>Notifications en échec</dt><dd>{summary["delivery_errors"]}</dd></div>
<div><dt>Prochaine expiration en attente</dt><dd>{date(summary["next_expiry"])}</dd></div></dl>
<h3 class="subheading">Notifications récentes</h3><ul class="diagnostic">{"".join(diagnostics) or "<li>Aucune livraison récente.</li>"}</ul></aside></div>""",
        )

    def detail(self, db, now, thread_id, cursor):
        thread = self.thread(db, now, thread_id)
        page = self.messages(db, now, thread_id, 50, cursor)
        items = []
        for row in page["results"]:
            delivery = self.delivery_status_details(db, now, row["message_id"])
            statuses = " ".join(
                f"{e(item['address'])} {badge(item['status'], item['http_status'], item['error_code'])}"
                for item in delivery
            )
            recipients = ", ".join(item["address"] for item in delivery)
            items.append(f"""<li class="message-card"><div class="message-heading">
<div><p class="eyebrow">De</p><strong>{e(row["from_address"])}</strong></div>
<time>{date(row["created_at"])}</time></div>
<p class="message">{e(row["text"])}</p>
<div class="message-footer"><p><span class="meta">À</span> {e(recipients) if recipients else "—"}</p>
<p class="meta">Expire le {date(row["expires_at"])}</p></div>
<div class="badge-row">{statuses}</div></li>""")
        more = (
            "<p><a href='?"
            + e(urlencode({"cursor": page["next_cursor"]}))
            + "'>Messages suivants</a></p>"
            if page["next_cursor"]
            else ""
        )
        subject = thread["subject"] or "Conversation sans titre"
        people = " · ".join(person["display_name"] for person in thread["participants"])
        return self.page(
            subject,
            f"""<p class="back-link"><a href="/admin/">← Tous les fils</a></p>
<div class="page-intro"><p class="eyebrow">Conversation</p><h1>{e(subject)}</h1>
<p class="intro-copy">Participants : {e(people)}</p></div>
<ol class="threads message-list">{"".join(items)}</ol>{more}""",
        )

    def routes(self):
        css = Path(__file__).with_name("admin.css").read_text()

        async def style(_request):
            return Response(css, media_type="text/css")

        return [
            Route("/admin", self.route),
            Route("/admin/", self.route),
            Route("/admin/style.css", style),
            Route("/admin/thread/{thread_id}", self.route),
            Route(
                "/admin/api/v1/threads/{thread_id}/messages",
                self.route,
                name="thread_messages",
            ),
            Route("/admin/api/v1/threads/{thread_id}", self.route),
            Route("/admin/api/v1/{action}", self.route),
        ]
