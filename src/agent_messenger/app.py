import asyncio
import logging
import os
from contextlib import asynccontextmanager, suppress

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .admin import Admin
from .auth import Auth, loopback
from .config import load_config
from .delivery import Dispatcher
from .domain import Messenger
from .events import Events
from .maintenance import prune
from .mcp_api import create_mcp
from .storage import Storage
from .webhooks import post_callback

LOG = logging.getLogger("agent_messenger")


class Boundary:
    def __init__(self, app, config):
        self.app = app
        self.auth = Auth(config)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]
        response = None
        if not loopback(scope):
            response = JSONResponse({"code": "forbidden"}, status_code=403)
        elif path == "/mcp":
            principal = await self.auth.principal(scope)
            if principal is None:
                response = JSONResponse(
                    {"code": "forbidden"}, 401, headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                scope.setdefault("state", {})["agent_messenger_principal"] = principal
        elif path == "/admin" or path.startswith("/admin/"):
            if not self.auth.admin(scope):
                response = JSONResponse(
                    {"code": "forbidden"},
                    401,
                    headers={
                        "WWW-Authenticate": 'Basic realm="Agent Messenger", charset="UTF-8"',
                    },
                )

        async def protected_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() != b"cache-control"
                ] + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (
                        b"content-security-policy",
                        b"default-src 'none'; style-src 'self'; frame-ancestors 'none'; "
                        b"base-uri 'none'; form-action 'none'",
                    ),
                ]
            await send(message)

        await (response if response is not None else self.app)(
            scope, receive, protected_send
        )


def sweep(mailbox):
    with mailbox.storage.connection() as db:
        due = db.execute("""
            SELECT min(expiry) FROM (
                SELECT min(expires_at) AS expiry FROM messages
                UNION ALL SELECT min(expires_at) FROM idempotency_receipts
                UNION ALL SELECT min(expires_at) FROM event_subscriptions
            )
        """).fetchone()[0]
    now = mailbox.clock()
    if due is not None and due <= now:
        prune(mailbox.storage, now)
        return now
    return due


async def maintain(mailbox, changed):
    while True:
        changed.clear()
        delay = 60
        try:
            due = await asyncio.to_thread(sweep, mailbox)
            if due is not None:
                delay = min(60, max(0, (due - mailbox.clock()) / 1000))
        except Exception:
            LOG.error("purge_iteration_failed")
        try:
            await asyncio.wait_for(changed.wait(), delay)
        except TimeoutError:
            pass


def build_app(config, transport=post_callback, background=True):
    # The SDK's diagnostic logging can contain rejected JSON/Pydantic inputs.
    logging.getLogger("mcp").setLevel(logging.CRITICAL + 1)
    storage = Storage(config.database)
    mailbox = Messenger(
        storage,
        config.cursor_key,
        config.resource_uri,
        message_retention_days=config.message_retention_days,
    )
    dispatcher = Dispatcher(mailbox, config.destinations, config.cipher, transport)
    events = Events(dispatcher)
    sdk = create_mcp(config, mailbox, dispatcher, events)

    @asynccontextmanager
    async def lifespan(_app):
        await asyncio.to_thread(storage.initialize)
        await asyncio.to_thread(config.seed, storage)
        async with sdk.router.lifespan_context(sdk):
            tasks = []
            if background:
                tasks = [
                    asyncio.create_task(dispatcher.run()),
                    asyncio.create_task(maintain(mailbox, dispatcher.retention_wake)),
                ]
            try:
                yield
            finally:
                for task in tasks:
                    task.cancel()
                for task in tasks:
                    with suppress(asyncio.CancelledError):
                        await task

    async def health(_request: Request):
        return Response(status_code=204)

    def ready(_request: Request):
        try:
            with storage.transaction(write=False) as db:
                db.execute("SELECT id FROM agents LIMIT 1").fetchone()
        except Exception:
            return Response(status_code=503)
        return Response(status_code=204)

    app = Starlette(
        routes=[
            Route("/healthz", health),
            Route("/readyz", ready),
            *Admin(mailbox).routes(),
            *sdk.routes,
        ],
        lifespan=lifespan,
    )
    app.add_middleware(Boundary, config=config)
    app.state.mailbox = mailbox
    app.state.dispatcher = dispatcher
    app.state.events = events
    return app


def create_app():
    return build_app(load_config(os.environ["AGENT_MESSENGER_CONFIG"]))
