import asyncio
import logging

from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp_types import (
    CallToolResult,
    ListToolsResult,
    RequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)
from pydantic import ConfigDict

from .auth import RateLimit
from .domain import DomainError, canonical
from .webhooks import CallbackError

LOG = logging.getLogger("agent_messenger.mcp")
STRING = {"type": "string"}
BOOL = {"type": "boolean"}
INT = {"type": "integer"}
ADDRESS = {"as_address": STRING}
THREAD = {**ADDRESS, "thread_id": STRING}
KEY = {"idempotency_key": STRING}
TOOLS = {
    "get_account": ("Consulter ton identité Messenger", {}, (), True),
    "send": (
        "Envoyer un message dans un fil existant ou à des destinataires",
        {
            **ADDRESS,
            **KEY,
            "text": STRING,
            "to_addresses": {"type": "array", "items": STRING, "maxItems": 7},
            "thread_id": STRING,
            "subject": STRING,
            "reply_to": STRING,
            "satisfied": BOOL,
        },
        ("as_address", "idempotency_key", "text"),
        False,
    ),
    "check_messages": (
        "Consulter et acquitter le courrier avec le dernier curseur traité",
        {
            **ADDRESS,
            "cursor": STRING,
            "wait_seconds": {**INT, "minimum": 0, "maximum": 25},
        },
        ("as_address",),
        False,
    ),
    "read_thread": (
        "Lire le contenu d’un fil autorisé",
        {**THREAD, "cursor": STRING, "seq": INT},
        ("as_address", "thread_id"),
        False,
    ),
    "set_satisfied": (
        "Indiquer si une réponse reste souhaitée",
        {**THREAD, **KEY, "satisfied": BOOL},
        ("as_address", "thread_id", "idempotency_key"),
        False,
    ),
    "get_reception": (
        "Consulter les états de réception de ton adresse",
        ADDRESS,
        ("as_address",),
        True,
    ),
}


class EventParams(RequestParams):
    model_config = ConfigDict(extra="allow")


class Tools:
    def __init__(self, mailbox, dispatcher, rate):
        self.mailbox = mailbox
        self.dispatcher = dispatcher
        self.rate = rate
        self.changed = asyncio.Event()
        self.definitions = {
            name: Tool(
                name=name,
                description=description,
                input_schema={
                    "type": "object",
                    "properties": properties,
                    "required": list(required),
                    "additionalProperties": False,
                },
                annotations=ToolAnnotations(
                    read_only_hint=readonly,
                    destructive_hint=False,
                    idempotent_hint=name != "check_messages",
                    open_world_hint=False,
                ),
            )
            for name, (description, properties, required, readonly) in TOOLS.items()
        }

    def committed(self):
        prev = self.changed
        self.changed = asyncio.Event()
        prev.set()
        self.dispatcher.wake.set()
        self.dispatcher.retention_wake.set()

    async def check(self, principal, args):
        deadline = asyncio.get_running_loop().time() + args.get("wait_seconds", 0)
        operation = self.mailbox.check_messages
        while True:
            changed = self.changed
            result = await asyncio.to_thread(operation, principal, **args)
            if result["phase"] == "feed":
                self.dispatcher.wake.set()
            if result["wait_outcome"] != "empty" or not args.get("wait_seconds"):
                return result
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining > 0:
                try:
                    await asyncio.wait_for(changed.wait(), remaining)
                    continue
                except TimeoutError:
                    pass
            return {**result, "wait_outcome": "timeout"}

    async def list(self, ctx, params):
        return ListToolsResult(tools=list(self.definitions.values()))

    async def call(self, ctx, params):
        principal = ctx.request.state.agent_messenger_principal
        name = params.name
        args = params.arguments or {}
        try:
            self.rate.check(principal, "tools")
            if name not in self.definitions:
                raise DomainError("not_found")
            _, properties, required, _ = TOOLS[name]
            if not set(required) <= args.keys() <= properties.keys():
                raise DomainError("invalid_arguments")
            types = {"string": str, "boolean": bool, "integer": int, "array": list}
            for key, value in args.items():
                if type(value) is not types[properties[key]["type"]]:
                    raise DomainError(
                        "invalid_text" if key == "text" else "invalid_arguments"
                    )
            operation = getattr(self.mailbox, name)
            if name == "send":
                self.rate.check(principal, "send")
            if name == "check_messages":
                result = await self.check(principal, args)
            else:
                result = await asyncio.to_thread(operation, principal, **args)
                if name == "send":
                    self.committed()
            failed = False
        except DomainError as error:
            result, failed = error.data, True
        except Exception:
            LOG.error(
                "tool_internal_error tool=%s",
                name if name in self.definitions else "unknown",
            )
            result, failed = {"code": "internal_error"}, True
        return CallToolResult(
            content=[TextContent(type="text", text=canonical(result))],
            structured_content=result,
            is_error=failed,
        )


def create_mcp(config, mailbox, dispatcher, events):
    rate = RateLimit(config.tools_limit, config.send_limit)
    tools = Tools(mailbox, dispatcher, rate)
    sdk = Server(
        "Agent Messenger",
        version="1.0.0",
        on_list_tools=tools.list,
        on_call_tool=tools.call,
        get_tool_input_schema=lambda name: (
            TOOLS.get(name) and tools.definitions[name].input_schema
        ),
    )

    async def capabilities(ctx, next_handler):
        result = await next_handler(ctx)
        if ctx.method in {"initialize", "server/discover"}:
            result["capabilities"]["events"] = {}
        return result

    # Keep discovery and custom methods inside the SDK transport and its protocol checks.
    # Disable the default telemetry middleware so messages cannot reach a span exporter.
    sdk.middleware[:] = [capabilities]

    def register(method):
        async def event_handler(ctx, _params):
            principal = ctx.request.state.agent_messenger_principal
            params = dict(ctx.params or {})
            params.pop("_meta", None)
            try:
                rate.check(principal, "tools")
                if method == "list":
                    if params:
                        raise DomainError("invalid_arguments")
                    return await asyncio.to_thread(events.list, principal)
                return await getattr(events, method)(principal, params)
            except DomainError as error:
                raise MCPError(
                    code=-32602, message=error.data["code"], data=error.data
                ) from None
            except CallbackError as error:
                raise MCPError(
                    code=-32015,
                    message="CallbackEndpointError",
                    data={"reason": str(error)},
                ) from None

        sdk.add_request_handler(f"events/{method}", EventParams, event_handler)

    for method in ("list", "subscribe", "unsubscribe"):
        register(method)

    return sdk.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=512 * 1024,
        transport_security=TransportSecuritySettings(
            allowed_hosts=list(config.allowed_hosts),
            allowed_origins=list(config.allowed_origins),
        ),
    )
