"""Create an isolated synthetic SQLite dataset for the README screenshots."""

import asyncio
import base64
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.fernet import Fernet

from agent_messenger.config import load_config
from agent_messenger.delivery import Dispatcher
from agent_messenger.domain import Messenger
from agent_messenger.events import Events
from agent_messenger.storage import Storage
from agent_messenger.webhooks import CallbackResponse

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / ".local" / "demo"
AGENTS = {
    "general": (
        "assistant_general",
        "general@agents.example.test",
        "Assistant Général",
    ),
    "project": ("assistant_project", "project@agents.example.test", "Assistant Projet"),
    "ops": ("assistant_ops", "ops@agents.example.test", "Assistant Ops"),
}


def private_file(name, value):
    path = DEMO / "credentials" / name
    path.write_bytes(value + b"\n")
    path.chmod(0o600)


def create_config():
    if DEMO.exists():
        raise SystemExit(
            f"Refusing to overwrite {DEMO}; remove this ignored demo directory to regenerate it."
        )
    old_mask = os.umask(0o077)
    try:
        (DEMO / "credentials").mkdir(parents=True, mode=0o700)
        (DEMO / "data").mkdir(mode=0o700)
        tokens = {name: secrets.token_urlsafe(32) for name in AGENTS}
        credentials = {
            "cursor-key": secrets.token_urlsafe(48).encode(),
            "encryption-key": Fernet.generate_key(),
            "admin-password": secrets.token_urlsafe(32).encode(),
            **{f"{name}-token": token.encode() for name, token in tokens.items()},
            "general-url": b"https://general.example.test/events",
            "general-secret": b"whsec_" + base64.b64encode(secrets.token_bytes(32)),
        }
        for name in ("project", "ops"):
            credentials[f"{name}-url"] = f"https://{name}.example.test/wake".encode()
            credentials[f"{name}-secret"] = b"whsec_" + base64.b64encode(
                secrets.token_bytes(32)
            )
        for name, value in credentials.items():
            private_file(name, value)

        def quote(value):
            return json.dumps(value, ensure_ascii=False)

        agents = []
        for name, (agent_id, address, label) in AGENTS.items():
            mode = "mcp_event" if name == "general" else "webhook"
            agents.append(
                f"[[agents]]\nid = {quote(agent_id)}\naddress = {quote(address)}\n"
                f"label = {quote(label)}\nmode = {quote(mode)}\nprincipal = {quote(agent_id)}"
            )
        hooks = "\n\n".join(
            f'[webhooks.assistant_{name}]\nurl_credential = "{name}-url"\n'
            f'secret_credential = "{name}-secret"'
            for name in ("project", "ops")
        )
        config = f"""[service]
mode = "local"
database = "data/messages.sqlite3"
credentials_directory = "credentials"
resource_uri = "http://127.0.0.1:8765/mcp"
cursor_credential = "cursor-key"
encryption_credential = "encryption-key"
admin_credential = "admin-password"
message_retention_days = 7

[limits]
send_per_minute = 30
tools_per_minute = 120

{"\n\n".join(agents)}

{hooks}

[local_tokens]
assistant_general = "general-token"
assistant_project = "project-token"
assistant_ops = "ops-token"
"""
        path = DEMO / "config.toml"
        path.write_text(config, encoding="utf-8")
        path.chmod(0o600)
        return path
    finally:
        os.umask(old_mask)


class LocalCallbacks:
    """Return synthetic delivery outcomes in process; never access the network."""

    async def __call__(self, _url, body, _headers, *, verification=False):
        payload = json.loads(body)
        if verification:
            return CallbackResponse(
                200, json.dumps({"challenge": payload["challenge"]}).encode()
            )
        return CallbackResponse(202)


def send(
    mailbox, sender, recipient, text, key, *, subject=None, thread=None, reply_to=None
):
    args = {"as_address": AGENTS[sender][1], "text": text, "idempotency_key": key}
    if thread:
        args.update(thread_id=thread, reply_to=reply_to)
    else:
        args.update(to_addresses=[AGENTS[recipient][1]], subject=subject)
    return mailbox.send(AGENTS[sender][0], **args)


def consult(mailbox, agent, thread):
    principal, address, _ = AGENTS[agent]
    page = mailbox.check_messages(principal, address)
    feed = mailbox.check_messages(principal, address, cursor=page["next_cursor"])
    if feed.get("next_cursor"):
        mailbox.check_messages(principal, address, cursor=feed["next_cursor"])
    mailbox.read_thread(principal, address, thread)


async def seed(mailbox, events, dispatcher, clock):
    mailbox.clock = lambda: clock[0]
    await events.subscribe(
        AGENTS["general"][0],
        {
            "name": "message.created",
            "arguments": {"address": AGENTS["general"][1]},
            "delivery": {
                "mode": "webhook",
                "url": "https://general.example.test/events",
                "secret": "whsec_" + base64.b64encode(secrets.token_bytes(32)).decode(),
            },
        },
    )
    conversations = [
        (
            "Préparation du rapport mensuel",
            "general",
            "project",
            [
                "Peux-tu préparer le rapport mensuel à partir des éléments partagés ?",
                "Oui. Je rassemble les éléments et je te propose une première version structurée.",
                "Ajoute aussi les points de vigilance et les prochaines étapes.",
            ],
        ),
        (
            "Analyse des indicateurs d’usage",
            "general",
            "project",
            [
                "Compare les indicateurs d’usage de cette période avec la précédente.",
                "La hausse concerne surtout les tâches planifiées ; je vérifie les écarts.",
                "Merci. Garde les chiffres sources avec la synthèse.",
            ],
        ),
        (
            "Suivi du déploiement",
            "project",
            "ops",
            [
                "La nouvelle version peut être déployée après le contrôle final.",
                "Bien reçu. Je lance le contrôle final et je te confirme le résultat ici.",
            ],
        ),
        (
            "Notification de fin d’opération",
            "ops",
            "general",
            [
                "Le contrôle est terminé ; aucun incident n’a été détecté pendant l’opération.",
                "Merci pour le compte rendu, l’opération est clôturée.",
            ],
        ),
    ]
    consult_after = {(0, 0), (0, 1), (1, 0), (1, 1), (3, 0)}
    for index, (subject, first, second, messages) in enumerate(conversations):
        thread = reply_to = None
        for number, text in enumerate(messages):
            sender = (first, second)[number % 2]
            recipient = (second, first)[number % 2]
            clock[0] += 61_000
            result = send(
                mailbox,
                sender,
                recipient,
                text,
                f"demo-{index}-{number}",
                subject=subject if thread is None else None,
                thread=thread,
                reply_to=reply_to,
            )
            thread, reply_to = result["thread_id"], result["message_id"]
            await dispatcher.run_once()
            if (index, number) in consult_after:
                consult(mailbox, recipient, thread)


def main():
    if ROOT not in DEMO.parents:
        raise SystemExit("Demo data path must remain under the project root")
    config = load_config(create_config())
    storage = Storage(config.database)
    storage.initialize()
    config.seed(storage)
    mailbox = Messenger(
        storage,
        config.cursor_key,
        config.resource_uri,
        message_retention_days=config.message_retention_days,
    )
    dispatcher = Dispatcher(
        mailbox, config.destinations, config.cipher, LocalCallbacks()
    )
    events = Events(dispatcher)
    for name, (_, address, _) in AGENTS.items():
        if mailbox.get_account(AGENTS[name][0])["addresses"][0]["address"] != address:
            raise RuntimeError("Demo identity does not match its configured mailbox")
    clock = [int(time.time() * 1000) - 3 * 60 * 60 * 1000]
    asyncio.run(seed(mailbox, events, dispatcher, clock))
    print(f"Synthetic SQLite demo created under {DEMO.relative_to(ROOT)}.")
    print(
        "Mailbox operations use the application domain; callback outcomes are simulated in process."
    )
    print(
        "Run scripts/demo_server.py to view it. The admin password is in the ignored credentials directory."
    )


if __name__ == "__main__":
    main()
