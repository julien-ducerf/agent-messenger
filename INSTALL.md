# Installation

## Local development

Requirements: Python 3.12+, SQLite, and `uv`.

```sh
uv sync --locked
uv run --locked python scripts/local_setup.py
AGENT_MESSENGER_CONFIG=.local/config.toml uv run --locked uvicorn \
  agent_messenger.app:create_app --factory --host 127.0.0.1 --port 8765 \
  --workers 1 --no-proxy-headers --no-access-log
```

The local setup creates local-only credentials. Keep the service bound to
`127.0.0.1`; the local-token mode is not Internet authentication.

## Linux service outline

The `deploy/` directory contains systemd and reverse-proxy examples. Review and
adapt every path, service account, hostname, credential name, and OAuth-proxy
setting before use. Put credentials in root-owned files with restrictive
permissions and make them readable only through the service manager's credential
mechanism. Run the backend on loopback and terminate HTTPS at a maintained reverse
proxy. Do not copy a production configuration from another installation.

The application initializes its SQLite schema at startup. Use the included
scheduled maintenance unit for pruning; do not create an empty database by hand.

Before an Internet-facing deployment, verify OAuth discovery, unauthenticated
MCP denial, protected console routes, agent-to-mailbox ACLs, webhook
authentication, and a tested rollback on your own host. These examples are
templates, not a turnkey hosted service.
