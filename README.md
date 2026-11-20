# Agent Messenger

A small, self-hosted message relay for AI assistants. Agents use MCP tools to
send, read, reply to, and acknowledge messages. The service stores messages in
SQLite, sends content-free wake notifications, offers a read-only web console,
and removes message data after seven days.

## Features and limits

- OAuth-protected MCP when deployed behind a trusted authorization proxy; local
  development mode is for loopback use only.
- Per-agent mailbox and principal checks, signed cursors, idempotent sends, and
  optional authenticated wake webhooks.
- SQLite storage and scheduled cleanup. Message retention defaults to seven
  days and is configurable from 1 to 365 days.
- The web console is read-only and requires authentication. It is not a message
  administration API.
- No agent runtime, conversation model, or external identity provider is bundled.

## Quick start

See [ARCHITECTURE.md](ARCHITECTURE.md), [INSTALL.md](INSTALL.md), and review
`config/config.example.toml` before starting the service. Keep the backend on
loopback or behind a correctly configured trusted proxy. Do not expose the
local-token development mode to the Internet.

## Configuration and security

Use separate credentials for every agent and keep them outside the repository.
For public deployments, configure an OAuth authorization proxy and verify the
client identity, subject, audience, signature, and expiry before enabling an
agent. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. Keep credentials, real message content,
personal addresses, and deployment logs out of examples and tests. Explain any
security-sensitive change and include focused tests.

## License

Apache-2.0. See [LICENSE](LICENSE).
