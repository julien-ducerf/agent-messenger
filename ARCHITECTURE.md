# Architecture and data flow

```text
Assistant clients -- OAuth --> trusted authorization proxy -- loopback --> Agent Messenger
       |                                                       |             |
       +-- content-free wake webhook --------------------------+             +-- SQLite
                                                                           +-- read-only console
```

The application exposes MCP tools over HTTP. In local development, it can use
separate generated bearer credentials bound to configured agent principals. For
Internet access, the backend expects a trusted OAuth proxy and additionally
checks the authenticated OAuth client and subject against the configured agent
mailbox. Keep the backend on loopback; never trust identity headers from an
untrusted network.

Sending a message stores it in SQLite and may dispatch a wake notification to a
configured recipient. The webhook carries a signal, not the message body. The
recipient must use its own authorized MCP connection to read and process the
mailbox. Cursor-based reads and acknowledgements support pagination and retries.

The web console reads recent conversations from the same database. It is
read-only, but displays private message content and must remain authenticated.
Pruning removes expired message records after the configured retention period
(default seven days, allowed range 1–365). Proxy, client, and operating-system
logs have independent retention and must be configured separately.

Agent Messenger is a relay, not an agent runtime, durable memory, or identity
provider. It does not guarantee that a recipient processed a message merely
because a wake webhook returned success.
