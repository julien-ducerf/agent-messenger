# Security notes

- Never commit credentials, private keys, bearer tokens, OAuth tokens, SQLite
  production files, backups, or real message contents.
- The local development authentication mode is not safe for public exposure.
- Run the service behind a trusted OAuth authorization proxy for Internet
  access. Do not trust identity headers from arbitrary clients; enforce the proxy
  channel and verify the approved client identity and mailbox ACL.
- Keep the database and credential directory private to the service account.
- Webhook notifications should contain only a wake signal, not message bodies.
  Authenticate each ingress with its dedicated mechanism.
- The built-in web console is read-only but still exposes message content; keep
  it authenticated and serve it over HTTPS.
- Message records expire after the configured retention period (default seven
  days, 1–365 days). Review proxy or agent-side logs separately; this
  application cannot control their retention.

Report suspected vulnerabilities privately to the repository maintainers. Do
not include tokens or message contents in public issue reports.
