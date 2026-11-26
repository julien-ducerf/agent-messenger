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

## OAuth proxy version requirement

Use [mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy) v2.10.3 or
later, with v2.11.0 as a validated deployment reference. Prefer a currently
maintained release after compatibility and security checks. Do not deploy
v2.10.2: it has an authentication bypass fixed in
[v2.10.3](https://github.com/sigbit/mcp-auth-proxy/releases/tag/v2.10.3).
Existing deployments on affected versions should upgrade and review potentially
issued tokens and the need for coordinated credential rotation.

## OAuth proxy signing-key rotation

In proxy mode, Agent Messenger obtains RS256 verification keys from the local
JWKS endpoint `http://127.0.0.1:<proxy_introspection_port>/.well-known/jwks.json`.
It then validates the token and checks proxy introspection plus the approved
OAuth client/subject mapping. The backend no longer pins a PEM public key:
`proxy_public_key_credential` and `proxy-oauth-public-key.pem` are not required
by this configuration. Do not add a private signing key or production runtime
credential to this repository.

The backend caches the JWKS for up to five minutes and rate-limits refresh
attempts to at most one per 30 seconds. A newly published signing key may
therefore take up to five minutes to be observed; failed JWKS retrieval does not
fall back to a pinned or stale PEM key.

### Rotation checklist

Follow the authorization proxy's supported rotation procedure. Preserve any
signing-key overlap needed for still-valid tokens according to that procedure;
do not change OAuth clients, channel credentials, or mailbox ACLs as part of a
key rotation.

1. Identify the exact proxy instance used by Messenger and confirm that its
   loopback JWKS endpoint is reachable from the Messenger service environment.
2. Use the proxy's supported key-rotation procedure. Never copy or expose the
   private signing key. Confirm that the published JWKS contains the expected
   public key and key identifier (`kid`) without exposing tokens or secrets.
3. Allow the backend JWKS cache to refresh (up to five minutes). If it does not,
   inspect the proxy and backend logs for JWKS retrieval, key-id, signature, or
   introspection errors before changing configuration.
4. Verify the Messenger service is healthy. Test an authorized client's MCP
   connection and a read-only `get_account` call; verify the returned mailbox
   identity. Test relevant clients independently and confirm that an
   unauthenticated MCP initialization still receives HTTP 401. Observe token
   renewal separately.

### Troubleshooting repeated OAuth authorization

If authorization and token issuance succeed but subsequent MCP requests return
HTTP 401, a client may repeatedly initiate OAuth authorization. Before
re-registering clients or changing mailbox ACLs, correlate proxy and backend
logs to distinguish token issuance failures from backend authentication
failures. Check that the backend can retrieve the current JWKS and that the
signing key's `kid` is present; then investigate signature, token claims,
introspection, channel credentials, and the approved client/subject mapping.

Do not bypass signature verification, introspection, channel authentication or
mailbox ACLs to resolve a 401. Do not restore a retired signing key merely to
make stale tokens work. Redact authorization codes, bearer tokens, secrets and
message contents from diagnostic reports.
