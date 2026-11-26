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

In proxy mode, Agent Messenger independently validates RS256 access tokens using
the public key configured by `proxy_public_key_credential`, then checks token
introspection and the approved OAuth client/subject mapping. Rotating the
authorization proxy's RSA signing key therefore requires a coordinated update
of the backend's trusted public key. With the example systemd unit, this key is
provided as `proxy-oauth-public-key.pem` via `LoadCredential`. Replacing its source
file alone does not refresh the running service's credentials.

### Rotation checklist

Perform the rotation during a maintenance window. Follow the authorization
proxy's supported rotation procedure and plan for existing tokens signed by
retired keys to become unusable.

1. Identify the active signing key of the correct proxy instance. Obtain its
   public key through a trusted administrative channel and verify that it
   matches the active proxy's published signing key (JWKS, if available). Do
   not copy or expose the private signing key.
2. Compare the SHA-256 fingerprints of the expected public key and the
   Messenger credential source file. For PEM public keys, compare the canonical
   DER SubjectPublicKeyInfo encoding rather than the raw PEM text.
3. If the keys differ, back up the existing public credential and atomically
   install the verified replacement, preserving ownership, permissions and
   applicable security attributes. Do not change the channel or introspection
   credentials unless those are independently being rotated.
4. Restart the Messenger service to reload its systemd credentials. For the
   example deployment, use `sudo systemctl restart agent-messenger.service`.
   Adapt the unit name to your installation. Expect a brief interruption.
5. Verify that the service is running and that its loaded public credential
   matches the active signing key. If the loaded credential cannot be inspected,
   treat that check as incomplete.
6. Test an authorized client's MCP connection and a read-only `get_account`
   call; verify the returned mailbox identity. Test each relevant client
   independently and confirm that an unauthenticated MCP initialization still
   receives HTTP 401. Observe token renewal separately.

For example, to fingerprint two PEM public-key files using OpenSSL, substitute
your actual paths:

```sh
set -o pipefail
openssl pkey -pubin -in /path/to/verified-proxy-public-key.pem -outform DER | sha256sum
openssl pkey -pubin -in /path/to/messenger-public-key.pem -outform DER | sha256sum
```

Run these commands in Bash and check their exit status; a failed OpenSSL
command must not be interpreted as a valid fingerprint. The first file must
already have been verified against the active signing key.

### Troubleshooting repeated OAuth authorization

If authorization and token issuance succeed but subsequent MCP requests return
HTTP 401, a client may repeatedly initiate OAuth authorization. Before
re-registering clients or changing mailbox ACLs, correlate proxy and backend
logs to distinguish token issuance failures from backend authentication
failures. Check the signing-key fingerprints and loaded credential first,
especially after a rotation or proxy upgrade. Other possible causes include a
channel credential mismatch, invalid token claims, failed introspection, or
an unapproved client/subject mapping.

Do not bypass signature verification, introspection, channel authentication or
mailbox ACLs to resolve a 401. Do not restore a retired signing key merely to
make stale tokens work. If the active signing key cannot be verified, stop and
investigate before changing the trusted credential. Redact authorization
codes, bearer tokens, secrets and message contents from diagnostic reports.
