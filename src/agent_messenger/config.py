import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from time import monotonic
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
import jwt

from .delivery import Destination
from .storage import Storage
from .webhooks import validate_url, webhook_key

SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,80}")
SAFE_BEARER = re.compile(r"[A-Za-z0-9_=./+-]{24,512}")
AGENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}")
ADDRESS = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}@[a-z0-9][a-z0-9.-]{0,126}")


def configured_message_retention_days(service):
    days = service.get("message_retention_days", 7)
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError("message_retention_days must be an integer between 1 and 365")
    return days


@dataclass(frozen=True)
class Agent:
    id: str
    address: str
    label: str
    mode: str
    principal: str
    enabled: bool = True
    oauth_client_id: str | None = None
    oauth_subject: str | None = None


class _RateLimitedPyJWKClient(jwt.PyJWKClient):
    def __init__(self, uri, *, min_fetch_interval=30, **kwargs):
        super().__init__(uri, **kwargs)
        self._min_fetch_interval = min_fetch_interval
        self._fetch_attempt_lock = Lock()
        self._last_fetch_attempt = None

    def fetch_data(self):
        # PyJWKClient cools down after successful fetches; also bound retries
        # when the endpoint is failing, without falling back to an old pin.
        with self._fetch_attempt_lock:
            now = monotonic()
            if (
                self._last_fetch_attempt is not None
                and now - self._last_fetch_attempt < self._min_fetch_interval
            ):
                raise jwt.PyJWKClientError("JWKS fetch rate limited")
            self._last_fetch_attempt = now
            return super().fetch_data()


@dataclass(frozen=True)
class ProxyOAuth:
    issuer: str
    jwks_client: jwt.PyJWKClient = field(repr=False)
    channel_key: bytes = field(repr=False)
    introspection_port: int
    introspection_credential: bytes = field(repr=False)


@dataclass(frozen=True)
class Config:
    database: Path
    resource_uri: str
    cursor_key: bytes = field(repr=False)
    cipher: Fernet = field(repr=False)
    agents: tuple[Agent, ...] = ()
    destinations: dict[str, Destination] = field(default_factory=dict, repr=False)
    local_tokens: dict[str, str] = field(default_factory=dict, repr=False)
    admin_password: str | None = field(default=None, repr=False)
    proxy_oauth: ProxyOAuth | None = None
    allowed_hosts: tuple[str, ...] = (
        "localhost:*",
        "127.0.0.1:*",
        "localhost",
        "127.0.0.1",
    )
    allowed_origins: tuple[str, ...] = ()
    send_limit: int = 30
    tools_limit: int = 120
    message_retention_days: int = 7

    def seed(self, storage: Storage):
        with storage.transaction() as db:
            db.execute("UPDATE agents SET active=0")
            db.execute("UPDATE principals SET active=0")
            db.execute("UPDATE destinations SET enabled=0")
            for agent in self.agents:
                old = db.execute(
                    "SELECT address,mode FROM agents WHERE id=?", (agent.id,)
                ).fetchone()
                binding = db.execute(
                    "SELECT id FROM principals WHERE agent_id=?", (agent.id,)
                ).fetchone()
                if old and (old["address"], old["mode"]) != (agent.address, agent.mode):
                    raise ValueError("agent ID cannot be reassigned")
                if binding and binding["id"] != agent.principal:
                    raise ValueError(
                        "principal binding change requires a controlled migration"
                    )
                db.execute(
                    """
                    INSERT INTO agents VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                    display_name=excluded.display_name,active=excluded.active
                """,
                    (agent.id, agent.address, agent.label, agent.enabled, agent.mode),
                )
                db.execute(
                    """
                    INSERT INTO principals VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET active=excluded.active
                """,
                    (agent.principal, agent.id, agent.enabled),
                )
                if agent.mode == "webhook":
                    enabled = agent.enabled and agent.id in self.destinations
                    db.execute(
                        """
                        INSERT INTO destinations VALUES (?,?) ON CONFLICT(agent_id) DO UPDATE SET enabled=excluded.enabled
                    """,
                        (agent.id, enabled),
                    )
                    if enabled:
                        db.execute(
                            """
                            UPDATE outbox SET state='queued',error_code=NULL
                            WHERE recipient_agent_id=? AND kind='webhook' AND state='attention'
                              AND (error_code IS NULL OR error_code='destination_unavailable')
                        """,
                            (agent.id,),
                        )


def credential(directory, name, *, systemd_managed=False):
    if (
        not isinstance(name, str)
        or not SAFE_NAME.fullmatch(name)
        or name in {".", ".."}
    ):
        raise ValueError("invalid credential name")
    path = directory / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("credentials require private regular files")
    if systemd_managed:
        # systemd grants the unit UID read access with a POSIX ACL. On ACL-backed
        # filesystems, that ACL is reflected in the group-read mode bit (0440),
        # even though no other user can traverse the per-unit credentials dir.
        configured_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if (
            not configured_dir
            or directory.resolve(strict=True) != Path(configured_dir).resolve(strict=True)
            or metadata.st_mode & 0o027
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o440}
        ):
            raise ValueError("systemd credentials require a private read-only file")
    elif metadata.st_mode & 0o077:
        raise ValueError("credentials require private regular files")
    with path.open("rb") as file:
        value = file.read(8193).strip()
    if not value or len(value) > 8192:
        raise ValueError("invalid credential")
    return value


def load_proxy_oauth(runtime, resource, agents, cursor_key, read):
    enabled = [agent for agent in agents if agent.enabled]
    client_ids = {agent.oauth_client_id for agent in enabled}
    if len(client_ids) != len(enabled) or any(
        not isinstance(agent.oauth_client_id, str)
        or not SAFE_NAME.fullmatch(agent.oauth_client_id)
        or not isinstance(agent.oauth_subject, str)
        or not 1 <= len(agent.oauth_subject) <= 256
        or not agent.oauth_subject.isprintable()
        or agent.oauth_subject != agent.oauth_subject.strip()
        for agent in enabled
    ):
        raise ValueError(
            "each enabled agent needs a distinct OAuth client ID and an approved subject"
        )
    port = runtime["proxy_introspection_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid loopback introspection port")
    # MCP Auth Proxy serves JWKS and introspection on the same loopback port.
    jwks_client = _RateLimitedPyJWKClient(
        f"http://127.0.0.1:{port}/.well-known/jwks.json",
        cache_keys=False,
        cache_jwk_set=True,
        lifespan=300,
        timeout=2,
        cooldown_duration=30,
        min_fetch_interval=30,
    )
    channel = read(runtime["proxy_channel_credential"])
    if not re.fullmatch(rb"[A-Za-z0-9_-]{43,128}", channel) or channel == cursor_key:
        raise ValueError(
            "an independent base64url proxy channel credential is required"
        )
    credential = read(runtime["proxy_introspection_credential"])
    client_id, _, secret = credential.partition(b":")
    if (
        not re.fullmatch(rb"[A-Za-z0-9_.-]{1,80}", client_id)
        or client_id.decode() in client_ids
        or not re.fullmatch(rb"[A-Za-z0-9_=./+-]{24,512}", secret)
        or secret in (channel, cursor_key)
    ):
        raise ValueError(
            "a separate confidential introspection client credential is required"
        )
    return ProxyOAuth(resource, jwks_client, channel, port, credential)


def load_config(path):
    path = Path(path).resolve()
    with path.open("rb") as file:
        raw = tomllib.load(file)
    runtime = raw["service"]
    mode = runtime["mode"]
    if mode not in {"local", "proxy"}:
        raise ValueError("invalid authentication mode")
    if mode == "proxy":
        directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
    else:
        directory = path.parent / runtime["credentials_directory"]

    def read(name):
        return credential(directory, name, systemd_managed=(mode == "proxy"))

    agents = tuple(Agent(**entry) for entry in raw["agents"])
    for agent in agents:
        if (
            not AGENT_ID.fullmatch(agent.id)
            or not ADDRESS.fullmatch(agent.address)
            or agent.mode not in {"mcp_event", "webhook"}
            or not agent.principal.isprintable()
            or not 1 <= len(agent.principal) <= 256
            or not agent.label.isprintable()
            or not 1 <= len(agent.label) <= 80
            or type(agent.enabled) is not bool
        ):
            raise ValueError("invalid agent configuration")
    for key in ("id", "address", "principal"):
        if len({getattr(agent, key) for agent in agents}) != len(agents):
            raise ValueError("duplicate agent configuration")
    destinations = {}
    for agent_id, item in raw.get("webhooks", {}).items():
        if agent_id not in {agent.id for agent in agents if agent.mode == "webhook"}:
            raise ValueError("invalid webhook agent")
        url = read(item["url_credential"]).decode("ascii")
        validate_url(url)
        bearer = (
            read(item["bearer_credential"]).decode("ascii")
            if "bearer_credential" in item
            else None
        )
        if bearer and not SAFE_BEARER.fullmatch(bearer):
            raise ValueError("invalid receiver credential")
        destinations[agent_id] = Destination(
            url, webhook_key(read(item["secret_credential"]).decode("ascii")), bearer
        )
    tokens = {
        subject: read(name).decode("ascii")
        for subject, name in raw.get("local_tokens", {}).items()
    }
    if tokens and mode != "local":
        raise ValueError("local credentials are disabled in proxy mode")
    if (
        not set(tokens) <= {agent.principal for agent in agents}
        or any(not SAFE_BEARER.fullmatch(token) for token in tokens.values())
        or len(set(tokens.values())) != len(tokens)
    ):
        raise ValueError("invalid local credentials")
    resource = runtime["resource_uri"]
    parsed = urlsplit(resource)
    if (
        parsed.scheme not in ({"https"} if mode == "proxy" else {"http", "https"})
        or not parsed.hostname
        or parsed.path != ("/" if mode == "proxy" else "/mcp")
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
    ):
        raise ValueError("invalid MCP resource URI")
    cursor_key = read(runtime["cursor_credential"])
    if len(cursor_key) < 32:
        raise ValueError("a cursor signing credential of at least 32 bytes is required")
    proxy_oauth = (
        load_proxy_oauth(runtime, resource, agents, cursor_key, read)
        if mode == "proxy"
        else None
    )
    password = None
    if "admin_credential" in runtime:
        password = read(runtime["admin_credential"]).decode("ascii")
        if not SAFE_BEARER.fullmatch(password) or password in tokens.values():
            raise ValueError("invalid admin credential")
    limits = raw.get("limits", {})
    counts = [limits.get("send_per_minute", 30), limits.get("tools_per_minute", 120)]
    if any(type(count) is not int or not 1 <= count <= 10_000 for count in counts):
        raise ValueError("invalid rate limits")
    retention_days = configured_message_retention_days(runtime)
    default_hosts = (*Config.allowed_hosts, parsed.netloc)
    return Config(
        database=path.parent / runtime["database"],
        resource_uri=resource,
        cursor_key=cursor_key,
        cipher=Fernet(read(runtime["encryption_credential"])),
        agents=agents,
        destinations=destinations,
        local_tokens=tokens,
        admin_password=password,
        proxy_oauth=proxy_oauth,
        allowed_hosts=tuple(runtime.get("allowed_hosts", default_hosts)),
        allowed_origins=tuple(runtime.get("allowed_origins", ())),
        send_limit=counts[0],
        tools_limit=counts[1],
        message_retention_days=retention_days,
    )
