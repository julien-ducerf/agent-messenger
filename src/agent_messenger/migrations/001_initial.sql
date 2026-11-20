CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0,1)),
    mode TEXT NOT NULL CHECK (mode IN ('webhook','mcp_event'))
);
CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL UNIQUE REFERENCES agents(id),
    active INTEGER NOT NULL CHECK (active IN (0,1))
);
CREATE TABLE threads (
    number INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    subject TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE thread_participants (
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    satisfied INTEGER NOT NULL DEFAULT 0 CHECK (satisfied IN (0,1)),
    PRIMARY KEY (thread_id, agent_id)
);
CREATE INDEX participant_agent ON thread_participants(agent_id, thread_id);
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    sender_agent_id TEXT NOT NULL REFERENCES agents(id),
    reply_to TEXT REFERENCES messages(id) ON DELETE SET NULL,
    body TEXT NOT NULL CHECK (length(CAST(body AS BLOB)) BETWEEN 1 AND 65536),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE (thread_id, seq)
);
CREATE INDEX message_expiry ON messages(expires_at);
CREATE TABLE inbox_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_agent_id TEXT NOT NULL REFERENCES agents(id),
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    UNIQUE (recipient_agent_id, message_id)
);
CREATE INDEX inbox_agent ON inbox_events(recipient_agent_id, id);
CREATE INDEX inbox_expiry ON inbox_events(expires_at);
CREATE TABLE inbox_positions (
    principal_id TEXT PRIMARY KEY REFERENCES principals(id),
    handled_through INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE inbox_floor (
    agent_id TEXT PRIMARY KEY REFERENCES agents(id),
    expired_through INTEGER NOT NULL
);
CREATE TABLE inbox_fetches (
    principal_id TEXT NOT NULL REFERENCES principals(id),
    event_id INTEGER NOT NULL REFERENCES inbox_events(id) ON DELETE CASCADE,
    fetched_at INTEGER NOT NULL,
    PRIMARY KEY (principal_id, event_id)
);
CREATE INDEX fetch_event ON inbox_fetches(event_id);
CREATE TABLE idempotency_receipts (
    principal_id TEXT NOT NULL REFERENCES principals(id),
    key TEXT NOT NULL,
    digest TEXT NOT NULL,
    receipt TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (principal_id, key)
);
CREATE INDEX receipt_expiry ON idempotency_receipts(expires_at);
CREATE TABLE destinations (
    agent_id TEXT PRIMARY KEY REFERENCES agents(id),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1))
);
CREATE TABLE event_subscriptions (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
    encrypted_callback BLOB NOT NULL,
    encrypted_secret BLOB NOT NULL,
    verified_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX subscription_agent ON event_subscriptions(agent_id, active, expires_at);
CREATE TABLE outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES inbox_events(id) ON DELETE CASCADE,
    recipient_agent_id TEXT NOT NULL REFERENCES agents(id),
    destination_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('webhook','mcp_event')),
    notification_id TEXT NOT NULL,
    notification_time INTEGER,
    state TEXT NOT NULL CHECK (state IN ('queued','retrying','wake_accepted','attention')),
    attempts INTEGER NOT NULL DEFAULT 0,
    due_at INTEGER NOT NULL,
    last_attempt_at INTEGER,
    accepted_at INTEGER,
    http_status INTEGER,
    error_code TEXT,
    UNIQUE (event_id, destination_id)
);
CREATE INDEX outbox_due ON outbox(state, due_at);
CREATE INDEX outbox_destination ON outbox(destination_id, state, id);
CREATE INDEX outbox_agent ON outbox(recipient_agent_id, last_attempt_at);
