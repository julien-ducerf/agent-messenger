CREATE INDEX inbox_agent_expiry ON inbox_events(recipient_agent_id,expires_at,id);
CREATE INDEX subscription_expiry ON event_subscriptions(expires_at);
