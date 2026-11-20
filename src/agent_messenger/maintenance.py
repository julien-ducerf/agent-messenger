import argparse
import json
import os
import tomllib
from pathlib import Path

from .config import load_config
from .domain import now_ms
from .storage import Storage


def prune(storage, now):
    with storage.transaction() as db:
        db.execute(
            """
            INSERT INTO inbox_floor SELECT recipient_agent_id,max(id) FROM inbox_events
            WHERE expires_at<=? GROUP BY recipient_agent_id
            ON CONFLICT(agent_id) DO UPDATE SET expired_through=max(expired_through,excluded.expired_through)
        """,
            (now,),
        )
        deleted = db.execute(
            "DELETE FROM messages WHERE expires_at<=?", (now,)
        ).rowcount
        db.execute(
            "DELETE FROM threads WHERE expires_at<=? AND NOT EXISTS "
            "(SELECT 1 FROM messages WHERE thread_id=threads.id)",
            (now,),
        )
        db.execute("DELETE FROM idempotency_receipts WHERE expires_at<=?", (now,))
        db.execute("DELETE FROM event_subscriptions WHERE expires_at<=?", (now,))
    if deleted:
        checkpoint(storage)
    return deleted


def checkpoint(storage):
    with storage.connection() as db:
        return tuple(db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prune", "checkpoint", "check", "init"])
    parser.add_argument("--config", default=os.environ.get("AGENT_MESSENGER_CONFIG"))
    args = parser.parse_args()
    if not args.config:
        parser.error("specify --config or AGENT_MESSENGER_CONFIG")
    path = Path(args.config).resolve()
    with path.open("rb") as file:
        database = path.parent / tomllib.load(file)["service"]["database"]
    storage = Storage(database)
    if args.action == "init":
        config = load_config(path)
        storage.initialize()
        config.seed(storage)
        print(json.dumps({"initialized": True}))
        return
    if not storage.path.is_file():
        parser.error("database does not exist")
    if args.action == "prune":
        print(json.dumps({"expired_messages_removed": prune(storage, now_ms())}))
    elif args.action == "checkpoint":
        busy, pages, flushed = checkpoint(storage)
        print(json.dumps({"busy": busy, "pages": pages, "flushed": flushed}))
        if busy:
            raise SystemExit(1)
    else:
        with storage.transaction(write=False) as db:
            healthy = [row[0] for row in db.execute("PRAGMA quick_check")] == ["ok"]
            print(
                json.dumps(
                    {
                        "healthy": healthy,
                        "schema": db.execute("PRAGMA user_version").fetchone()[0],
                    }
                )
            )
            if not healthy:
                raise SystemExit(1)


if __name__ == "__main__":
    main()
