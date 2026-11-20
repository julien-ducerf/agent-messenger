import sqlite3

from agent_messenger.storage import Storage


def test_initialize_creates_schema_without_resetting_existing_database(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    database = state_dir / "messages.sqlite3"
    storage = Storage(database)

    assert not database.exists()
    storage.initialize()
    assert database.is_file()

    with sqlite3.connect(database) as db:
        schema_version = db.execute("PRAGMA user_version").fetchone()[0]
        assert schema_version > 0
        db.execute("CREATE TABLE recovery_sentinel (value TEXT NOT NULL)")
        db.execute("INSERT INTO recovery_sentinel VALUES ('keep')")

    storage.initialize()
    with sqlite3.connect(database) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == schema_version
        assert db.execute("SELECT value FROM recovery_sentinel").fetchone() == ("keep",)
