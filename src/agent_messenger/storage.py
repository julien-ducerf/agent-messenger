import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Storage:
    def __init__(self, path: Path):
        self.path = path

    def initialize(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.stat().st_mode & 0o077:
            raise ValueError("database directory must be private (0700)")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise ValueError("database file must be private (0600)")
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            paths = sorted(Path(__file__).with_name("migrations").glob("*.sql"))
            if version > len(paths):
                raise ValueError("database schema is newer than this application")
            for expected, path in enumerate(paths, start=1):
                migration = int(path.name.split("_")[0])
                if migration != expected:
                    raise ValueError("migration sequence is incomplete")
                if migration <= version:
                    continue
                statement = ""
                for line in path.read_text().splitlines(keepends=True):
                    statement += line
                    if sqlite3.complete_statement(statement):
                        db.execute(statement)
                        statement = ""
                if statement.strip():
                    raise ValueError("migration ends with an incomplete statement")
                db.execute(f"PRAGMA user_version={migration}")
            db.commit()

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=4, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA secure_delete=ON")
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self, write=True):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
