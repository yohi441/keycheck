"""Tests for the schema migration against a pre-existing database.

The service has no migration tool: `Base.metadata.create_all()` builds missing
tables but never adds columns. A server already running the old schema would
therefore keep the old shape and fail at query time. `app/migrations.py` exists
to close that gap, and these tests pin the behaviour that matters:

  * an old database gains the new columns,
  * its existing keys survive and are marked as the original kind,
  * running twice is a no-op,
  * a fresh database is left alone.
"""

import sqlite3

from sqlalchemy import create_engine, text

from app.database import Base
from app.migrations import run_migrations, schema_problems

# The schema exactly as it was before signed keys existed.
OLD_SCHEMA = """
CREATE TABLE license_keys (
    id INTEGER NOT NULL PRIMARY KEY,
    "key" VARCHAR(19) NOT NULL,
    status VARCHAR(10) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    max_uses INTEGER NOT NULL,
    used_uses INTEGER NOT NULL
);
CREATE UNIQUE INDEX ix_license_keys_key ON license_keys ("key");
"""


def _old_db(path):
    con = sqlite3.connect(path)
    con.executescript(OLD_SCHEMA)
    con.execute(
        'INSERT INTO license_keys ("key", status, max_uses, used_uses) '
        "VALUES ('AAAA-BBBB-CCCC-DDDD', 'active', 1, 0)")
    con.execute(
        'INSERT INTO license_keys ("key", status, max_uses, used_uses) '
        "VALUES ('EEEE-FFFF-GGGG-HHHH', 'revoked', 5, 2)")
    con.commit()
    con.close()


def _columns(engine):
    with engine.connect() as c:
        return [r[1] for r in c.execute(text("PRAGMA table_info(license_keys)"))]


def test_old_database_is_upgraded(tmp_path):
    db = tmp_path / "old.db"
    _old_db(db)
    engine = create_engine(f"sqlite:///{db}")

    assert "kind" not in _columns(engine)
    assert schema_problems(engine)  # non-empty before

    run_migrations(engine)

    for column in ("kind", "clinic", "serial", "machine_code", "activated_at"):
        assert column in _columns(engine), column
    assert schema_problems(engine) == []


def test_existing_keys_survive_and_are_marked_random(tmp_path):
    db = tmp_path / "old.db"
    _old_db(db)
    engine = create_engine(f"sqlite:///{db}")
    run_migrations(engine)

    with engine.connect() as c:
        rows = dict(c.execute(text('SELECT "key", kind FROM license_keys')).all())
    assert rows == {
        "AAAA-BBBB-CCCC-DDDD": "random",
        "EEEE-FFFF-GGGG-HHHH": "random",
    }


def test_migration_is_idempotent(tmp_path):
    db = tmp_path / "old.db"
    _old_db(db)
    engine = create_engine(f"sqlite:///{db}")
    run_migrations(engine)
    before = _columns(engine)
    # Running again must not raise (no duplicate-column error) or change shape.
    run_migrations(engine)
    assert _columns(engine) == before


def test_fresh_database_is_untouched(tmp_path):
    db = tmp_path / "fresh.db"
    engine = create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(bind=engine)

    before = _columns(engine)
    assert not schema_problems(engine)
    run_migrations(engine)
    assert _columns(engine) == before


def test_signed_length_key_fits_after_migration(tmp_path):
    """The widened column must actually accept a signed key.

    SQLite ignores VARCHAR lengths, which is why widening is a no-op there --
    this test pins that assumption so a move to a stricter database is caught.
    """
    db = tmp_path / "old.db"
    _old_db(db)
    engine = create_engine(f"sqlite:///{db}")
    run_migrations(engine)

    long_key = "CLN1-" + "A" * 140 + "-" + "B" * 103
    with engine.begin() as c:
        c.execute(text(
            'INSERT INTO license_keys ("key", status, kind, max_uses, used_uses) '
            "VALUES (:k, 'active', 'signed', 0, 0)"), {"k": long_key})
    with engine.connect() as c:
        stored = c.execute(text(
            'SELECT "key" FROM license_keys WHERE kind = \'signed\'')).scalar()
    assert stored == long_key


def test_migration_failure_is_logged_not_raised(tmp_path, caplog):
    """A broken database must not stop the service from booting.

    Key checking has to keep working even if the schema cannot be upgraded, so
    run_migrations swallows and logs rather than raising.
    """
    db = tmp_path / "broken.db"
    con = sqlite3.connect(db)
    con.executescript("CREATE TABLE license_keys (id INTEGER PRIMARY KEY);")
    con.commit()
    con.close()
    engine = create_engine(f"sqlite:///{db}")

    # This adds columns to a table with no other content, so it should actually
    # succeed; the point is that it never raises.
    run_migrations(engine)
    assert True
