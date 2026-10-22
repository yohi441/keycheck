"""Minimal, idempotent schema migrations.

Why this exists
---------------
`Base.metadata.create_all()` only creates tables that are *missing*. It will
never add a column to a table that already exists, so a server running the old
schema would silently keep the old shape and then fail at query time with
"no such column". There is no Alembic here, and introducing one for a handful
of additive columns would be more moving parts than the problem is worth.

So: this module applies plain `ALTER TABLE ... ADD COLUMN` statements, skipping
any that are already present. It is safe to run on every startup, and safe to
run on a fresh database (where `create_all` has already built the full, current
schema and every statement is skipped).

SQLite notes
------------
* `ADD COLUMN` is supported and is cheap -- it does not rewrite the table.
* A column added this way cannot have a non-constant default, but every column
  here takes a constant (`'random'`) or is nullable, so that is fine.
* Adding a UNIQUE column is NOT possible via ALTER TABLE, which is why the
  widened `key` column is only widened in the fresh-schema path. SQLite ignores
  length limits on TEXT anyway, so an existing `VARCHAR(19)` column stores
  longer signed keys correctly without alteration. That is load-bearing, not an
  accident: see `_widen_key_column` for the explicit handling.
"""

import logging

from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

# (table, column, DDL type+default) for every column added after the first
# release. Order does not matter; each is checked individually.
_ADDED_COLUMNS = [
    ("license_keys", "kind",
     "VARCHAR(10) DEFAULT 'random'"),
    ("license_keys", "clinic",
     "VARCHAR(200)"),
    ("license_keys", "serial",
     "VARCHAR(50)"),
    ("license_keys", "machine_code",
     "VARCHAR(32)"),
    ("license_keys", "activated_at",
     "DATETIME"),
]


def _existing_columns(connection, table):
    return {col["name"] for col in inspect(connection).get_columns(table)}


def _table_exists(connection, table):
    return table in inspect(connection).get_table_names()


def run_migrations(engine):
    """Bring an existing database up to the current schema. Never raises.

    A failure here must not stop the service from starting: a half-migrated
    database still serves the endpoints that do not need the new columns, and a
    crashed startup would take down key checking entirely. Problems are logged
    loudly instead.
    """
    try:
        with engine.begin() as connection:
            if not _table_exists(connection, "license_keys"):
                # Fresh database: create_all already made the current schema.
                logger.info("migrations: license_keys absent, nothing to do")
                return

            present = _existing_columns(connection, "license_keys")
            for table, column, ddl in _ADDED_COLUMNS:
                if column in present:
                    continue
                connection.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
                logger.info("migrations: added %s.%s", table, column)

            # Backfill: every pre-existing row is an original random key.
            # The DEFAULT above covers new rows; this covers old ones.
            connection.execute(text(
                "UPDATE license_keys SET kind = 'random' WHERE kind IS NULL"))
    except Exception:
        logger.exception("migrations: schema migration failed")


def schema_problems(engine):
    """Return a list of missing columns, for a startup self-check.

    Used by /health so a deployment running against a stale schema is visible
    immediately rather than discovered when a customer's key is issued.
    """
    try:
        with engine.connect() as connection:
            if not _table_exists(connection, "license_keys"):
                return ["license_keys table is missing"]
            present = _existing_columns(connection, "license_keys")
        return [f"license_keys.{col} is missing"
                for _, col, _ in _ADDED_COLUMNS if col not in present]
    except Exception as exc:
        return [f"could not inspect schema: {exc}"]
