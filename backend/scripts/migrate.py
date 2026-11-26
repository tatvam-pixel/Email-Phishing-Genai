"""Schema migration runner for PhishGuard AI.

Usage::

    python scripts/migrate.py --target test   # uses TEST_DATABASE_URL
    python scripts/migrate.py --target prod   # uses DATABASE_URL

Exposes ``apply_migrations(engine)`` for programmatic use (e.g. test
fixtures).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine

# Resolve paths relative to *this file* so they work regardless of cwd.
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent.parent  # scripts -> backend -> project root
_SCHEMA_SQL = _PROJECT_ROOT / "db" / "schema.sql"
_MIGRATIONS_DIR = _PROJECT_ROOT / "db" / "migrations"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_migrations(
    engine: Engine,
    *,
    schema_path: Path | None = None,
    migrations_dir: Path | None = None,
) -> None:
    """Apply all pending migrations to the database.

    1. Ensure the ``schema_migrations`` bookkeeping table exists.
    2. Apply ``db/schema.sql`` as ``000_baseline`` in autocommit mode
       (the file contains its own ``BEGIN`` / ``COMMIT``).
    3. Apply each ``db/migrations/*.sql`` in sorted order, each wrapped
       in a single transaction together with its bookkeeping record.
    """
    schema_path = schema_path or _SCHEMA_SQL
    migrations_dir = migrations_dir or _MIGRATIONS_DIR

    # 1. Bookkeeping table
    with engine.connect() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "name TEXT PRIMARY KEY, "
            "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        ))
        conn.commit()

    # 2. Baseline (schema.sql has its own BEGIN/COMMIT)
    if not _is_applied(engine, "000_baseline"):
        sql = schema_path.read_text(encoding="utf-8")
        _run_autocommit(engine, sql)
        _record(engine, "000_baseline")

    # 3. Incremental migration files
    if not migrations_dir.exists():
        return
    for mf in sorted(migrations_dir.glob("*.sql")):
        name = mf.name
        if _is_applied(engine, name):
            continue
        sql = mf.read_text(encoding="utf-8")
        _run_in_transaction(engine, name, sql)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_applied(engine: Engine, name: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM schema_migrations WHERE name = :n"),
            {"n": name},
        ).fetchone()
        return row is not None


def _run_autocommit(engine: Engine, sql: str) -> None:
    """Execute a multi-statement SQL script in autocommit mode via raw DBAPI."""
    raw = engine.raw_connection()
    try:
        dbapi_conn = raw.dbapi_connection
        dbapi_conn.autocommit = True
        dbapi_conn.execute(sql)
    finally:
        raw.close()


def _record(engine: Engine, name: str) -> None:
    """Record a migration as applied (separate transaction)."""
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO schema_migrations (name) VALUES (:n)"),
            {"n": name},
        )
        conn.commit()


def _run_in_transaction(engine: Engine, name: str, sql: str) -> None:
    """Execute a migration file and record it in one transaction.

    Uses the raw DBAPI connection so multi-statement SQL is supported
    via the simple query protocol (psycopg 3 / PQexec).
    """
    raw = engine.raw_connection()
    dbapi_conn = raw.dbapi_connection
    try:
        dbapi_conn.execute(sql)
        dbapi_conn.execute(
            "INSERT INTO schema_migrations (name) VALUES (%s)", (name,)
        )
        dbapi_conn.commit()
    except Exception:
        dbapi_conn.rollback()
        raise
    finally:
        raw.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Run database migrations")
    parser.add_argument(
        "--target",
        choices=["test", "prod"],
        required=True,
        help="'test' uses TEST_DATABASE_URL; 'prod' uses DATABASE_URL",
    )
    args = parser.parse_args()

    from dotenv import load_dotenv
    load_dotenv()

    import os
    env_var = "TEST_DATABASE_URL" if args.target == "test" else "DATABASE_URL"
    url = os.environ.get(env_var)
    if not url:
        print(f"Error: {env_var} is not set.", file=sys.stderr)
        sys.exit(1)

    # Add backend/ to sys.path so we can import app.db
    sys.path.insert(0, str(_SCRIPT_DIR.parent))
    from app.db import get_engine

    engine = get_engine(url)
    print(f"Applying migrations to {args.target} database...")
    apply_migrations(engine)
    print("Done.")
    engine.dispose()


if __name__ == "__main__":
    main()
