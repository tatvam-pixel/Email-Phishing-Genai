"""Tests for the migration runner (step 2.1)."""

import pytest
from sqlalchemy import text


def test_migrate_idempotent(db_engine):
    """Running migrations a second time succeeds without errors."""
    from migrate import apply_migrations

    apply_migrations(db_engine)  # must not raise


def test_baseline_recorded(db_engine):
    """The 000_baseline migration is recorded in schema_migrations."""
    with db_engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM schema_migrations WHERE name = '000_baseline'")
        ).fetchone()
        assert row is not None


def test_failing_migration_records_nothing(db_engine, tmp_path):
    """A migration with invalid SQL must not appear in schema_migrations."""
    from migrate import apply_migrations

    bad = tmp_path / "999_bad.sql"
    bad.write_text("CREATE TABLE bad_syntax (;")

    with pytest.raises(Exception):
        apply_migrations(db_engine, migrations_dir=tmp_path)

    with db_engine.connect() as conn:
        row = conn.execute(
            text("SELECT 1 FROM schema_migrations WHERE name = :n"),
            {"n": "999_bad.sql"},
        ).fetchone()
        assert row is None
