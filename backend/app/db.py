"""Database engine for serverless deployment (Supabase transaction pooler).

Importing this module does NOT create any connections.
"""

import os

from sqlalchemy import create_engine as _sa_create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.pool import NullPool


def normalize_url(url: str) -> str:
    """Ensure the URL uses the ``postgresql+psycopg`` dialect for psycopg 3."""
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    return url


def get_engine(url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine for the Supabase transaction pooler.

    - ``NullPool``: no persistent connections (serverless).
    - ``prepare_threshold=None``: transaction pooler disallows prepared
      statements.

    If *url* is omitted, reads ``DATABASE_URL`` from the environment.
    Raises ``RuntimeError`` when no URL is available.
    """
    if url is None:
        url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "Set it in .env or as an environment variable."
        )
    return _sa_create_engine(
        normalize_url(url),
        poolclass=NullPool,
        connect_args={"prepare_threshold": None},
    )


def validate_test_db_url(
    test_url: str | None, prod_url: str | None
) -> str | None:
    """Validate ``TEST_DATABASE_URL`` for safe test execution.

    Returns the normalised URL, or ``None`` if *test_url* is not set.
    Raises ``RuntimeError`` if *test_url* equals *prod_url* after
    normalisation.
    """
    if not test_url:
        return None
    test_norm = normalize_url(test_url)
    if prod_url and test_norm == normalize_url(prod_url):
        raise RuntimeError(
            "TEST_DATABASE_URL must not equal DATABASE_URL — "
            "refusing to run tests against the production database."
        )
    return test_norm
