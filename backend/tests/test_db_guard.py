"""Tests for the database URL validation guard (step 2.2)."""

import pytest

from app.db import validate_test_db_url


def test_refuses_when_test_url_equals_prod():
    url = "postgresql://user:pass@host:5432/db"
    with pytest.raises(RuntimeError, match="must not equal"):
        validate_test_db_url(url, url)


def test_refuses_after_normalization():
    """postgres:// and postgresql:// normalise to the same dialect URL."""
    with pytest.raises(RuntimeError, match="must not equal"):
        validate_test_db_url(
            "postgresql://host/db",
            "postgres://host/db",
        )


def test_returns_none_when_test_url_missing():
    assert validate_test_db_url(None, "postgresql://host/db") is None


def test_returns_none_when_test_url_empty():
    assert validate_test_db_url("", "postgresql://host/db") is None


def test_normalizes_returned_url():
    result = validate_test_db_url("postgresql://host/db", "postgresql://other/db")
    assert result == "postgresql+psycopg://host/db"


def test_accepts_when_prod_url_is_none():
    result = validate_test_db_url("postgresql://host/db", None)
    assert result == "postgresql+psycopg://host/db"
