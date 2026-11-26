import os
import sys
from pathlib import Path

# Set ENV before any app import — tests must not load .env
os.environ.setdefault("ENV", "test")

import pytest  # noqa: E402
from dotenv import dotenv_values, find_dotenv  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app import create_app  # noqa: E402
from app.db import get_engine, validate_test_db_url  # noqa: E402

# Allow importing app and scripts/migrate.py from any directory
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
_SCRIPTS_DIR = _BACKEND_DIR / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

# Read .env without polluting os.environ
_env_path = find_dotenv()
_dotenv = dotenv_values(_env_path) if _env_path else {}
_TEST_DB_URL = os.environ.get("TEST_DATABASE_URL") or _dotenv.get("TEST_DATABASE_URL")
_PROD_DB_URL = os.environ.get("DATABASE_URL") or _dotenv.get("DATABASE_URL")

# Hard fail if TEST equals PROD
_checked_url = validate_test_db_url(_TEST_DB_URL, _PROD_DB_URL)

# All 10 app tables (never schema_migrations)
_APP_TABLES = [
    "webhook_deliveries", "webhooks", "ai_analyses", "scan_evidence",
    "scan_urls", "scans", "api_usage_logs", "rate_limit_counters",
    "api_keys", "users",
]


@pytest.fixture(scope="session")
def db_engine():
    if _checked_url is None:
        pytest.skip("TEST_DATABASE_URL not set; skipping DB tests")
    engine = get_engine(_checked_url)
    from migrate import apply_migrations
    apply_migrations(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def truncate_tables(db_engine):
    """Truncate all app tables with RESTART IDENTITY CASCADE."""
    with db_engine.connect() as conn:
        conn.execute(text(
            f"TRUNCATE {', '.join(_APP_TABLES)} RESTART IDENTITY CASCADE"
        ))
        conn.commit()


@pytest.fixture()
def conn(db_engine, truncate_tables):
    """Provide a DB connection with clean tables."""
    with db_engine.connect() as c:
        yield c


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False)
    yield a


@pytest.fixture()
def client(app):
    return app.test_client()
