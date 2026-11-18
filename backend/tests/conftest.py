import os

# Set ENV before any app import — tests must not load .env
os.environ.setdefault("ENV", "test")

import pytest

from app import create_app


@pytest.fixture()
def app():
    a = create_app()
    a.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False)
    yield a


@pytest.fixture()
def client(app):
    return app.test_client()
