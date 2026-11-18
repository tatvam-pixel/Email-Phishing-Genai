"""Tests for Vercel WSGI entrypoint."""

import os

# Set ENV=test before importing entrypoint
os.environ.setdefault("ENV", "test")

from apiflask import APIFlask  # noqa: E402
from index import app  # noqa: E402


def test_entrypoint_app_instance():
    assert isinstance(app, APIFlask)


def test_entrypoint_health_endpoint():
    client = app.test_client()
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"
