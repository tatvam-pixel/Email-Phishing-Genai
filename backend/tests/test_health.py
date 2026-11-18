"""Tests for GET /api/v1/health, /docs, /openapi.json."""

from datetime import datetime


def test_health_returns_200(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"
    # Verify time is valid ISO 8601
    datetime.fromisoformat(data["time"])
    assert "X-Request-Id" in resp.headers


def test_docs_available(client):
    resp = client.get("/docs")
    assert resp.status_code == 200


def test_openapi_json_available(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["info"]["title"] == "PhishGuard AI"
    assert data["info"]["version"] == "0.1.0"
