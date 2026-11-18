"""Tests for the standard error shape (design §3) and X-Request-Id."""


def test_404_error_shape(client):
    resp = client.get("/nonexistent")
    assert resp.status_code == 404
    data = resp.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "not_found"
    assert "message" in data["error"]
    assert data["error"]["request_id"] is not None
    assert "X-Request-Id" in resp.headers
    assert resp.headers["X-Request-Id"] == data["error"]["request_id"]


def test_405_error_shape(client):
    resp = client.delete("/api/v1/health")
    assert resp.status_code == 405
    data = resp.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "method_not_allowed"
    assert data["error"]["request_id"] is not None
    assert "X-Request-Id" in resp.headers


def test_500_error_shape(app, client):
    # Throwaway route registered only in this test
    @app.get("/test-500")
    def raise_error():
        raise RuntimeError("boom")

    resp = client.get("/test-500")
    assert resp.status_code == 500
    data = resp.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "internal_error"
    assert data["error"]["request_id"] is not None
    assert "X-Request-Id" in resp.headers
    # No internal details leak
    assert "boom" not in data["error"]["message"]
    assert "Traceback" not in resp.get_data(as_text=True)


def test_request_id_generated_when_absent(client):
    resp = client.get("/api/v1/health")
    rid = resp.headers.get("X-Request-Id")
    assert rid is not None
    assert rid.startswith("req_")


def test_request_id_echoed_when_valid(client):
    resp = client.get(
        "/api/v1/health", headers={"X-Request-Id": "my-custom-id-123"}
    )
    assert resp.headers["X-Request-Id"] == "my-custom-id-123"


def test_request_id_replaced_when_invalid(client):
    # Too long
    resp = client.get(
        "/api/v1/health", headers={"X-Request-Id": "a" * 65}
    )
    assert resp.headers["X-Request-Id"].startswith("req_")

    # Bad characters
    resp = client.get(
        "/api/v1/health", headers={"X-Request-Id": "bad id!@#"}
    )
    assert resp.headers["X-Request-Id"].startswith("req_")

    # Non-matching chars (dots, spaces, special symbols)
    resp = client.get(
        "/api/v1/health", headers={"X-Request-Id": "invalid.id"}
    )
    assert resp.headers["X-Request-Id"].startswith("req_")
