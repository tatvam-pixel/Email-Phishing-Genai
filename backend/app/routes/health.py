"""GET /api/v1/health — liveness probe, no DB dependency."""

from datetime import datetime, timezone

from apiflask import APIBlueprint

health_bp = APIBlueprint("health", __name__, url_prefix="/api/v1")


@health_bp.get("/health")
def health():
    """Return service status, version, and current UTC time."""
    return {
        "status": "ok",
        "version": "0.1.0",
        "time": datetime.now(timezone.utc).isoformat(),
    }
