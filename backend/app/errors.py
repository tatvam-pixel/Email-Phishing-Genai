"""Standard error shape (design §3) and status-code map (design §7)."""

from flask import g

STATUS_CODE_MAP: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "rate_limit_exceeded",
    500: "internal_error",
    503: "service_unavailable",
}


def error_response(status_code: int, message: str, code: str | None = None) -> dict:
    """Build the standard error envelope per design §3."""
    return {
        "success": False,
        "error": {
            "code": code or STATUS_CODE_MAP.get(status_code, "internal_error"),
            "message": message,
            "request_id": getattr(g, "request_id", None),
        },
    }
