"""PhishGuard AI — application factory."""

from datetime import timedelta
import hashlib
import hmac
import os
import re
import secrets

from apiflask import APIFlask
from apiflask.security import APIKeyHeaderAuth
from flask import g, request

from .config import Config, get_config, is_secure_cookie_required
from .errors import STATUS_CODE_MAP, error_response

# Security scheme for backward compatibility and OpenAPI
api_key_auth = APIKeyHeaderAuth(name="X-API-Key")


@api_key_auth.verify_token
def verify_api_key(token: str) -> bool:
    """Verify incoming X-API-Key against DEMO_API_KEY_SHA256 in constant time."""
    expected_hash = os.environ.get("DEMO_API_KEY_SHA256", "")
    if not token or not expected_hash:
        return False
    incoming_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(incoming_hash, expected_hash)


@api_key_auth.error_processor
def auth_error_processor(error):
    """Return standard 401 error envelope on missing or invalid key."""
    return error_response(401, "Invalid or missing API key.", "unauthorized"), 401


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def create_app(config: Config | None = None) -> APIFlask:
    app = APIFlask(
        __name__,
        title="PhishGuard AI",
        version="0.1.0",
        docs_path="/docs",
        spec_path="/openapi.json",
    )

    if config is None:
        config = get_config()
    app.config["ENV_NAME"] = config.ENV

    # ---- Session Configuration ----------------------------------------------
    secure_cookies = is_secure_cookie_required(config)

    session_secret = (
        os.environ.get("SESSION_SECRET")
        or os.environ.get("SECRET_KEY")
        or config.SESSION_SECRET
    )
    if not session_secret:
        if secure_cookies:
            raise RuntimeError(
                "SESSION_SECRET environment variable is required in production and secure deployments"
            )
        session_secret = "dev-insecure-session-secret-change-in-prod"

    app.secret_key = session_secret
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=secure_cookies,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="session",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    )

    # ---- OpenAPI Security Schemes -------------------------------------------
    app.security_schemes = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for programmatic access",
        },
        "CookieAuth": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
            "description": "Authenticated browser session cookie",
        },
    }

    # ---- Request ID --------------------------------------------------------
    @app.before_request
    def set_request_id():
        incoming = request.headers.get("X-Request-Id", "")
        if incoming and _REQUEST_ID_RE.fullmatch(incoming):
            g.request_id = incoming
        else:
            g.request_id = f"req_{secrets.token_urlsafe(12)}"

    @app.after_request
    def add_request_id_header(response):
        response.headers["X-Request-Id"] = getattr(g, "request_id", "")
        return response

    # ---- Error handling -----------------------------------------------------
    @app.error_processor
    def process_error(error):
        status = error.status_code
        custom_code = (getattr(error, "extra_data", None) or {}).get("code")
        code = custom_code or STATUS_CODE_MAP.get(status, "internal_error")
        if status >= 500:
            message = "An unexpected error occurred."
        else:
            message = error.message or "An error occurred."
        body = error_response(status, message, code)
        if error.detail:
            body["error"]["detail"] = error.detail
        return body, status, error.headers if error.headers else {}

    # Non-HTTP exceptions (RuntimeError, etc.)
    @app.errorhandler(Exception)
    def handle_unexpected(exc):
        body = error_response(500, "An unexpected error occurred.")
        return body, 500

    # ---- Blueprints ---------------------------------------------------------
    from .routes.auth import auth_bp
    from .routes.health import health_bp
    from .routes.scan import scan_bp
    from .routes.ui import ui_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(ui_bp)

    return app
