"""PhishGuard AI — application factory."""

import re
import secrets

from apiflask import APIFlask
from apiflask.security import APIKeyHeaderAuth
from flask import g, request

from .config import Config, get_config
from .errors import STATUS_CODE_MAP, error_response

# Security scheme for OpenAPI; verify callback added in step 3.2
api_key_auth = APIKeyHeaderAuth()

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
        code = STATUS_CODE_MAP.get(status, "internal_error")
        if status >= 500:
            message = "An unexpected error occurred."
        else:
            message = error.message or "An error occurred."
        body = error_response(status, message, code)
        if error.detail:
            body["error"]["detail"] = error.detail
        return body, status, error.headers if error.headers else {}

    # Non-HTTP exceptions (RuntimeError, etc.) — HTTPException is handled
    # by APIFlask's own handler which calls error_processor above.
    @app.errorhandler(Exception)
    def handle_unexpected(exc):
        body = error_response(500, "An unexpected error occurred.")
        return body, 500

    # ---- Blueprints ---------------------------------------------------------
    from .routes.health import health_bp

    app.register_blueprint(health_bp)

    return app
