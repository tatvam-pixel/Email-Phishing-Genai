"""Cryptographically signed and session-bound CSRF protection."""

import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from flask import current_app, request, session


def _get_secret(override_secret: Optional[str | bytes] = None) -> bytes:
    """Return the application secret key as bytes."""
    if override_secret:
        return override_secret.encode("utf-8") if isinstance(override_secret, str) else override_secret

    try:
        secret = current_app.secret_key
    except RuntimeError:
        secret = os.environ.get("SESSION_SECRET") or os.environ.get("SECRET_KEY")

    if not secret:
        raise RuntimeError("Secret key is not configured for CSRF validation")
    if isinstance(secret, str):
        return secret.encode("utf-8")
    return secret


def generate_csrf_token(user_sub: str, secret: Optional[str | bytes] = None) -> str:
    """Generate a cryptographically random, HMAC-signed CSRF token bound to user_sub.

    Token structure: <raw_entropy>:<user_sub>:<timestamp>.<signature>
    """
    if not user_sub:
        raise ValueError("user_sub is required to bind CSRF token")

    raw_entropy = secrets.token_urlsafe(32)
    timestamp = int(time.time())
    payload = f"{raw_entropy}:{user_sub}:{timestamp}"
    signature = hmac.new(_get_secret(secret), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{payload}.{signature}"

    # Bind token to current server session if available
    try:
        session["csrf_token"] = token
    except RuntimeError:
        pass

    return token


def validate_csrf_token(
    token: str,
    user_sub: str,
    max_age_seconds: int = 86400,
    secret: Optional[str | bytes] = None,
) -> bool:
    """Validate token signature, user binding, freshness, and session match.

    Uses constant-time comparisons throughout to prevent timing attacks.
    """
    if not token or not isinstance(token, str) or not user_sub:
        return False

    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        return False

    payload, signature = parts

    # 1. Verify cryptographic HMAC signature
    try:
        sec = _get_secret(secret)
    except RuntimeError:
        return False

    expected_sig = hmac.new(sec, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        return False

    # 2. Verify payload structure and user binding
    payload_parts = payload.split(":")
    if len(payload_parts) != 3:
        return False

    _, token_user_sub, ts_str = payload_parts
    if not hmac.compare_digest(token_user_sub, user_sub):
        return False

    # 3. Verify timestamp freshness (default 24 hours, with 300s clock skew allowance)
    try:
        ts = int(ts_str)
    except ValueError:
        return False

    now = int(time.time())
    if now - ts > max_age_seconds or ts > (now + 300):
        return False

    # 4. Verify match against active server session binding if session is active
    try:
        saved_token = session.get("csrf_token")
        if saved_token and not hmac.compare_digest(token, saved_token):
            return False
    except RuntimeError:
        pass

    return True


def validate_request_csrf() -> bool:
    """Validate CSRF token for the current incoming request.

    Enforces the double-submit pattern:
    - X-CSRF-Token header must be present and valid.
    - If csrf_token cookie is also present, it must match the header token in constant time.
    """
    user = session.get("user")
    if not user or not isinstance(user, dict) or not user.get("sub"):
        return False

    user_sub = user["sub"]
    header_token = request.headers.get("X-CSRF-Token", "").strip()
    if not header_token:
        return False

    cookie_token = request.cookies.get("csrf_token", "").strip()
    if cookie_token and not hmac.compare_digest(header_token, cookie_token):
        return False

    return validate_csrf_token(header_token, user_sub)
