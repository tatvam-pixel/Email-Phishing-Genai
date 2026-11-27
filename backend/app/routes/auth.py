"""Authentication routes for Google OAuth 2.0 and session management."""

import hmac
import logging
import os
import secrets
from typing import Any

from apiflask import APIBlueprint, Schema, abort
from apiflask.fields import Boolean, Nested, String
from flask import current_app, redirect, request, session

from ..config import is_confirmed_local_dev
from ..csrf import generate_csrf_token, validate_request_csrf
from ..errors import error_response
from ..services.oauth_service import (
    OAuthError,
    OAuthValidationError,
    build_authorization_url,
    exchange_code_for_tokens,
    validate_google_id_token,
)

logger = logging.getLogger(__name__)

auth_bp = APIBlueprint("auth", __name__, tag="Authentication")


class UserProfileSchema(Schema):
    sub = String(metadata={"example": "108234567890123456789"})
    email = String(metadata={"example": "analyst@example.com"})
    name = String(metadata={"example": "Security Analyst"})
    picture = String(metadata={"example": "https://lh3.googleusercontent.com/..."})


class AuthMeResponseSchema(Schema):
    authenticated = Boolean(metadata={"example": True})
    user = Nested(UserProfileSchema, allow_none=True)
    csrf_token = String(metadata={"example": "token_string"}, allow_none=True)


class CsrfTokenResponseSchema(Schema):
    csrf_token = String(metadata={"example": "token_string"})


def _get_redirect_uri() -> str:
    """Determine the configured OAuth redirect URI.

    Production and ambiguous environments require GOOGLE_REDIRECT_URI explicitly.
    Localhost fallback is permitted only in confirmed local development/test.
    """
    configured = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
    if configured:
        return configured
    if is_confirmed_local_dev():
        return "http://localhost:8000/auth/callback"
    raise RuntimeError("GOOGLE_REDIRECT_URI must be explicitly configured outside local development")


@auth_bp.get("/auth/login")
def login():
    """Initiate Google OAuth 2.0 authorization redirect."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        return error_response(500, "Google OAuth is not configured on the server.", "config_error"), 500

    try:
        redirect_uri = _get_redirect_uri()
    except RuntimeError:
        logger.warning("GOOGLE_REDIRECT_URI is not configured")
        return error_response(500, "Google OAuth redirect URI is not configured on the server.", "config_error"), 500

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    session["oauth_state"] = state
    session["oauth_nonce"] = nonce
    session["oauth_redirect_uri"] = redirect_uri

    auth_url = build_authorization_url(
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        nonce=nonce,
    )
    return redirect(auth_url)


@auth_bp.get("/auth/callback")
def callback():
    """Handle OAuth 2.0 callback, exchange code, validate ID token, and establish session."""
    incoming_state = request.args.get("state")

    saved_state = session.pop("oauth_state", None)
    saved_nonce = session.pop("oauth_nonce", None)
    saved_redirect_uri = session.pop("oauth_redirect_uri", None)

    # 1. Validate OAuth state BEFORE handling any error or code response
    if not saved_state or not incoming_state or not hmac.compare_digest(incoming_state, saved_state):
        logger.warning("OAuth callback state mismatch or expired")
        return error_response(400, "Invalid or expired OAuth state parameter.", "invalid_oauth_state"), 400

    # 2. Handle OAuth provider error/denial only after state validation
    error = request.args.get("error")
    if error:
        logger.warning("OAuth error returned from Google: %s", error)
        session.pop("user", None)
        return redirect("/?auth_error=google_denied")

    if not saved_redirect_uri:
        try:
            saved_redirect_uri = _get_redirect_uri()
        except RuntimeError:
            logger.warning("GOOGLE_REDIRECT_URI is not configured")
            return error_response(500, "Google OAuth redirect URI is not configured on the server.", "config_error"), 500

    code = request.args.get("code")

    if not saved_nonce:
        logger.warning("OAuth callback missing saved nonce in session")
        return error_response(400, "Missing or expired OAuth nonce in session.", "missing_oauth_nonce"), 400

    if not code:
        return error_response(400, "Missing authorization code from Google.", "missing_code"), 400

    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()

    # 2. Token exchange
    try:
        token_data = exchange_code_for_tokens(
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=saved_redirect_uri,
        )
    except OAuthError as exc:
        logger.warning("OAuth token exchange failure: %s", type(exc).__name__)
        return error_response(401, "Failed to authenticate with Google.", "token_exchange_failed"), 401

    id_token = token_data.get("id_token")
    if not id_token:
        return error_response(401, "Google did not provide an ID token.", "missing_id_token"), 401

    # 3. Comprehensive OIDC ID token validation (mandatory nonce, RS256 alg enforcement, key rotation)
    try:
        claims = validate_google_id_token(
            id_token_str=id_token,
            client_id=client_id,
            expected_nonce=saved_nonce,
        )
    except OAuthValidationError as exc:
        logger.warning("OIDC token validation failed: %s", type(exc).__name__)
        return error_response(401, "Google ID token validation failed.", "invalid_id_token"), 401
    except Exception as exc:
        logger.warning("Unexpected error validating ID token: %s", type(exc).__name__)
        return error_response(401, "Failed to validate identity.", "auth_error"), 401

    # 4. Prevent session fixation by resetting the session
    session.clear()
    session.permanent = True
    session["user"] = {
        "sub": claims["sub"],
        "email": claims["email"],
        "name": claims.get("name", claims["email"]),
        "picture": claims.get("picture", ""),
    }

    # 5. Generate session-bound CSRF token
    csrf_token = generate_csrf_token(claims["sub"])

    # Redirect to home with double-submit CSRF cookie using configured security
    response = redirect("/")
    is_secure = current_app.config.get("SESSION_COOKIE_SECURE", True)
    response.set_cookie(
        "csrf_token",
        csrf_token,
        samesite="Lax",
        secure=is_secure,
        httponly=False,  # Accessible to JavaScript for double-submit header
        max_age=86400,
    )
    return response


@auth_bp.post("/auth/logout")
@auth_bp.doc(
    summary="Log out of authenticated session",
    description="Terminates the user session and deletes authentication cookies. Requires a valid CSRF token.",
    responses={
        302: "Redirects to home after session termination",
        403: "Forbidden - invalid or missing CSRF token",
    },
)
def logout():
    """Clear session and authentication cookies via POST with CSRF validation."""
    if not validate_request_csrf():
        return error_response(403, "Invalid or missing CSRF token.", "forbidden"), 403

    session.clear()
    is_secure = current_app.config.get("SESSION_COOKIE_SECURE", True)

    response = redirect("/")
    response.delete_cookie("csrf_token", samesite="Lax", secure=is_secure)
    response.delete_cookie(
        current_app.config.get("SESSION_COOKIE_NAME", "session"),
        samesite="Lax",
        secure=is_secure,
    )
    return response


@auth_bp.get("/auth/logout")
@auth_bp.doc(
    summary="Reject GET logout",
    description="GET /auth/logout is rejected to prevent CSRF logout attacks. Logout must be sent via POST with CSRF.",
    responses={
        405: "Method Not Allowed - POST required",
    },
)
def logout_get():
    """Reject GET /auth/logout without changing authentication state."""
    return error_response(
        405,
        "Method not allowed. Logout must be submitted via POST with a valid CSRF token.",
        "method_not_allowed",
    ), 405


@auth_bp.get("/auth/me")
@auth_bp.output(AuthMeResponseSchema, status_code=200)
def me():
    """Return the currently authenticated user session information."""
    user = session.get("user")
    if not user or not user.get("sub"):
        return {"authenticated": False, "user": None, "csrf_token": None}

    user_sub = user["sub"]
    csrf_token = session.get("csrf_token")
    if not csrf_token:
        csrf_token = generate_csrf_token(user_sub)

    return {
        "authenticated": True,
        "user": user,
        "csrf_token": csrf_token,
    }


@auth_bp.get("/auth/csrf-token")
@auth_bp.output(CsrfTokenResponseSchema, status_code=200)
def csrf_token_endpoint():
    """Issue a fresh signed CSRF token for the authenticated session."""
    user = session.get("user")
    if not user or not user.get("sub"):
        abort(401, message="Authentication required to request a CSRF token.", extra_data={"code": "unauthorized"})

    token = generate_csrf_token(user["sub"])
    return {"csrf_token": token}
