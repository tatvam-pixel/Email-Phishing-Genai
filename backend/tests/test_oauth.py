"""Comprehensive tests for Google OAuth 2.0, session authentication, and CSRF protection."""

import base64
import hashlib
import hmac
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    from app import create_app
    from app.config import Config, is_secure_cookie_required
    from app.csrf import generate_csrf_token, validate_csrf_token, validate_request_csrf
    from app.services.oauth_service import (
        ALLOWED_ISSUERS,
        OAuthError,
        OAuthValidationError,
        validate_google_id_token,
    )
except ImportError:
    from backend.app import create_app
    from backend.app.config import Config, is_secure_cookie_required
    from backend.app.csrf import generate_csrf_token, validate_csrf_token, validate_request_csrf
    from backend.app.services.oauth_service import (
        ALLOWED_ISSUERS,
        OAuthError,
        OAuthValidationError,
        validate_google_id_token,
    )

TEST_CLIENT_ID = "test-google-client-id.apps.googleusercontent.com"
TEST_CLIENT_SECRET = "test-google-client-secret-xyz"
TEST_REDIRECT_URI = "http://localhost:8000/auth/callback"
DEMO_KEY = "pg_demo_test_secret_key_12345"
DEMO_KEY_HASH = hashlib.sha256(DEMO_KEY.encode("utf-8")).hexdigest()


# Helper to generate test RSA key pair and JWKS
@pytest.fixture(scope="session")
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = "test-key-id-1"
    pub_jwk = JsonWebKey.import_key(public_key, {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig"})
    jwks = {"keys": [pub_jwk.as_dict()]}
    return private_key, kid, jwks


def make_id_token(
    private_key,
    kid: str | None = "test-key-id-1",
    iss: str = "https://accounts.google.com",
    aud: object = TEST_CLIENT_ID,
    sub: str = "109876543210123456789",
    email: str = "security.analyst@example.com",
    email_verified: bool = True,
    exp: int | None = None,
    iat: object = "DEFAULT_NOW",
    nonce: str | None = "test-nonce-12345",
    alg: str = "RS256",
    azp: str | None = None,
) -> str:
    now = int(time.time())
    header = {"alg": alg}
    if kid is not None:
        header["kid"] = kid
    payload: dict[str, object] = {
        "iss": iss,
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "exp": exp if exp is not None else (now + 3600),
    }
    if aud is not None:
        payload["aud"] = aud
    if iat == "DEFAULT_NOW":
        payload["iat"] = now
    elif iat is not None:
        payload["iat"] = iat
    if azp is not None:
        payload["azp"] = azp
    if nonce is not None:
        payload["nonce"] = nonce

    encoded = jwt.encode(header, payload, private_key)
    return encoded.decode("utf-8") if isinstance(encoded, bytes) else encoded


@pytest.fixture(autouse=True)
def set_oauth_env(monkeypatch):
    """Ensure required OAuth and security environment variables are set."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", TEST_CLIENT_ID)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", TEST_CLIENT_SECRET)
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", TEST_REDIRECT_URI)
    monkeypatch.setenv("SESSION_SECRET", "super-secret-session-key-for-testing-12345")
    monkeypatch.setenv("DEMO_API_KEY_SHA256", DEMO_KEY_HASH)
    monkeypatch.setenv("GEMINI_API_KEY", "test_gemini_key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)


@pytest.fixture
def app():
    test_app = create_app()
    test_app.config["TESTING"] = True
    return test_app


@pytest.fixture
def client(app):
    with app.test_client() as test_client:
        yield test_client


# =============================================================================
# 1. Finding 1: Production Cookie Security & Environment Detection
# =============================================================================
def test_cookie_security_vercel_production_with_explicit_false(monkeypatch):
    """Vercel production MUST require Secure cookies even when SESSION_COOKIE_SECURE=false."""
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "production")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert is_secure_cookie_required() is True


def test_cookie_security_env_production_with_explicit_false(monkeypatch):
    """ENV=production MUST require Secure cookies even when SESSION_COOKIE_SECURE=false."""
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert is_secure_cookie_required() is True


def test_cookie_security_vercel_preview_detected(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "preview")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert is_secure_cookie_required() is True


def test_cookie_security_local_dev_explicit_false_and_true(monkeypatch):
    """Explicit false is honored ONLY in confirmed local development/test."""
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv("ENV", "development")

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert is_secure_cookie_required() is False

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    assert is_secure_cookie_required() is True


def test_cookie_security_ambiguous_environment_fails_securely(monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv("ENV", "staging-unknown")
    # Fail secure even if explicit false is set in ambiguous environment
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    assert is_secure_cookie_required() is True

    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    assert is_secure_cookie_required() is True


def test_redirect_uri_missing_in_production_returns_500(client, monkeypatch):
    """Production must require GOOGLE_REDIRECT_URI explicitly; never derive from Host header."""
    monkeypatch.delenv("GOOGLE_REDIRECT_URI", raising=False)
    monkeypatch.setenv("ENV", "production")

    res = client.get("/auth/login", headers={"Host": "evil.attacker.com"})
    assert res.status_code == 500
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "config_error"


def test_redirect_uri_missing_in_vercel_returns_500(client, monkeypatch):
    """Vercel deployments must require GOOGLE_REDIRECT_URI explicitly."""
    monkeypatch.delenv("GOOGLE_REDIRECT_URI", raising=False)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "production")
    monkeypatch.setenv("ENV", "development")

    res = client.get("/auth/login", headers={"Host": "evil.attacker.com"})
    assert res.status_code == 500
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "config_error"


def test_redirect_uri_localhost_fallback_in_confirmed_development(client, monkeypatch):
    """Confirmed local development falls back to localhost:8000, ignoring Host header."""
    monkeypatch.delenv("GOOGLE_REDIRECT_URI", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv("ENV", "development")

    res = client.get("/auth/login", headers={"Host": "evil.attacker.com"})
    assert res.status_code == 302
    location = res.headers.get("Location", "")
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauth%2Fcallback" in location
    assert "evil.attacker.com" not in location


def test_cookie_security_dev_and_test_allow_insecure(monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("ENV", "test")
    assert is_secure_cookie_required() is False

    monkeypatch.setenv("ENV", "development")
    assert is_secure_cookie_required() is False


def test_missing_session_secret_in_production_raises_error(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SESSION_SECRET environment variable is required"):
        create_app()


# =============================================================================
# 2. Finding 2: Mandatory OIDC Nonce Tests
# =============================================================================
def test_oidc_validation_rejects_missing_expected_nonce(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, nonce="nonce-123")
    with pytest.raises(OAuthValidationError, match="Missing or empty expected nonce"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="", jwks=jwks)

    with pytest.raises(OAuthValidationError, match="Missing or empty expected nonce"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce=None, jwks=jwks)  # type: ignore


def test_oidc_validation_rejects_missing_token_nonce(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, nonce=None)
    with pytest.raises(OAuthValidationError, match="ID token is missing mandatory 'nonce' claim"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="expected-nonce", jwks=jwks)


def test_oidc_validation_rejects_mismatched_nonce(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, nonce="token-nonce-a")
    with pytest.raises(OAuthValidationError, match="OAuth nonce mismatch"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="expected-nonce-b", jwks=jwks)


def test_oidc_validation_succeeds_with_matching_nonce(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, nonce="secure-nonce-12345")
    claims = validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="secure-nonce-12345", jwks=jwks)
    assert claims["nonce"] == "secure-nonce-12345"
    assert claims["email"] == "security.analyst@example.com"


# =============================================================================
# 3. Finding 4: JWKS Key Rotation Tests
# =============================================================================
def test_jwks_key_rotation_refreshes_and_succeeds():
    """Simulate a stale JWKS cache missing the new key; refresh should fetch new key and succeed."""
    k1 = rsa.generate_private_key(65537, 2048)
    k2 = rsa.generate_private_key(65537, 2048)
    jwk1 = JsonWebKey.import_key(k1.public_key(), {"kty": "RSA", "kid": "old-key-1", "alg": "RS256", "use": "sig"})
    jwk2 = JsonWebKey.import_key(k2.public_key(), {"kty": "RSA", "kid": "new-key-2", "alg": "RS256", "use": "sig"})

    stale_jwks = {"keys": [jwk1.as_dict()]}
    fresh_jwks = {"keys": [jwk1.as_dict(), jwk2.as_dict()]}

    token = make_id_token(k2, kid="new-key-2", nonce="test-nonce")

    with patch("app.services.oauth_service.fetch_google_jwks") as mock_fetch:
        mock_fetch.return_value = fresh_jwks
        claims = validate_google_id_token(
            id_token_str=token,
            client_id=TEST_CLIENT_ID,
            expected_nonce="test-nonce",
            jwks=stale_jwks,
        )
        assert claims["sub"] == "109876543210123456789"
        assert mock_fetch.call_count == 1
        assert mock_fetch.call_args[1].get("force_refresh") is True


def test_jwks_key_rotation_fails_bounded_if_key_still_unknown(rsa_keys):
    """When key is still unknown after single refresh, fail with OAuthValidationError without looping."""
    priv_key, _, jwks = rsa_keys
    token = make_id_token(priv_key, kid="unknown-phantom-key", nonce="test-nonce")

    with patch("app.services.oauth_service.fetch_google_jwks", return_value=jwks) as mock_fetch:
        with pytest.raises(OAuthValidationError, match="Unknown key ID"):
            validate_google_id_token(
                id_token_str=token,
                client_id=TEST_CLIENT_ID,
                expected_nonce="test-nonce",
                jwks=jwks,
            )
        assert mock_fetch.call_count <= 1


# =============================================================================
# 4. Finding 5: Explicit JWT Algorithm Enforcement Tests
# =============================================================================
def test_jwt_algorithm_enforcement_rejects_hs256():
    raw_header = json.dumps({"alg": "HS256", "kid": "k1"})
    raw_payload = json.dumps({"iss": "https://accounts.google.com", "nonce": "n1"})
    b64_h = base64.urlsafe_b64encode(raw_header.encode()).decode().rstrip("=")
    b64_p = base64.urlsafe_b64encode(raw_payload.encode()).decode().rstrip("=")
    fake_token = f"{b64_h}.{b64_p}.sig"

    with pytest.raises(OAuthValidationError, match="Unsupported JWT algorithm: 'HS256'"):
        validate_google_id_token(fake_token, TEST_CLIENT_ID, expected_nonce="n1")


def test_jwt_algorithm_enforcement_rejects_none():
    raw_header = json.dumps({"alg": "none", "kid": "k1"})
    raw_payload = json.dumps({"iss": "https://accounts.google.com", "nonce": "n1"})
    b64_h = base64.urlsafe_b64encode(raw_header.encode()).decode().rstrip("=")
    b64_p = base64.urlsafe_b64encode(raw_payload.encode()).decode().rstrip("=")
    fake_token = f"{b64_h}.{b64_p}."

    with pytest.raises(OAuthValidationError, match="Unsupported JWT algorithm: 'none'"):
        validate_google_id_token(fake_token, TEST_CLIENT_ID, expected_nonce="n1")


def test_jwt_algorithm_enforcement_rejects_missing_kid(rsa_keys):
    priv_key, _, jwks = rsa_keys
    token = make_id_token(priv_key, kid=None, nonce="test-nonce")
    with pytest.raises(OAuthValidationError, match="Missing or invalid 'kid' header"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="test-nonce", jwks=jwks)


# =============================================================================
# 5. Finding 3: Logout CSRF & POST-only Enforcement Tests
# =============================================================================
def test_logout_get_returns_405_and_preserves_session(client):
    with client.session_transaction() as sess:
        sess["user"] = {"sub": "usr_99", "email": "analyst@example.com"}
        sess["csrf_token"] = generate_csrf_token("usr_99")

    # GET /auth/logout must not log the user out
    res = client.get("/auth/logout")
    assert res.status_code == 405
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "method_not_allowed"

    # Session must remain intact
    with client.session_transaction() as sess:
        assert sess.get("user", {}).get("sub") == "usr_99"


def test_logout_post_without_csrf_returns_403_and_preserves_session(client):
    with client.session_transaction() as sess:
        sess["user"] = {"sub": "usr_99", "email": "analyst@example.com"}
        sess["csrf_token"] = generate_csrf_token("usr_99")

    # POST /auth/logout without CSRF header
    res = client.post("/auth/logout")
    assert res.status_code == 403
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "forbidden"

    # Session must remain intact
    with client.session_transaction() as sess:
        assert sess.get("user", {}).get("sub") == "usr_99"


def test_logout_post_with_valid_csrf_clears_session(client):
    user_sub = "usr_99"
    with client.session_transaction() as sess:
        sess["user"] = {"sub": user_sub, "email": "analyst@example.com"}
        csrf = generate_csrf_token(user_sub)
        sess["csrf_token"] = csrf

    client.set_cookie("csrf_token", csrf)
    res = client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    assert res.status_code == 302
    assert res.headers.get("Location") == "/"

    # Session must be completely cleared
    with client.session_transaction() as sess:
        assert "user" not in sess
        assert "csrf_token" not in sess


# =============================================================================
# 6. General OAuth Claims & Flow Tests
# =============================================================================
def test_oidc_validation_rejects_invalid_issuer(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, iss="https://evil-issuer.com", nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="Invalid token issuer"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_oidc_validation_rejects_audience_mismatch(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, aud="wrong-audience-id", nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="Token audience mismatch"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_oidc_audience_string_and_array_validation(rsa_keys):
    priv_key, kid, jwks = rsa_keys

    # Valid string audience
    token_str = make_id_token(priv_key, kid, aud=TEST_CLIENT_ID, nonce="nonce-1")
    claims = validate_google_id_token(token_str, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)
    assert claims["aud"] == TEST_CLIENT_ID

    # Valid array audience (single element)
    token_arr_one = make_id_token(priv_key, kid, aud=[TEST_CLIENT_ID], nonce="nonce-1")
    claims = validate_google_id_token(token_arr_one, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)
    assert claims["aud"] == [TEST_CLIENT_ID]

    # Valid array audience (multiple elements with matching azp)
    token_arr_multi = make_id_token(
        priv_key, kid, aud=[TEST_CLIENT_ID, "other-client.apps.googleusercontent.com"], azp=TEST_CLIENT_ID, nonce="nonce-1"
    )
    claims = validate_google_id_token(token_arr_multi, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)
    assert claims["azp"] == TEST_CLIENT_ID

    # Array audience missing client_id
    token_missing_cid = make_id_token(priv_key, kid, aud=["other-client-1", "other-client-2"], azp=TEST_CLIENT_ID, nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="Token audience mismatch"):
        validate_google_id_token(token_missing_cid, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)

    # Multiple audiences with missing azp
    token_missing_azp = make_id_token(priv_key, kid, aud=[TEST_CLIENT_ID, "other-client"], azp=None, nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="authorized party"):
        validate_google_id_token(token_missing_azp, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)

    # Multiple audiences with wrong azp
    token_wrong_azp = make_id_token(priv_key, kid, aud=[TEST_CLIENT_ID, "other-client"], azp="other-client", nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="authorized party"):
        validate_google_id_token(token_wrong_azp, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)

    # Malformed audience values
    for bad_aud in [None, [], 12345, [""]]:
        bad_token = make_id_token(priv_key, kid, aud=bad_aud, nonce="nonce-1")
        with pytest.raises(OAuthValidationError, match="Malformed or missing 'aud'"):
            validate_google_id_token(bad_token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_oidc_iat_validation(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    now = int(time.time())

    # Valid iat (within leeway)
    valid_token = make_id_token(priv_key, kid, iat=now - 10, nonce="nonce-1")
    claims = validate_google_id_token(valid_token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)
    assert claims["iat"] == now - 10

    # Missing iat
    missing_iat_token = make_id_token(priv_key, kid, iat=None, nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="missing or malformed 'iat'"):
        validate_google_id_token(missing_iat_token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)

    # Malformed iat (string and bool)
    for bad_iat in ["not-a-timestamp", True]:
        malformed_token = make_id_token(priv_key, kid, iat=bad_iat, nonce="nonce-1")
        with pytest.raises(OAuthValidationError, match="missing or malformed 'iat'"):
            validate_google_id_token(malformed_token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)

    # Future iat beyond leeway
    future_token = make_id_token(priv_key, kid, iat=now + 600, nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="issued in the future"):
        validate_google_id_token(future_token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_oidc_validation_rejects_expired_token(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    expired_time = int(time.time()) - 500
    token = make_id_token(priv_key, kid, exp=expired_time, nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="ID token has expired"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_oidc_validation_rejects_unverified_email(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, email_verified=False, nonce="nonce-1")
    with pytest.raises(OAuthValidationError, match="Google email address is not verified"):
        validate_google_id_token(token, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_oidc_validation_rejects_bad_signature(rsa_keys):
    priv_key, kid, jwks = rsa_keys
    token = make_id_token(priv_key, kid, nonce="nonce-1")
    parts = token.split(".")
    corrupted = f"{parts[0]}.{parts[1]}.badsignature"
    with pytest.raises(OAuthValidationError, match="signature verification failed|Invalid JWKS"):
        validate_google_id_token(corrupted, TEST_CLIENT_ID, expected_nonce="nonce-1", jwks=jwks)


def test_login_redirects_to_google(client):
    res = client.get("/auth/login")
    assert res.status_code == 302
    location = res.headers.get("Location", "")
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth")
    assert f"client_id={TEST_CLIENT_ID}" in location

    with client.session_transaction() as sess:
        assert "oauth_state" in sess
        assert "oauth_nonce" in sess
        assert sess["oauth_redirect_uri"] == TEST_REDIRECT_URI


def test_callback_state_mismatch_rejected(client):
    with client.session_transaction() as sess:
        sess["oauth_state"] = "valid-state"
        sess["oauth_nonce"] = "valid-nonce"

    res = client.get("/auth/callback?code=some-code&state=wrong-state")
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error"]["code"] == "invalid_oauth_state"


def test_callback_error_requires_valid_state(client):
    # Missing state with error -> 400 invalid_oauth_state
    res = client.get("/auth/callback?error=access_denied")
    assert res.status_code == 400
    assert res.get_json()["error"]["code"] == "invalid_oauth_state"

    # Mismatched state with error -> 400 invalid_oauth_state
    with client.session_transaction() as sess:
        sess["oauth_state"] = "expected-state"
        sess["oauth_nonce"] = "expected-nonce"
    res = client.get("/auth/callback?error=access_denied&state=wrong-state")
    assert res.status_code == 400
    assert res.get_json()["error"]["code"] == "invalid_oauth_state"

    # Valid state with error -> redirects cleanly and creates no authenticated session
    with client.session_transaction() as sess:
        sess["oauth_state"] = "expected-state"
        sess["oauth_nonce"] = "expected-nonce"
    res = client.get("/auth/callback?error=access_denied&state=expected-state")
    assert res.status_code == 302
    assert "auth_error=google_denied" in res.headers.get("Location", "")
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_callback_success_establishes_session_and_csrf(client, rsa_keys):
    priv_key, kid, _ = rsa_keys
    test_nonce = "my-test-oauth-nonce"
    test_token = make_id_token(priv_key, kid, nonce=test_nonce)

    with client.session_transaction() as sess:
        sess["oauth_state"] = "test-state-123"
        sess["oauth_nonce"] = test_nonce
        sess["oauth_redirect_uri"] = TEST_REDIRECT_URI

    mock_tokens = {
        "access_token": "mock-access-token-456",
        "id_token": test_token,
    }

    with patch("app.routes.auth.exchange_code_for_tokens", return_value=mock_tokens), \
         patch("app.routes.auth.validate_google_id_token", return_value={
             "sub": "user_id_1001",
             "email": "analyst@example.com",
             "name": "Jane Analyst",
             "picture": "https://example.com/pic.jpg",
         }):
        res = client.get("/auth/callback?code=good-code&state=test-state-123")
        assert res.status_code == 302
        assert res.headers.get("Location") == "/"

        with client.session_transaction() as sess:
            assert sess["user"]["sub"] == "user_id_1001"
            assert sess["user"]["email"] == "analyst@example.com"
            assert "csrf_token" in sess


def test_scan_path_a_valid_api_key_bypasses_csrf(client):
    res = client.post(
        "/api/v1/scan/url",
        headers={"X-API-Key": DEMO_KEY},
        json={"url": "https://accounts.google.com/signin", "include_ai_analysis": False},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True


def test_scan_path_a_invalid_api_key_returns_401_no_fallback(client):
    with client.session_transaction() as sess:
        sess["user"] = {"sub": "usr_99", "email": "me@example.com"}
        csrf = generate_csrf_token("usr_99")
        sess["csrf_token"] = csrf

    res = client.post(
        "/api/v1/scan/url",
        headers={"X-API-Key": "invalid_wrong_key", "X-CSRF-Token": csrf},
        json={"url": "https://accounts.google.com/signin"},
    )
    assert res.status_code == 401
    data = res.get_json()
    assert data["error"]["code"] == "unauthorized"


def test_scan_path_b_session_requires_csrf(client):
    with client.session_transaction() as sess:
        sess["user"] = {"sub": "usr_99", "email": "me@example.com"}
        sess["csrf_token"] = generate_csrf_token("usr_99")

    res = client.post("/api/v1/scan/url", json={"url": "https://accounts.google.com/signin"})
    assert res.status_code == 403


def test_scan_path_b_session_with_valid_csrf_succeeds(client):
    user_sub = "usr_99"
    with client.session_transaction() as sess:
        sess["user"] = {"sub": user_sub, "email": "me@example.com"}
        csrf = generate_csrf_token(user_sub)
        sess["csrf_token"] = csrf

    client.set_cookie("csrf_token", csrf)
    res = client.post(
        "/api/v1/scan/url",
        headers={"X-CSRF-Token": csrf},
        json={"url": "https://accounts.google.com/signin", "include_ai_analysis": False},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
