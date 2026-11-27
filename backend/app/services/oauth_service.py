"""Google OAuth 2.0 and OpenID Connect (OIDC) service."""

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional
from urllib.parse import urlencode

import requests
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import BadSignatureError, DecodeError, JoseError

logger = logging.getLogger(__name__)

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs"
ALLOWED_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

# In-memory JWKS cache with TTL
_JWKS_CACHE: dict[str, Any] = {}
_JWKS_CACHE_EXPIRY: float = 0.0
JWKS_CACHE_TTL_SECONDS = 3600


class OAuthError(Exception):
    """Base OAuth exception."""


class OAuthValidationError(OAuthError):
    """OIDC token validation error."""


def build_authorization_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
) -> str:
    """Construct the Google OAuth 2.0 authorization URL."""
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"


def fetch_google_jwks(timeout: int = 8, force_refresh: bool = False) -> dict[str, Any]:
    """Fetch Google's public JSON Web Key Set (JWKS) with caching and timeout."""
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRY

    now = time.time()
    if not force_refresh and _JWKS_CACHE and now < _JWKS_CACHE_EXPIRY:
        return _JWKS_CACHE

    try:
        response = requests.get(GOOGLE_JWKS_ENDPOINT, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or "keys" not in data:
            raise OAuthError("Malformed JWKS response from Google")
        _JWKS_CACHE = data
        _JWKS_CACHE_EXPIRY = now + JWKS_CACHE_TTL_SECONDS
        return _JWKS_CACHE
    except Exception as exc:
        logger.warning("Failed to fetch Google JWKS: %s", type(exc).__name__)
        raise OAuthError("Failed to retrieve Google public signing keys") from exc


def exchange_code_for_tokens(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    timeout: int = 8,
) -> dict[str, Any]:
    """Exchange authorization code for access and ID tokens."""
    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(
            GOOGLE_TOKEN_ENDPOINT,
            data=payload,
            headers=headers,
            timeout=timeout,
        )
        data = response.json()
        if response.status_code != 200:
            error_desc = data.get("error_description") or data.get("error") or "token_exchange_failed"
            logger.warning("OAuth token exchange failed with status %s", response.status_code)
            raise OAuthError(f"OAuth token exchange failed: {error_desc}")
        return data
    except requests.RequestException as exc:
        logger.warning("OAuth token exchange network error: %s", type(exc).__name__)
        raise OAuthError("Token exchange network request failed") from exc


def _find_key_in_jwks(jwks_data: dict[str, Any], target_kid: str):
    """Import JWKS and find RSA key matching target_kid."""
    try:
        keyset = JsonWebKey.import_key_set(jwks_data)
        for k in keyset.keys:
            if getattr(k, "kid", None) == target_kid:
                return k
    except Exception:
        return None
    return None


def validate_google_id_token(
    id_token_str: str,
    client_id: str,
    expected_nonce: str,
    jwks: Optional[dict[str, Any]] = None,
    leeway: int = 120,
) -> dict[str, Any]:
    """Validate Google OIDC ID token.

    Validates:
    - Mandatory expected_nonce provided and matches token's nonce in constant time
    - Explicit RS256 algorithm enforcement (all other algorithms rejected)
    - Presence of 'kid' header and key selection against Google JWKS
    - JWKS key rotation: if kid is unknown, refreshes JWKS once and retries
    - Signature verification using Google's public JWKS keys
    - Issuer ('iss') matches Google
    - Audience ('aud') matches client_id
    - Expiration ('exp') is in the future
    - User email is verified ('email_verified' is True)
    - User profile data is present and well-formed
    """
    if not id_token_str or not isinstance(id_token_str, str):
        raise OAuthValidationError("Missing or invalid ID token format")

    if not client_id:
        raise OAuthValidationError("client_id is required for token validation")

    # 1. Mandatory Nonce Requirement
    if not expected_nonce or not isinstance(expected_nonce, str) or not expected_nonce.strip():
        raise OAuthValidationError("Missing or empty expected nonce: OIDC nonce validation is mandatory")

    # 2. Parse token segments and header
    parts = id_token_str.split(".")
    if len(parts) != 3:
        raise OAuthValidationError("ID token must have three segments")

    try:
        header_raw = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        header = json.loads(header_raw)
    except Exception as exc:
        raise OAuthValidationError("Malformed JWT header") from exc

    # 3. Explicit JWT Algorithm Enforcement (RS256 only)
    alg = header.get("alg")
    if alg != "RS256":
        raise OAuthValidationError(f"Unsupported JWT algorithm: {alg!r}. Only 'RS256' is permitted.")

    kid = header.get("kid")
    if not kid or not isinstance(kid, str) or not kid.strip():
        raise OAuthValidationError("Missing or invalid 'kid' header in ID token")

    # 4. JWKS Key Selection and Key Rotation
    current_jwks = jwks if jwks is not None else fetch_google_jwks()
    matching_key = _find_key_in_jwks(current_jwks, kid)

    # If kid is not found in cached/provided JWKS, attempt a single refresh
    if not matching_key:
        logger.info("Key ID '%s' not found in JWKS, attempting single refresh", kid)
        try:
            current_jwks = fetch_google_jwks(force_refresh=True)
            matching_key = _find_key_in_jwks(current_jwks, kid)
        except Exception as exc:
            logger.warning("JWKS refresh attempt failed during key rotation: %s", type(exc).__name__)

    if not matching_key:
        raise OAuthValidationError(f"Unknown key ID (kid) '{kid}' in Google JWKS")

    # 5. Decode and verify signature
    try:
        claims = jwt.decode(id_token_str, matching_key)
    except BadSignatureError as exc:
        raise OAuthValidationError("ID token signature verification failed") from exc
    except JoseError as exc:
        raise OAuthValidationError(f"JWT decode error: {type(exc).__name__}") from exc
    except Exception as exc:
        raise OAuthValidationError(f"Unexpected token validation error: {type(exc).__name__}") from exc

    # 6. Validate Issuer ('iss')
    iss = claims.get("iss")
    if iss not in ALLOWED_ISSUERS:
        raise OAuthValidationError(f"Invalid token issuer: {iss}")

    # 7. Validate Audience ('aud') and Authorized Party ('azp')
    aud = claims.get("aud")
    if isinstance(aud, str):
        if not aud.strip() or aud != client_id:
            raise OAuthValidationError(f"Token audience mismatch: expected {client_id}, got {aud!r}")
        if "azp" in claims and claims.get("azp") != client_id:
            raise OAuthValidationError("Token authorized party (azp) mismatch")
    elif isinstance(aud, list) and len(aud) > 0 and all(isinstance(a, str) and a.strip() for a in aud):
        if client_id not in aud:
            raise OAuthValidationError(f"Token audience mismatch: {client_id} not in {aud!r}")
        if len(aud) > 1:
            azp = claims.get("azp")
            if not azp or not isinstance(azp, str) or azp != client_id:
                raise OAuthValidationError("Invalid or missing authorized party (azp) for multi-audience token")
        elif "azp" in claims and claims.get("azp") != client_id:
            raise OAuthValidationError("Token authorized party (azp) mismatch")
    else:
        raise OAuthValidationError("Malformed or missing 'aud' claim in ID token")

    # 8. Validate Expiry ('exp') and Mandatory Issued At ('iat')
    now = time.time()
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp < (now - leeway):
        raise OAuthValidationError("ID token has expired")

    iat = claims.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        raise OAuthValidationError("ID token missing or malformed 'iat' claim")
    if iat > (now + leeway):
        raise OAuthValidationError("ID token issued in the future")

    # 9. Mandatory Nonce Match Verification
    token_nonce = claims.get("nonce")
    if not token_nonce or not isinstance(token_nonce, str) or not token_nonce.strip():
        raise OAuthValidationError("ID token is missing mandatory 'nonce' claim")

    if not hmac.compare_digest(token_nonce, expected_nonce):
        raise OAuthValidationError("OAuth nonce mismatch")

    # 10. Validate identity profile data: email, email_verified, sub
    sub = claims.get("sub")
    if not sub or not isinstance(sub, str):
        raise OAuthValidationError("ID token missing 'sub' subject claim")

    email = claims.get("email")
    if not email or not isinstance(email, str):
        raise OAuthValidationError("ID token missing 'email' claim")

    email_verified = claims.get("email_verified")
    if email_verified is not True:
        raise OAuthValidationError("Google email address is not verified")

    return dict(claims)
