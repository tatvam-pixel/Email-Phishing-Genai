"""Application configuration loaded from environment variables."""

import os


class Config:
    """Application configuration."""

    ENV: str = os.environ.get("ENV", "development")
    GOOGLE_CLIENT_ID: str = os.environ.get("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.environ.get("GOOGLE_REDIRECT_URI", "")
    SESSION_SECRET: str = os.environ.get("SESSION_SECRET", "")


def is_confirmed_local_dev(config: Config | None = None) -> bool:
    """Return True only when running in confirmed local development/test (not Vercel/production)."""
    is_vercel = os.environ.get("VERCEL") == "1"
    vercel_env = (os.environ.get("VERCEL_ENV") or "").strip().lower()
    if is_vercel or vercel_env in ("production", "preview"):
        return False

    env_val = (os.environ.get("ENV") or (config.ENV if config else "") or "").strip().lower()
    return env_val in ("development", "test")


def is_secure_cookie_required(config: Config | None = None) -> bool:
    """Determine whether secure (HTTPS-only) cookies must be enforced.

    Precedence:
    1. Production & Vercel deployments (VERCEL=1, VERCEL_ENV in ('production', 'preview'),
       or ENV == 'production') ALWAYS require Secure cookies; SESSION_COOKIE_SECURE=false
       cannot disable Secure cookies in production.
    2. Confirmed local development/test (not Vercel, ENV in ('development', 'test')):
       honors explicit SESSION_COOKIE_SECURE ('true'/'false'), defaulting to False.
    3. Ambiguous or unknown environment: fails securely by returning True.
    """
    is_vercel = os.environ.get("VERCEL") == "1"
    vercel_env = (os.environ.get("VERCEL_ENV") or "").strip().lower()
    env_val = (os.environ.get("ENV") or (config.ENV if config else "") or "").strip().lower()

    # 1. Production / Vercel always requires Secure cookies
    if is_vercel or vercel_env in ("production", "preview") or env_val == "production":
        return True

    # 2. Only confirmed local development/test may honor explicit false or default to False
    if env_val in ("development", "test"):
        explicit = os.environ.get("SESSION_COOKIE_SECURE")
        if explicit is not None:
            val = explicit.strip().lower()
            if val in ("true", "1", "yes", "on"):
                return True
            if val in ("false", "0", "no", "off"):
                return False
        return False

    # 3. Ambiguous or unknown environment: fail securely by requiring HTTPS cookies
    return True


def get_config() -> Config:
    """Return the application config."""
    return Config()
