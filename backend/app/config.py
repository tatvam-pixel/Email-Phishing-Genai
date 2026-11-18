"""Application configuration loaded from environment variables."""

import os


class Config:
    """Phase 1 configuration — only ENV is required."""

    ENV: str = os.environ.get("ENV", "development")


def get_config() -> Config:
    """Return the application config.

    Fails fast on missing required vars unless ENV=test.
    Phase 1: only ENV is needed; more checks added in later steps.
    """
    return Config()
