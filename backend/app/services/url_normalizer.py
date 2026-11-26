"""URL normalization and basic validation service."""

from urllib.parse import urlsplit, urlunsplit


class InvalidUrlError(ValueError):
    """Raised when a URL is invalid, unsupported, or malformed."""

    pass


MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}


def normalize_url(raw_url: str) -> str:
    """Validate and normalize a URL.

    Requirements:
    - Must be a non-empty string.
    - Max length 2048 characters.
    - Scheme required: only http and https.
    - Host required and converted to lowercase.
    - Fragment stripped.
    - Raises InvalidUrlError on invalid input.
    """
    if not isinstance(raw_url, str):
        raise InvalidUrlError("URL must be a string.")

    cleaned = raw_url.strip()
    if not cleaned:
        raise InvalidUrlError("URL cannot be empty.")

    if len(cleaned) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters.")

    try:
        parts = urlsplit(cleaned)
    except Exception as exc:
        raise InvalidUrlError(f"Malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if not scheme:
        raise InvalidUrlError("URL scheme is required (http or https).")

    if scheme not in ALLOWED_SCHEMES:
        raise InvalidUrlError(f"Scheme '{scheme}' is not supported. Only http and https are allowed.")

    if not parts.netloc:
        raise InvalidUrlError("URL must include a valid host.")

    # Lowercase host while preserving username/password/port if present
    # urlsplit separates userinfo and port in netloc
    netloc = parts.netloc
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.rsplit("@", 1)
        userinfo = userinfo + "@"

    # Separate host and port
    if host_port.startswith("[") and "]" in host_port:
        # IPv6 literal
        closing_bracket = host_port.index("]")
        host = host_port[: closing_bracket + 1]
        raw_port = host_port[closing_bracket + 1 :]
    elif ":" in host_port:
        parts_colon = host_port.split(":")
        if len(parts_colon) > 2:
            raise InvalidUrlError("Malformed host and port combination.")
        host, raw_port = parts_colon[0], ":" + parts_colon[1]
    else:
        host = host_port
        raw_port = ""

    host = host.lower()
    if not host or host == "[]":
        raise InvalidUrlError("URL host cannot be empty.")

    # Validate port if specified
    normalized_port = ""
    if raw_port:
        if not raw_port.startswith(":"):
            raise InvalidUrlError("Malformed port separator.")
        port_val = raw_port[1:]
        if not port_val:
            raise InvalidUrlError("Port cannot be empty.")
        if not port_val.isdigit():
            raise InvalidUrlError(f"Invalid port '{port_val}'. Port must be numeric.")
        port_int = int(port_val)
        if not (1 <= port_int <= 65535):
            raise InvalidUrlError(f"Port {port_int} out of valid range (1-65535).")
        normalized_port = f":{port_int}"

    normalized_netloc = f"{userinfo}{host}{normalized_port}"

    # Strip fragment by passing empty string as fifth element
    path = parts.path or "/" if not parts.query else parts.path
    normalized = urlunsplit((scheme, normalized_netloc, path, parts.query, ""))
    return normalized
