"""URL feature extraction service using offline tldextract."""

from dataclasses import dataclass, field
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

import tldextract

_extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")


@dataclass
class URLFeatures:
    """Extracted syntactic and structural features from a normalized URL."""

    url: str
    scheme: str
    netloc: str
    hostname: str
    port: int | None
    path: str
    query: str
    has_at_symbol: bool
    is_ip: bool
    is_punycode_or_mixed: bool
    subdomain: str
    subdomain_depth: int
    domain: str
    suffix: str
    registered_domain: str
    tokens: set[str] = field(default_factory=set)
    subdomain_tokens: set[str] = field(default_factory=set)
    path_tokens: set[str] = field(default_factory=set)
    query_tokens: set[str] = field(default_factory=set)
    url_length: int = 0


def _is_ip_address(host: str) -> bool:
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def _get_char_script(char: str) -> str | None:
    """Identify the script of an alphabetic character via Unicode character name."""
    try:
        first = unicodedata.name(char).split()[0]
        if first in {
            "LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW",
            "DEVANAGARI", "BENGALI", "HIRAGANA", "KATAKANA", "CJK",
            "HANGUL", "THAI", "GEORGIAN", "ARMENIAN",
        }:
            return first
    except ValueError:
        pass
    return None


def _is_mixed_script(host: str) -> bool:
    """Check if host mixes characters from more than one alphabet/script."""
    scripts = set()
    for char in host:
        if char.isalpha():
            script = _get_char_script(char)
            if script:
                scripts.add(script)
                if len(scripts) > 1:
                    return True
    return False


def _is_punycode_or_mixed(host: str) -> bool:
    """Detect punycode or mixed-script host per U03.

    Ordinary single-script internationalized domains (e.g. pure Cyrillic or Arabic)
    are not treated as mixed script.
    """
    if "xn--" in host.lower():
        return True
    if _is_mixed_script(host):
        return True
    return False


def extract_features(normalized_url: str) -> URLFeatures:
    """Extract offline features from a normalized URL."""
    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower()

    # Authority check (@ in netloc)
    has_at_symbol = "@" in parsed.netloc

    # IP address check
    is_ip = _is_ip_address(hostname)

    # Punycode or non-ascii check
    is_punycode = _is_punycode_or_mixed(hostname)

    # Offline tldextract
    ext = _extractor(normalized_url)
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    domain = ext.domain.lower() if ext.domain else ""
    suffix = ext.suffix.lower() if ext.suffix else ""
    reg_domain = f"{domain}.{suffix}" if (domain and suffix) else domain

    # Subdomain depth: count of non-empty dot-separated labels
    subdomain_labels = [p for p in subdomain.split(".") if p]
    subdomain_depth = len(subdomain_labels)

    # Token extraction (split on non-alphanumeric characters)
    subdomain_tokens = {t.lower() for t in _TOKEN_SPLIT_RE.split(subdomain) if t}
    path_tokens = {t.lower() for t in _TOKEN_SPLIT_RE.split(parsed.path) if t}
    query_tokens = {t.lower() for t in _TOKEN_SPLIT_RE.split(parsed.query) if t}
    all_tokens = subdomain_tokens | path_tokens | query_tokens

    return URLFeatures(
        url=normalized_url,
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc,
        hostname=hostname,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
        has_at_symbol=has_at_symbol,
        is_ip=is_ip,
        is_punycode_or_mixed=is_punycode,
        subdomain=subdomain,
        subdomain_depth=subdomain_depth,
        domain=domain,
        suffix=suffix,
        registered_domain=reg_domain,
        tokens=all_tokens,
        subdomain_tokens=subdomain_tokens,
        path_tokens=path_tokens,
        query_tokens=query_tokens,
        url_length=len(normalized_url),
    )
