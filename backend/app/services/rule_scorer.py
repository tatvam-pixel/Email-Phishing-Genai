"""Rule-based scoring engine following the PhishGuard Lite policy."""

from dataclasses import dataclass
from typing import Any

from ..data import (
    BRANDS,
    BRAND_DOMAINS,
    RISKY_TLDS,
    SENSITIVE_TOKENS,
    SHARED_HOSTING_SUFFIXES,
    SHORTENERS,
    TRUSTED_DOMAINS,
    levenshtein_distance,
)
from .url_features import URLFeatures


@dataclass
class RuleEvidence:
    """Internal representation of a rule match before final ref assignment."""

    rule_id: str
    indicator: str
    points: int
    severity: str
    description: str


def _get_severity(points: int) -> str:
    """Determine severity according to Lite scoring policy:

    points >= 25: high
    10-24: medium
    1-9: low
    <= 0: info
    """
    if points >= 25:
        return "high"
    if points >= 10:
        return "medium"
    if points >= 1:
        return "low"
    return "info"


def _is_brand_legitimate_domain(brand: str, features: URLFeatures) -> bool:
    """Check if the URL belongs to a legitimate brand domain (including regional ccTLDs)."""
    official = BRAND_DOMAINS.get(brand, {f"{brand}.com"})
    if features.registered_domain in official:
        return True
    # If the domain label itself matches the brand and the suffix is not in RISKY_TLDS
    if features.domain == brand and features.suffix not in RISKY_TLDS:
        return True
    return False


def evaluate_rules(features: URLFeatures) -> tuple[int, list[dict[str, Any]]]:
    """Evaluate Lite rules U01-U12 and N01 against extracted URL features.

    Returns:
        (raw_score_sum, list of evidence dicts with refs E1, E2...)
    """
    matches: list[RuleEvidence] = []

    # U01: IP address as host (+30)
    if features.is_ip:
        matches.append(
            RuleEvidence(
                rule_id="U01",
                indicator="ip_address_host",
                points=30,
                severity=_get_severity(30),
                description=f"The host '{features.hostname}' is an IP address rather than a domain name.",
            )
        )

    # U02: "@" in URL authority (+25)
    if features.has_at_symbol:
        matches.append(
            RuleEvidence(
                rule_id="U02",
                indicator="at_symbol_in_authority",
                points=25,
                severity=_get_severity(25),
                description="The URL authority contains an '@' character, often used to conceal the true destination host.",
            )
        )

    # U03: Punycode or mixed-script host (+20)
    if features.is_punycode_or_mixed:
        matches.append(
            RuleEvidence(
                rule_id="U03",
                indicator="punycode_or_mixed_script",
                points=20,
                severity=_get_severity(20),
                description=f"The host '{features.hostname}' uses punycode or mixed-script characters, which can deceive visual inspection.",
            )
        )

    # U04: Brand lookalike (+30)
    # Registered domain within edit distance 2 of a brand, not equal to it
    if features.domain and features.domain not in BRANDS:
        matched_lookalike = None
        min_dist = 999
        for brand in BRANDS:
            dist = levenshtein_distance(features.domain, brand)
            if 1 <= dist <= 2 and dist < min_dist:
                min_dist = dist
                matched_lookalike = brand

        if matched_lookalike:
            matches.append(
                RuleEvidence(
                    rule_id="U04",
                    indicator="brand_lookalike",
                    points=30,
                    severity=_get_severity(30),
                    description=f"The domain '{features.domain}' is visually similar to brand '{matched_lookalike}' (edit distance {min_dist}).",
                )
            )

    # U05: Brand token in subdomain/path but registered domain not the brand's (+25)
    # Check tokens strictly in subdomain or path (excluding query parameters)
    subdomain_and_path_tokens = features.subdomain_tokens | features.path_tokens
    matched_brand_u05 = None
    for brand in sorted(BRANDS):
        if brand in subdomain_and_path_tokens:
            if not _is_brand_legitimate_domain(brand, features):
                matched_brand_u05 = brand
                break

    if matched_brand_u05:
        matches.append(
            RuleEvidence(
                rule_id="U05",
                indicator="brand_in_subdomain_or_path",
                points=25,
                severity=_get_severity(25),
                description=(
                    f"The brand name '{matched_brand_u05}' appears in the subdomain or path, "
                    f"but the registered domain is '{features.registered_domain}'."
                ),
            )
        )

    # U06: Subdomain depth: 3 labels = +5, 4+ labels = +10
    if features.subdomain_depth >= 4:
        matches.append(
            RuleEvidence(
                rule_id="U06",
                indicator="excessive_subdomain_depth",
                points=10,
                severity=_get_severity(10),
                description=f"Excessive subdomain depth ({features.subdomain_depth} labels).",
            )
        )
    elif features.subdomain_depth == 3:
        matches.append(
            RuleEvidence(
                rule_id="U06",
                indicator="high_subdomain_depth",
                points=5,
                severity=_get_severity(5),
                description="Subdomain depth is 3 labels.",
            )
        )

    # U07: Risky TLD (+10)
    if features.suffix in RISKY_TLDS:
        matches.append(
            RuleEvidence(
                rule_id="U07",
                indicator="risky_tld",
                points=10,
                severity=_get_severity(10),
                description=f"The .{features.suffix} top-level domain is frequently associated with phishing campaigns.",
            )
        )

    # U08: Known shortener (+10)
    if features.registered_domain in SHORTENERS or features.hostname in SHORTENERS:
        matches.append(
            RuleEvidence(
                rule_id="U08",
                indicator="url_shortener",
                points=10,
                severity=_get_severity(10),
                description="The URL uses a known link-shortening service that conceals the destination.",
            )
        )

    # U09: Sensitive tokens (+5 each, max 15)
    matched_sensitive = sorted(features.tokens & SENSITIVE_TOKENS)
    if matched_sensitive:
        counted = min(len(matched_sensitive), 3)
        points = counted * 5
        tokens_str = ", ".join(matched_sensitive[:counted])
        matches.append(
            RuleEvidence(
                rule_id="U09",
                indicator="sensitive_tokens",
                points=points,
                severity=_get_severity(points),
                description=f"The URL contains sensitive keywords ({tokens_str}) commonly targeted in phishing lures.",
            )
        )

    # U10: URL longer than 100 characters (+5)
    if features.url_length > 100:
        matches.append(
            RuleEvidence(
                rule_id="U10",
                indicator="long_url",
                points=5,
                severity=_get_severity(5),
                description=f"The URL length ({features.url_length} characters) exceeds 100 characters.",
            )
        )

    # U11: Scheme is http (+5)
    if features.scheme == "http":
        matches.append(
            RuleEvidence(
                rule_id="U11",
                indicator="http_scheme",
                points=5,
                severity=_get_severity(5),
                description="The URL uses unencrypted HTTP rather than HTTPS.",
            )
        )

    # U12: 3+ hyphens in registered domain (+5)
    if features.registered_domain.count("-") >= 3:
        matches.append(
            RuleEvidence(
                rule_id="U12",
                indicator="hyphens_in_domain",
                points=5,
                severity=_get_severity(5),
                description=f"The registered domain '{features.registered_domain}' contains 3 or more hyphens.",
            )
        )

    # N01: Registered domain in trusted domain list (-25)
    if (
        features.registered_domain in TRUSTED_DOMAINS
        and features.registered_domain not in SHARED_HOSTING_SUFFIXES
        and features.suffix not in SHARED_HOSTING_SUFFIXES
    ):
        matches.append(
            RuleEvidence(
                rule_id="N01",
                indicator="trusted_domain",
                points=-25,
                severity=_get_severity(-25),
                description=f"The registered domain '{features.registered_domain}' is recognized in the trusted domains list.",
            )
        )

    # Calculate sum and build evidence items with sequential refs E1, E2...
    raw_sum = sum(m.points for m in matches)
    evidence: list[dict[str, Any]] = []
    for idx, m in enumerate(matches, start=1):
        evidence.append(
            {
                "ref": f"E{idx}",
                "indicator": m.indicator,
                "severity": m.severity,
                "description": m.description,
            }
        )

    return raw_sum, evidence
