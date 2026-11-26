"""Constants and reference data for URL scoring (Lite policy)."""

# Popular brands frequently targeted by phishing campaigns
BRANDS: set[str] = {
    "paypal",
    "google",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "citi",
    "binance",
    "coinbase",
    "dropbox",
    "yahoo",
    "ebay",
    "adobe",
    "linkedin",
    "twitter",
    "spotify",
    "roblox",
    "steam",
    "telegram",
    "discord",
    "tiktok",
}

# Mapping of brand name to its primary legitimate registered domain(s)
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.co.jp", "google.co.in"},
    "apple": {"apple.com", "icloud.com", "apple.co"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "windows.com"},
    "amazon": {"amazon.com", "aws.amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.co.jp", "amazon.ca"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citibank.com", "citi.com"},
    "citi": {"citi.com", "citibank.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "dropbox": {"dropbox.com"},
    "yahoo": {"yahoo.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "adobe": {"adobe.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "spotify": {"spotify.com"},
    "roblox": {"roblox.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "telegram": {"telegram.org"},
    "discord": {"discord.com", "discord.gg"},
    "tiktok": {"tiktok.com"},
}

# Small curated list of about 30 trusted popular domains (N01)
TRUSTED_DOMAINS: set[str] = {
    "google.com",
    "google.co.uk",
    "paypal.com",
    "paypal.me",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "amazon.co.uk",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "citibank.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "wikipedia.org",
    "youtube.com",
    "yahoo.com",
    "bing.com",
    "cloudflare.com",
    "dropbox.com",
    "adobe.com",
    "spotify.com",
    "zoom.us",
    "slack.com",
    "reddit.com",
    "ebay.com",
    "github.com",
}

# Shared hosting or user-generated content suffixes (not trusted as an entity)
SHARED_HOSTING_SUFFIXES: set[str] = {
    "github.io",
    "blogspot.com",
    "vercel.app",
    "pages.dev",
    "webflow.io",
    "wordpress.com",
    "firebaseapp.com",
    "netlify.app",
    "herokuapp.com",
    "wixsite.com",
}

# Top-level domains commonly abused in phishing attacks
RISKY_TLDS: set[str] = {
    "tk",
    "xyz",
    "top",
    "zip",
    "click",
    "fit",
    "country",
    "cf",
    "ga",
    "gq",
    "ml",
    "work",
    "link",
    "tokyo",
    "bid",
    "loan",
    "racing",
    "download",
    "stream",
    "trade",
    "monster",
    "cam",
}

# Known URL shorteners
SHORTENERS: set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bitly.com",
    "tiny.cc",
    "rb.gy",
    "cutt.ly",
    "rebrand.ly",
}

# Sensitive tokens commonly found in phishing lures
SENSITIVE_TOKENS: set[str] = {
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
}

# Fixed baseline limitations
LIMITATIONS: list[str] = [
    "The page itself was not inspected.",
    "No threat database was checked.",
    "Low risk does not confirm that a URL is safe.",
]

# Baseline security recommendations
BASELINE_RECOMMENDATIONS: list[str] = [
    "Never enter passwords, PINs, or sensitive credentials on unverified websites.",
    "Verify the destination by navigating directly to the official service website.",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings without third-party dependencies."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    len_s2 = len(s2)
    prev_row = list(range(len_s2 + 1))

    for i, c1 in enumerate(s1):
        curr_row = [i + 1] * (len_s2 + 1)
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row[j + 1] = min(
                curr_row[j] + 1,       # insertion
                prev_row[j + 1] + 1,   # deletion
                prev_row[j] + cost,    # substitution
            )
        prev_row = curr_row

    return prev_row[len_s2]
