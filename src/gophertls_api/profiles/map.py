"""
Map tls-client style ``x-tls-profile`` IDs to curl_cffi ``impersonate`` targets.

tls-client names (bogdanfinn) often use underscores and newer browser versions than
libcurl-impersonate exposes; this table picks the closest supported target.
Pass-through: any value that is already a valid ``BrowserType`` string is accepted.
"""

from __future__ import annotations

from curl_cffi.requests.impersonate import BrowserType

# Explicit tls-client / common aliases -> curl_cffi impersonate string
TLS_CLIENT_TO_CURL: dict[str, str] = {
    # Firefox (example client uses firefox_147)
    "firefox_147": "firefox144",
    "firefox_144": "firefox144",
    "firefox_135": "firefox135",
    "firefox_133": "firefox133",
    # Chrome
    "chrome_142": "chrome142",
    "chrome_136": "chrome136",
    "chrome_133": "chrome133a",
    "chrome_131": "chrome131",
    "chrome_124": "chrome124",
    "chrome_123": "chrome123",
    "chrome_120": "chrome120",
    "chrome_119": "chrome119",
    "chrome_116": "chrome116",
    "chrome_110": "chrome110",
    "chrome_107": "chrome107",
    "chrome_104": "chrome104",
    "chrome_101": "chrome101",
    "chrome_100": "chrome100",
    "chrome_99": "chrome99",
    "chrome_99_android": "chrome99_android",
    "chrome_131_android": "chrome131_android",
    # Safari
    "safari_2601": "safari2601",
    "safari_260": "safari260",
    "safari_260_ios": "safari260_ios",
    "safari_184": "safari184",
    "safari_184_ios": "safari184_ios",
    "safari_180": "safari180",
    "safari_180_ios": "safari180_ios",
    "safari_172_ios": "safari172_ios",
    "safari_170": "safari170",
    "safari_155": "safari155",
    "safari_153": "safari153",
    # Edge
    "edge_101": "edge101",
    "edge_99": "edge99",
    # Tor
    "tor_145": "tor145",
}

_VALID_IMPERSONATE = frozenset(m.value for m in BrowserType)


def resolve_impersonate(profile: str) -> str:
    """
    Resolve ``x-tls-profile`` to a curl_cffi impersonate target.

    Raises:
        ValueError: if the profile cannot be mapped or is not a known impersonate string.
    """
    key = profile.strip()
    if not key:
        raise ValueError("empty client profile")
    candidate = TLS_CLIENT_TO_CURL.get(key, key)
    if candidate not in _VALID_IMPERSONATE:
        raise ValueError(f"invalid client profile: {profile}")
    return candidate


def list_known_profiles() -> tuple[str, ...]:
    """Sorted tls-client-style keys plus note that raw curl targets also work."""
    return tuple(sorted(TLS_CLIENT_TO_CURL.keys()))
