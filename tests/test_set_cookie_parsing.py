from datetime import datetime, timezone

from gophertls_api.utils.set_cookie import parse_set_cookie_header


def test_parse_set_cookie_basic_flags() -> None:
    parsed = parse_set_cookie_header(
        "dtCookie=abc123; Path=/; Secure; HttpOnly; SameSite=None"
    )
    assert parsed is not None
    assert parsed["key"] == "dtCookie"
    assert parsed["value"] == "abc123"
    assert parsed["path"] == "/"
    assert parsed["secure"] is True
    assert parsed["httponly"] is True
    assert parsed["samesite"] == "none"


def test_parse_set_cookie_domain_and_expires() -> None:
    parsed = parse_set_cookie_header(
        "foo=bar; Domain=example.com; Path=/app; "
        "Expires=Wed, 25 Mar 2026 11:38:55 GMT; Secure"
    )
    assert parsed is not None
    assert parsed["key"] == "foo"
    assert parsed["domain"] == "example.com"
    assert parsed["path"] == "/app"
    assert parsed["secure"] is True
    expires = parsed.get("expires")
    assert isinstance(expires, datetime)
    assert expires.tzinfo is not None
    assert expires == datetime(2026, 3, 25, 11, 38, 55, tzinfo=timezone.utc)


def test_parse_set_cookie_max_age() -> None:
    parsed = parse_set_cookie_header("a=b; Max-Age=3600; Path=/")
    assert parsed is not None
    assert parsed["key"] == "a"
    assert parsed["max_age"] == 3600
