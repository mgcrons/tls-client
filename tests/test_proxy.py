import pytest

from gophertls_api.utils.proxy import ProxyType, format_proxy, parse_proxy_type


def test_format_proxy_without_auth() -> None:
    assert format_proxy("1.1.1.1:8080") == "http://1.1.1.1:8080"


def test_format_proxy_with_auth() -> None:
    assert format_proxy("1.1.1.1:8080:user:pass") == (
        "http://user:pass@1.1.1.1:8080"
    )


def test_format_proxy_socks5() -> None:
    assert format_proxy("1.1.1.1:1080", ProxyType.SOCKS5) == (
        "socks5://1.1.1.1:1080"
    )


def test_format_proxy_socks4_with_auth() -> None:
    assert (
        format_proxy("1.1.1.1:1080:u:p", ProxyType.SOCKS4)
        == "socks4://u:p@1.1.1.1:1080"
    )


def test_format_proxy_invalid() -> None:
    with pytest.raises(ValueError, match="invalid proxy format"):
        format_proxy("bad")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", ProxyType.HTTP),
        ("HTTP", ProxyType.HTTP),
        ("http", ProxyType.HTTP),
        ("SOCKS4", ProxyType.SOCKS4),
        ("socks4", ProxyType.SOCKS4),
        ("SOCKS5", ProxyType.SOCKS5),
        ("SOCK-S5", ProxyType.SOCKS5),
        (None, ProxyType.HTTP),
    ],
)
def test_parse_proxy_type_ok(raw: str | None, expected: ProxyType) -> None:
    assert parse_proxy_type(raw) == expected


def test_parse_proxy_type_invalid() -> None:
    with pytest.raises(ValueError, match="invalid proxy type"):
        parse_proxy_type("socks")
