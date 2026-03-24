from gophertls_api.utils.proxy import format_proxy


def test_format_proxy_without_auth() -> None:
    assert format_proxy("1.1.1.1:8080") == "http://1.1.1.1:8080"


def test_format_proxy_with_auth() -> None:
    assert format_proxy("1.1.1.1:8080:user:pass") == "http://user:pass@1.1.1.1:8080"


def test_format_proxy_invalid() -> None:
    try:
        format_proxy("bad")
        assert False
    except ValueError as exc:
        assert str(exc) == "invalid proxy format"
