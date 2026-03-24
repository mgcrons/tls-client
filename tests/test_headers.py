from gophertls_api.models.tls_request import build_forward_headers


def test_build_forward_headers_strips_tls_headers() -> None:
    incoming = [
        ("x-tls-url", "https://example.com"),
        ("User-Agent", "UA"),
        ("Accept", "*/*"),
        ("Content-Length", "99"),
    ]
    out = build_forward_headers(incoming, ["Accept", "User-Agent"], "GET")
    assert out == [("Accept", "*/*"), ("User-Agent", "UA")]


def test_build_forward_headers_drops_content_type_for_get() -> None:
    incoming = [("Content-Type", "application/json"), ("Accept", "*/*")]
    out = build_forward_headers(incoming, ["Accept"], "GET")
    assert out == [("Accept", "*/*")]


def test_build_forward_headers_drops_host() -> None:
    incoming = [("Host", "127.0.0.1"), ("Accept", "*/*")]
    out = build_forward_headers(incoming, ["Accept"], "GET")
    assert out == [("Accept", "*/*")]
