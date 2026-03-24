from fastapi.testclient import TestClient

from gophertls_api.app import app


def test_error_shape_on_missing_headers() -> None:
    client = TestClient(app)
    response = client.post("/go/pher")
    assert response.status_code == 500
    assert response.json().get("success") is False
    assert "error while extracting tls data" in response.json().get("message", "")
