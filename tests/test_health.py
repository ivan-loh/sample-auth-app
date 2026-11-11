from fastapi.testclient import TestClient


def test_health_is_200_without_a_token(api_test_client: TestClient) -> None:
    response = api_test_client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
