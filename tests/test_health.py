import pytest

from app import create_app


@pytest.fixture
def client():
    application = create_app()
    application.config.update(TESTING=True)
    with application.test_client() as test_client:
        yield test_client


def test_health_returns_ok(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
