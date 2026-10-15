import pytest

from app import create_app


@pytest.fixture
def app(tmp_path):
    application = create_app()
    application.config.update(
        TESTING=True,
        DATABASE=str(tmp_path / "doomvault.db"),
    )
    yield application


@pytest.fixture
def client(app):
    with app.test_client() as test_client:
        yield test_client
