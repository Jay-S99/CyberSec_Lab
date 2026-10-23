import pytest

from tests.helpers import csrf_token, location_path, page_text


@pytest.mark.parametrize(
    "destination",
    (
        "///evil.example/phish",
        "/\\evil.example/phish",
        "/safe\r\nX-Test: injected",
    ),
)
def test_language_switch_rejects_unsafe_return_paths(client, destination):
    login_page = client.get("/login")

    response = client.post(
        "/language",
        data={
            "csrf_token": csrf_token(page_text(login_page)),
            "language": "pl",
            "next": destination,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert location_path(response) == "/login"
    assert "evil.example" not in response.location
    assert "X-Test" not in response.location


def test_language_switch_accepts_same_origin_return_path(client):
    login_page = client.get("/login")

    response = client.post(
        "/language",
        data={
            "csrf_token": csrf_token(page_text(login_page)),
            "language": "pl",
            "next": "/login?notice=session-expired",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.location.endswith("/login?notice=session-expired")


def test_language_switch_rejects_unsupported_language(client):
    login_page = client.get("/login")

    response = client.post(
        "/language",
        data={
            "csrf_token": csrf_token(page_text(login_page)),
            "language": "de",
            "next": "/login",
        },
    )

    assert response.status_code == 400
