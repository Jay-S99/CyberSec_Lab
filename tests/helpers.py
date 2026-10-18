import re
from urllib.parse import urlparse

from database import get_db, init_db
from seed import seed_database


def prepare_database(app):
    with app.app_context():
        init_db()
        seed_database()


def provision(app, username):
    result = app.test_cli_runner().invoke(args=["provision-user", username])
    assert result.exit_code == 0, result.output
    match = re.search(r"^Temporary password: (\S+)$", result.output, re.MULTILINE)
    assert match, result.output
    return match.group(1)


def csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, html
    return match.group(1)


def page_text(response):
    return response.get_data(as_text=True)


def location_path(response):
    return urlparse(response.location).path


def post_login(client, username, password, query=""):
    page = client.get("/login")
    token = csrf_token(page_text(page))
    return client.post(
        "/login" + query,
        data={
            "username": username,
            "password": password,
            "csrf_token": token,
        },
        follow_redirects=False,
    )


def submit_password_change(
    client,
    new_password,
    confirmation=None,
    current_password=None,
):
    page = client.get("/password/change")
    token = csrf_token(page_text(page))
    data = {
        "new_password": new_password,
        "confirmation": new_password if confirmation is None else confirmation,
        "csrf_token": token,
    }
    if current_password is not None:
        data["current_password"] = current_password
    return client.post("/password/change", data=data, follow_redirects=False)


def session_token(client):
    cookie = client.get_cookie("doomvault_session")
    if cookie is None:
        return None
    return cookie.decoded_value


def user_row(app, username):
    with app.app_context():
        return get_db().execute(
            """
            SELECT
                id,
                username,
                password_hash,
                is_active,
                is_blocked,
                must_change_password,
                password_changed_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
