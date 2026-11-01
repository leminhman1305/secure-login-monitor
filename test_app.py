import html
import re
import sqlite3
from types import SimpleNamespace

import pytest

import app as app_module
import login_security


@pytest.fixture
def web_app(tmp_path, monkeypatch):
    # Chuyen database cua ung dung va bo bao ve
    # sang thu muc tam rieng cho moi test
    monkeypatch.setattr(app_module, "BASE_DIR", tmp_path)
    monkeypatch.setattr(login_security, "BASE_DIR", tmp_path)

    # Dong ho gia: kiem tra het han chan ma khong cho 5 phut
    clock = {"now": 1800000000.0}
    monkeypatch.setattr(
        login_security,
        "time",
        SimpleNamespace(time=lambda: clock["now"]),
    )

    application = app_module.create_app()
    application.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret-key",
    )

    database = tmp_path / "instance" / "security.db"

    with sqlite3.connect(database) as db:
        encoded_hash = app_module.HASHER.hash("Demo-R7!k2@p9")

        db.executemany(
            """
            INSERT INTO users (username, password_hash, is_admin)
            VALUES (?, ?, ?)
            """,
            [
                ("admin", encoded_hash, 1),
                ("testuser", encoded_hash, 0),
            ],
        )

    return application, database, clock


def submit_login(client, username, password):
    page = client.get("/")

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        page.get_data(as_text=True),
    )
    assert match is not None, "Khong tim thay CSRF token trong form"

    return client.post(
        "/",
        data={
            "username": username,
            "password": password,
            "csrf_token": html.unescape(match.group(1)),
        },
    )


def test_login_success_and_log(web_app):
    application, database, _ = web_app
    client = application.test_client()

    response = submit_login(client, "admin", "Demo-R7!k2@p9")

    assert response.status_code == 302
    assert response.headers["Location"] == "/dashboard"
    assert client.get("/dashboard").status_code == 200

    with sqlite3.connect(database) as db:
        event = db.execute(
            """
            SELECT event, ip
            FROM login_events
            ORDER BY id DESC LIMIT 1
            """
        ).fetchone()

    assert event == ("success", "127.0.0.1")


def test_wrong_password(web_app):
    application, database, _ = web_app
    client = application.test_client()

    response = submit_login(client, "admin", "Wrong-password!")

    assert response.status_code == 401

    with sqlite3.connect(database) as db:
        count = db.execute(
            "SELECT COUNT(*) FROM login_events WHERE event = 'failure'"
        ).fetchone()[0]

    assert count == 1


def test_pair_block_and_expiry(web_app):
    application, _, clock = web_app
    client = application.test_client()

    for _ in range(4):
        response = submit_login(client, "admin", "Wrong-password!")
        assert response.status_code == 401

    response = submit_login(client, "admin", "Wrong-password!")
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0

    # Mat khau dung cung khong vuot qua thoi gian chan
    response = submit_login(client, "admin", "Demo-R7!k2@p9")
    assert response.status_code == 429

    clock["now"] += 301

    response = submit_login(client, "admin", "Demo-R7!k2@p9")
    assert response.status_code == 302


def test_ip_block_across_usernames(web_app):
    application, _, _ = web_app
    client = application.test_client()

    for index in range(19):
        response = submit_login(
            client, f"unknown{index}", "Wrong-password!"
        )
        assert response.status_code == 401

    response = submit_login(client, "unknown19", "Wrong-password!")
    assert response.status_code == 429

    # IP da bi chan du thu username khac va mat khau dung
    response = submit_login(client, "admin", "Demo-R7!k2@p9")
    assert response.status_code == 429


def test_security_permissions(web_app):
    application, _, _ = web_app

    anonymous = application.test_client()
    assert anonymous.get("/security").status_code == 302

    regular = application.test_client()
    submit_login(regular, "testuser", "Demo-R7!k2@p9")
    assert regular.get("/security").status_code == 403

    admin = application.test_client()
    submit_login(admin, "admin", "Demo-R7!k2@p9")
    assert admin.get("/security").status_code == 200


def test_missing_csrf_is_rejected(web_app):
    application, _, _ = web_app
    client = application.test_client()

    response = client.post(
        "/",
        data={
            "username": "admin",
            "password": "Demo-R7!k2@p9",
        },
    )

    assert response.status_code == 400