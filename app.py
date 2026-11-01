import os
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path
from login_security import register_login_security

import click
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError
from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect


BASE_DIR = Path(__file__).resolve().parent

HASHER = PasswordHasher(type=Type.ID)

# Dung de van thuc hien verify khi username khong ton tai
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            BASE_DIR / "instance" / "security.db",
            timeout=10,
        )
        g.db.row_factory = sqlite3.Row

    return g.db


def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    CSRFProtect(app)

    # Thu muc database duoc tao tu dong
    (BASE_DIR / "instance").mkdir(exist_ok=True)

    @app.teardown_appcontext
    def close_db(error=None):
        db = g.pop("db", None)

        if db is not None:
            db.close()

    with app.app_context():
        db = get_db()

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)

        # Bo sung cot cho database da tao o buoc truoc
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(users)")
        }

        if "is_admin" not in columns:
            db.execute("""
                ALTER TABLE users
                ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0
            """)

        db.commit()

    @app.cli.command("create-user")
    @click.option("--username", prompt="Username")
    @click.password_option(
        confirmation_prompt=True,
        help="Mat khau cua tai khoan moi.",
    )
    def create_user(username, password):
        """Tao tai khoan tu terminal, khong hardcode mat khau."""
        username = username.strip().casefold()

        if not 3 <= len(username) <= 64:
            raise click.ClickException(
                "Username can tu 3 den 64 ky tu."
            )

        if not 8 <= len(password) <= 128 or password.isspace():
            raise click.ClickException(
                "Mat khau can tu 8 den 128 ky tu, "
                "khong duoc chi co khoang trang."
            )

        password_hash = HASHER.hash(password)
        db = get_db()

        try:
            db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            raise click.ClickException("Username da ton tai.")

        click.echo(f"Da tao tai khoan: {username}")

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.route("/", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        message = None
        status_code = 200

        if request.method == "POST":
            username = request.form.get(
                "username", ""
            ).strip().casefold()

            password = request.form.get("password", "")

            if (
                not 3 <= len(username) <= 64
                or not 1 <= len(password) <= 128
            ):
                message = "Tên đăng nhập hoặc mật khẩu không đúng."
                status_code = 401
            else:
                db = get_db()

                user = db.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username,),
                ).fetchone()

                encoded_hash = (
                    user["password_hash"] if user else DUMMY_HASH
                )

                verified = False

                try:
                    HASHER.verify(encoded_hash, password)
                    verified = user is not None
                except (VerificationError, InvalidHashError):
                    verified = False

                if verified:
                    # Cap nhat hash neu cau hinh thu vien thay doi
                    if HASHER.check_needs_rehash(encoded_hash):
                        db.execute(
                            """
                            UPDATE users
                            SET password_hash = ?
                            WHERE id = ?
                            """,
                            (HASHER.hash(password), user["id"]),
                        )
                        db.commit()

                    session.clear()
                    session["user_id"] = user["id"]
                    session.permanent = True

                    return redirect(url_for("dashboard"))

                message = "Tên đăng nhập hoặc mật khẩu không đúng."
                status_code = 401

        return (
            render_template("login.html", message=message),
            status_code,
        )

    @app.get("/dashboard")
    def dashboard():
        user_id = session.get("user_id")

        if not user_id:
            return redirect(url_for("login"))

        user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        return render_template("dashboard.html", user=user)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
    @app.cli.command("promote-admin")
    @click.option("--username", prompt="Username")
    def promote_admin(username):
        """Cap quyen quan tri tu terminal."""
        username = username.strip().casefold()
        db = get_db()

        cursor = db.execute(
            "UPDATE users SET is_admin = 1 WHERE username = ?",
            (username,),
        )
        db.commit()

        if cursor.rowcount == 0:
            raise click.ClickException("Khong tim thay tai khoan.")

        click.echo(f"Da cap quyen quan tri cho: {username}")

    @app.get("/security")
    def security_dashboard():
        user_id = session.get("user_id")

        if not user_id:
            return redirect(url_for("login"))

        db = get_db()

        user = db.execute(
            "SELECT id, username, is_admin FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        if not user["is_admin"]:
            abort(403)

        events = db.execute("""
            SELECT id, time_utc, ip, username, event, reason
            FROM login_events
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

        counts = {
            row["event"]: row["total"]
            for row in db.execute("""
                SELECT event, COUNT(*) AS total
                FROM login_events
                GROUP BY event
            """)
        }

        return render_template(
            "security.html",
            events=events,
            counts=counts,
        )
    register_login_security(app)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)