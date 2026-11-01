import math
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import g, render_template, request


BASE_DIR = Path(__file__).resolve().parent

WINDOW_SECONDS = 300
BLOCK_SECONDS = 300
PAIR_THRESHOLD = 5
IP_THRESHOLD = 20


def register_login_security(app):
    database = BASE_DIR / "instance" / "security.db"

    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS login_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                time_utc TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                event TEXT NOT NULL,
                reason TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_login_events_lookup
            ON login_events (ip, event, timestamp);

            CREATE TABLE IF NOT EXISTS login_blocks (
                ip TEXT NOT NULL,
                scope TEXT NOT NULL,
                username TEXT NOT NULL,
                blocked_until REAL NOT NULL,
                PRIMARY KEY (ip, scope, username)
            );
        """)

    def record_event(db, timestamp, ip, username, event, reason):
        time_utc = datetime.fromtimestamp(
            timestamp, tz=timezone.utc
        ).isoformat(timespec="seconds")

        db.execute(
            """
            INSERT INTO login_events
                (timestamp, time_utc, ip, username, event, reason)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, time_utc, ip, username, event, reason),
        )

    @app.before_request
    def check_login_limit():
        if request.endpoint != "login" or request.method != "POST":
            return None

        # CSRFProtect da duoc dang ky truoc hook nay trong app.py.
        # Khong tin X-Forwarded-For do client tu gui.
        ip = request.remote_addr or "unknown"

        username = request.form.get(
            "username", ""
        ).strip().casefold()[:64]

        db = sqlite3.connect(database, timeout=10)
        db.row_factory = sqlite3.Row
        g.security_db = db

        try:
            # Tuan tu hoa kiem tra + cap nhat de tranh vuot nguong
            # khi co nhieu request dong thoi trong ban demo SQLite.
            db.execute("BEGIN IMMEDIATE")

            now = time.time()

            db.execute(
                "DELETE FROM login_blocks WHERE blocked_until <= ?",
                (now,),
            )

            block = db.execute(
                """
                SELECT blocked_until
                FROM login_blocks
                WHERE ip = ?
                  AND (
                    scope = 'ip'
                    OR (scope = 'pair' AND username = ?)
                  )
                ORDER BY blocked_until DESC
                LIMIT 1
                """,
                (ip, username),
            ).fetchone()

            if block:
                remaining = max(
                    1, math.ceil(block["blocked_until"] - now)
                )

                record_event(
                    db, now, ip, username,
                    "blocked", "active_temporary_block",
                )
                db.commit()

                response = app.make_response((
                    render_template(
                        "login.html",
                        message=(
                            "Tạm giới hạn đăng nhập. "
                            f"Vui lòng thử lại sau {remaining} giây."
                        ),
                    ),
                    429,
                ))
                response.headers["Retry-After"] = str(remaining)
                return response

            g.login_security_context = (ip, username)
            return None

        except sqlite3.Error:
            db.rollback()
            app.logger.exception("Login security database error")

            return render_template(
                "login.html",
                message="Dịch vụ đang bận. Vui lòng thử lại sau.",
            ), 503

    @app.after_request
    def record_login_result(response):
        context = getattr(g, "login_security_context", None)

        if context is None:
            return response

        db = g.security_db
        ip, username = context
        now = time.time()

        try:
            if response.status_code == 401:
                record_event(
                    db, now, ip, username,
                    "failure", "invalid_credentials",
                )

                cutoff = now - WINDOW_SECONDS

                pair_count = db.execute(
                    """
                    SELECT COUNT(*)
                    FROM login_events
                    WHERE ip = ?
                      AND username = ?
                      AND event = 'failure'
                      AND timestamp > ?
                    """,
                    (ip, username, cutoff),
                ).fetchone()[0]

                ip_count = db.execute(
                    """
                    SELECT COUNT(*)
                    FROM login_events
                    WHERE ip = ?
                      AND event = 'failure'
                      AND timestamp > ?
                    """,
                    (ip, cutoff),
                ).fetchone()[0]

                limits = [
                    (
                        "pair",
                        username,
                        pair_count,
                        PAIR_THRESHOLD,
                        "pair_failure_threshold",
                    ),
                    (
                        "ip",
                        "",
                        ip_count,
                        IP_THRESHOLD,
                        "ip_failure_threshold",
                    ),
                ]

                blocked = False

                for scope, target, count, threshold, reason in limits:
                    if count < threshold:
                        continue

                    db.execute(
                        """
                        INSERT INTO login_blocks
                            (ip, scope, username, blocked_until)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(ip, scope, username)
                        DO UPDATE SET
                            blocked_until = excluded.blocked_until
                        """,
                        (ip, scope, target, now + BLOCK_SECONDS),
                    )

                    record_event(
                        db, now, ip, username,
                        "alert", reason,
                    )
                    blocked = True

                if blocked:
                    response = app.make_response((
                        render_template(
                            "login.html",
                            message=(
                                "Có nhiều lần đăng nhập thất bại. "
                                "Tạm giới hạn đăng nhập trong 5 phút."
                            ),
                        ),
                        429,
                    ))
                    response.headers["Retry-After"] = str(
                        BLOCK_SECONDS
                    )

            elif (
                response.status_code == 302
                and response.headers.get("Location") == "/dashboard"
            ):
                record_event(
                    db, now, ip, username,
                    "success", "authenticated",
                )

            db.commit()

        except sqlite3.Error:
            db.rollback()
            app.logger.exception("Cannot record login security event")

            # Khong tra ve redirect thanh cong neu khong ghi duoc log.
            from flask import session
            session.clear()

            response = app.make_response((
                render_template(
                    "login.html",
                    message="Dịch vụ đang bận. Vui lòng thử lại sau.",
                ),
                503,
            ))

        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"

        return response

    @app.teardown_request
    def close_security_database(error=None):
        db = g.pop("security_db", None)

        if db is not None:
            db.rollback()
            db.close()