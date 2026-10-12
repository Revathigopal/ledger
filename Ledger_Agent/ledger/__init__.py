"""Ledger application package - use ``create_app()`` to build the Flask app."""

from __future__ import annotations

import logging
import os
import secrets
from datetime import timedelta
from typing import Any

from flask import Flask, render_template

from .db import Database
from .security import init_security
from .services import LedgerService

log = logging.getLogger("ledger")


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("LEDGER_SECRET_KEY") or secrets.token_hex(32),
        RATES_DB=os.environ.get("LEDGER_RATES_DB", "data/rates.db"),
        ADMIN_USERNAME=os.environ.get("LEDGER_ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.environ.get("LEDGER_ADMIN_PASSWORD"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("LEDGER_SECURE_COOKIES") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=16 * 1024,  # forms are tiny; reject large bodies
        DEMO=False,
    )
    if config:
        app.config.update(config)

    db = Database(app.config["RATES_DB"])
    service = LedgerService(db)
    app.extensions["ledger_db"] = db
    app.extensions["ledger"] = service

    if service.admin_count() == 0:
        password = app.config["ADMIN_PASSWORD"]
        if not password:
            password = secrets.token_urlsafe(12) + "9a"
            log.warning(
                "No LEDGER_ADMIN_PASSWORD set - generated admin password: %s", password
            )
            print(f" * Admin login -> username: {app.config['ADMIN_USERNAME']}  "
                  f"password: {password}", flush=True)
        service.bootstrap_admin(app.config["ADMIN_USERNAME"], password)

    init_security(app)

    from .web import bp
    app.register_blueprint(bp)

    for code in (400, 403, 404, 405, 413):
        app.register_error_handler(code, _error_page)
    return app


def _error_page(err):
    return render_template("error.html", error=err), err.code
