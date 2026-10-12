"""Web-layer security: sessions, CSRF protection, role decorators, headers."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from functools import wraps

from flask import Flask, abort, current_app, g, redirect, request, session, url_for

from .services import LedgerService, NotFound

CSRF_FIELD = "csrf_token"


def csrf_token() -> str:
    token = session.get("_csrf")
    if token is None:
        token = session["_csrf"] = secrets.token_urlsafe(32)
    return token


def _check_csrf() -> None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    expected = session.get("_csrf")
    supplied = request.form.get(CSRF_FIELD) or request.headers.get("X-CSRF-Token")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Missing or invalid CSRF token.")


def _load_user() -> None:
    g.user = None
    uid = session.get("uid")
    if uid is None:
        return
    service: LedgerService = current_app.extensions["ledger"]
    try:
        g.user = service.get_account(uid)
    except NotFound:  # account was deleted while logged in
        session.clear()


def _security_headers(response):
    h = response.headers
    h["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    h["X-Frame-Options"] = "DENY"
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if g.get("user") is not None:
        h["Cache-Control"] = "no-store"
    return response


def init_security(app: Flask) -> None:
    app.before_request(_load_user)
    app.before_request(_check_csrf)
    app.after_request(_security_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token


def login_user(account_id: int) -> None:
    session.clear()  # prevent session fixation
    session.permanent = True
    session["uid"] = account_id
    csrf_token()


def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("web.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("web.admin_login", next=request.path))
        if not g.user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped
