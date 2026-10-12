"""GUI routes (server-rendered HTML, Post/Redirect/Get pattern)."""

from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import viz
from .guardrails import CURRENCIES, LedgerError
from .security import admin_required, login_required, login_user
from .services import LedgerService

bp = Blueprint("web", __name__)


def svc() -> LedgerService:
    return current_app.extensions["ledger"]


def _safe_next(target: str | None) -> str | None:
    """Only allow local, relative redirect targets (blocks open redirects)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


@bp.get("/")
def index():
    if g.user is None:
        return redirect(url_for("web.login"))
    return redirect(url_for("web.admin" if g.user.is_admin else "web.dashboard"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    return _login(admin_only=False)


@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Dedicated administrator sign-in page; refuses customer accounts."""
    return _login(admin_only=True)


def _login(*, admin_only: bool):
    page = lambda: render_template("login.html", admin_only=admin_only)  # noqa: E731
    if request.method == "POST":
        try:
            account = svc().authenticate(request.form.get("username"), request.form.get("password"))
        except LedgerError as exc:
            flash(str(exc), "error")
            return page(), 401
        if admin_only and not account.is_admin:
            flash("This login is for administrators only. Use the customer login instead.", "error")
            return page(), 403
        login_user(account.id)
        flash(f"Welcome, {account.full_name}!", "success")
        default = url_for("web.admin" if account.is_admin else "web.dashboard")
        return redirect(_safe_next(request.args.get("next")) or default)
    return page()


@bp.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    target = "web.admin_login" if request.form.get("next") == "admin" else "web.login"
    return redirect(url_for(target))


# ------------------------------------------------------------------- customer
@bp.get("/dashboard")
@login_required
def dashboard():
    if g.user.is_admin:
        return redirect(url_for("web.admin"))
    s = svc()
    return render_template(
        "dashboard.html",
        balances=s.get_balances(g.user.id),
        transactions=s.transactions_for(g.user.id),
        rates=s.get_rates(),
        currencies=CURRENCIES,
    )


@bp.post("/entry")
@login_required
def entry():
    """Credit or debit the logged-in user's own account."""
    kind = request.form.get("kind", "")
    currency = request.form.get("currency")
    amount = request.form.get("amount")
    memo = request.form.get("memo", "")
    try:
        match kind:
            case "credit":
                new = svc().credit(g.user, currency, amount, memo)
                flash(f"Credited {amount} {currency}. New balance: {new} {currency}.", "success")
            case "debit":
                new = svc().debit(g.user, currency, amount, memo)
                flash(f"Debited {amount} {currency}. New balance: {new} {currency}.", "success")
            case _:
                flash("Unknown operation.", "error")
    except LedgerError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.dashboard"))


@bp.post("/transfer")
@login_required
def transfer():
    f = request.form
    try:
        r = svc().transfer(
            g.user, f.get("to_username"), f.get("from_currency"),
            f.get("to_currency"), f.get("amount"), f.get("memo", ""),
            optimize=f.get("optimize") == "on",
        )
        flash(
            f"Transferred {r.debited} {r.from_currency} to {f.get('to_username', '').strip().lower()}"
            f" (they received {r.credited} {r.to_currency} at "
            f"{'optimized' if f.get('optimize') == 'on' else 'direct'} rate {r.rate}).",
            "success",
        )
    except LedgerError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.dashboard"))


@bp.get("/advisor")
@login_required
def advisor():
    """Graphical recommendation of the best conversion route between two currencies."""
    a = request.args
    source, target, amount = a.get("from", "USD"), a.get("to", "INR"), a.get("amount", "100")
    s = svc()
    rates = s.rate_table()
    loops = s.arbitrage_loops()
    plan = error = None
    try:
        plan = s.conversion_plan(source, target, amount)
    except LedgerError as exc:
        error = str(exc)
    return render_template(
        "advisor.html",
        plan=plan, error=error, loops=loops, currencies=CURRENCIES,
        form={"from": source, "to": target, "amount": amount},
        network=viz.network(plan, rates) if plan else None,
        bars=viz.gain_bars(plan) if plan else None,
        heat=viz.heatmap(rates, (plan.source, plan.target) if plan else None),
        balances=None if g.user.is_admin else s.get_balances(g.user.id),
        fmt_rate=viz.fmt_rate,
    )


@bp.post("/convert")
@login_required
def convert():
    """Exchange between the user's own currency balances along the chosen route."""
    f = request.form
    optimize = f.get("route", "best") != "direct"
    try:
        route = svc().convert(g.user, f.get("from"), f.get("to"), f.get("amount"), optimize=optimize)
        flash(f"Converted {route.sent} {route.path[0]} into {route.received} {route.path[-1]} "
              f"via {route.label} (effective rate {viz.fmt_rate(route.effective_rate)}).", "success")
    except LedgerError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.advisor", **{"from": f.get("from", ""), "to": f.get("to", ""),
                                              "amount": f.get("amount", "")}))


@bp.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":
        try:
            if request.form.get("new_password") != request.form.get("confirm_password"):
                raise LedgerError("New passwords do not match.")
            svc().change_password(
                g.user, request.form.get("current_password"), request.form.get("new_password")
            )
            flash("Password changed.", "success")
            return redirect(url_for("web.index"))
        except LedgerError as exc:
            flash(str(exc), "error")
    return render_template("password.html")


# ---------------------------------------------------------------------- admin
@bp.get("/admin")
@admin_required
def admin():
    s = svc()
    return render_template(
        "admin.html",
        arbitrage=s.arbitrage_loops(),
        accounts=s.list_accounts(g.user),
        rates=s.get_rates(),
        rate_history=s.rate_history(20),
        audit=s.audit_log(g.user, 30),
        currencies=CURRENCIES,
    )


@bp.post("/admin/accounts")
@admin_required
def admin_create_account():
    f = request.form
    try:
        acc = svc().create_account(
            g.user, f.get("username"), f.get("full_name"), f.get("password"), f.get("role", "user")
        )
        flash(f"Account '{acc.username}' created.", "success")
    except LedgerError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.admin"))


@bp.post("/admin/accounts/<int:account_id>/delete")
@admin_required
def admin_delete_account(account_id: int):
    try:
        svc().delete_account(g.user, account_id, force=request.form.get("force") == "on")
        flash("Account deleted.", "success")
    except LedgerError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.admin"))


@bp.post("/admin/rates")
@admin_required
def admin_set_rate():
    f = request.form
    try:
        value = svc().set_rate(g.user, f.get("base"), f.get("quote"), f.get("rate"))
        flash(f"Rate {f.get('base')}->{f.get('quote')} set to {value}.", "success")
    except LedgerError as exc:
        flash(str(exc), "error")
    return redirect(url_for("web.admin"))
