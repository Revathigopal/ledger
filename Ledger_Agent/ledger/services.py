"""Business logic.

The service layer enforces authorisation itself (defence in depth): even if a
route forgot a decorator, a non-admin still could not create accounts or change
rates, and nobody can move money out of someone else's account.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_EVEN, Decimal

from werkzeug.security import check_password_hash, generate_password_hash

from . import advisor
from .db import Database, utcnow
from .guardrails import (
    CURRENCIES,
    MAX_BALANCE,
    Currency,
    LedgerError,
    ValidationError,
    from_minor,
    parse_amount,
    parse_currency,
    parse_rate,
    to_minor,
    validate_full_name,
    validate_memo,
    validate_password,
    validate_role,
    validate_username,
)

MAX_FAILED_LOGINS = 5
LOCKOUT_PERIOD = timedelta(minutes=5)

# Used to keep login timing similar for unknown usernames.
_DUMMY_HASH = generate_password_hash("not-a-real-password-0")


class AuthError(LedgerError):
    pass


class PermissionDenied(LedgerError):
    pass


class NotFound(LedgerError):
    pass


class InsufficientFunds(LedgerError):
    pass


@dataclass(frozen=True, slots=True)
class Account:
    id: int
    username: str
    full_name: str
    role: str
    created_at: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Account:
        return cls(row["id"], row["username"], row["full_name"], row["role"], row["created_at"])


@dataclass(frozen=True, slots=True)
class TransferResult:
    debited: Decimal
    from_currency: Currency
    credited: Decimal
    to_currency: Currency
    rate: Decimal


class LedgerService:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _require_admin(actor: Account) -> None:
        if not actor.is_admin:
            raise PermissionDenied("Only an administrator can perform this action.")

    @staticmethod
    def _require_customer(actor: Account) -> None:
        if actor.is_admin:
            raise PermissionDenied("Administrator accounts do not hold balances.")

    @staticmethod
    def _audit(cur: sqlite3.Cursor, actor: str, action: str, details: str = "") -> None:
        cur.execute(
            "INSERT INTO audit_log (actor, action, details, created_at) VALUES (?, ?, ?, ?)",
            (actor, action, details, utcnow()),
        )

    @staticmethod
    def _balance_minor(cur: sqlite3.Cursor, account_id: int, currency: str) -> int:
        row = cur.execute(
            "SELECT amount_minor FROM balances WHERE account_id = ? AND currency = ?",
            (account_id, currency),
        ).fetchone()
        if row is None:
            raise NotFound("Account not found.")
        return row["amount_minor"]

    @staticmethod
    def _set_balance(cur: sqlite3.Cursor, account_id: int, currency: str, minor: int) -> None:
        cur.execute(
            "UPDATE balances SET amount_minor = ? WHERE account_id = ? AND currency = ?",
            (minor, account_id, currency),
        )

    # --------------------------------------------------------------- accounts
    def bootstrap_admin(self, username: str, password: str) -> Account:
        """Create the initial administrator (used once at start-up)."""
        username = validate_username(username)
        validate_password(password)
        with self.db.transaction() as cur:
            cur.execute(
                "INSERT INTO accounts (username, full_name, password_hash, role, created_at) "
                "VALUES (?, ?, ?, 'admin', ?)",
                (username, "Administrator", generate_password_hash(password), utcnow()),
            )
            self._audit(cur, "system", "BOOTSTRAP_ADMIN", username)
        return self.get_account_by_username(username)

    def create_account(
        self,
        actor: Account,
        username: object,
        full_name: object,
        password: object,
        role: object = "user",
    ) -> Account:
        self._require_admin(actor)
        username = validate_username(username)
        full_name = validate_full_name(full_name)
        password = validate_password(password)
        role = validate_role(role)
        with self.db.transaction() as cur:
            try:
                cur.execute(
                    "INSERT INTO accounts (username, full_name, password_hash, role, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, full_name, generate_password_hash(password), role, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise ValidationError(f"Username '{username}' is already taken.") from exc
            account_id = cur.lastrowid
            if role == "user":
                cur.executemany(
                    "INSERT INTO balances (account_id, currency, amount_minor) VALUES (?, ?, 0)",
                    [(account_id, c.value) for c in CURRENCIES],
                )
            self._audit(cur, actor.username, "CREATE_ACCOUNT", f"{username} (role={role})")
        return self.get_account(account_id)

    def delete_account(self, actor: Account, account_id: int, *, force: bool = False) -> None:
        self._require_admin(actor)
        if account_id == actor.id:
            raise ValidationError("You cannot delete your own account.")
        with self.db.transaction() as cur:
            row = cur.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if row is None:
                raise NotFound("Account not found.")
            if row["role"] == "admin":
                admins = cur.execute(
                    "SELECT COUNT(*) FROM accounts WHERE role = 'admin'"
                ).fetchone()[0]
                if admins <= 1:
                    raise ValidationError("Cannot delete the last administrator.")
            total = cur.execute(
                "SELECT COALESCE(SUM(amount_minor), 0) FROM balances WHERE account_id = ?",
                (account_id,),
            ).fetchone()[0]
            if total and not force:
                raise ValidationError(
                    "Account still holds funds. Tick 'force' to delete it anyway."
                )
            cur.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
            self._audit(
                cur, actor.username, "DELETE_ACCOUNT",
                f"{row['username']} (forced={force}, remaining_minor_total={total})",
            )

    def get_account(self, account_id: int) -> Account:
        row = self.db.query_one("SELECT * FROM accounts WHERE id = ?", (account_id,))
        if row is None:
            raise NotFound("Account not found.")
        return Account.from_row(row)

    def get_account_by_username(self, username: str) -> Account:
        row = self.db.query_one("SELECT * FROM accounts WHERE username = ?", (username,))
        if row is None:
            raise NotFound("Account not found.")
        return Account.from_row(row)

    def list_accounts(self, actor: Account) -> list[dict]:
        self._require_admin(actor)
        accounts = []
        for row in self.db.query("SELECT * FROM accounts ORDER BY id"):
            acc = Account.from_row(row)
            accounts.append({"account": acc, "balances": self.get_balances(acc.id)})
        return accounts

    def admin_count(self) -> int:
        return self.db.query_one("SELECT COUNT(*) AS n FROM accounts WHERE role = 'admin'")["n"]

    # ---------------------------------------------------------- authentication
    def authenticate(self, username: object, password: object) -> Account:
        generic = AuthError("Invalid username or password.")
        if not isinstance(username, str) or not isinstance(password, str):
            raise generic
        row = self.db.query_one(
            "SELECT * FROM accounts WHERE username = ?", (username.strip(),)
        )
        if row is None:
            check_password_hash(_DUMMY_HASH, password)  # constant-ish timing
            raise generic
        now = datetime.now(UTC)
        if row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > now:
            raise AuthError("Account temporarily locked after too many failed logins.")
        if not check_password_hash(row["password_hash"], password):
            failures = row["failed_logins"] + 1
            locked_until = None
            if failures >= MAX_FAILED_LOGINS:
                locked_until = (now + LOCKOUT_PERIOD).isoformat(timespec="seconds")
                failures = 0
            with self.db.transaction() as cur:
                cur.execute(
                    "UPDATE accounts SET failed_logins = ?, locked_until = ? WHERE id = ?",
                    (failures, locked_until, row["id"]),
                )
                self._audit(cur, row["username"], "LOGIN_FAILED",
                            "locked" if locked_until else f"attempt {failures}")
            raise generic
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE accounts SET failed_logins = 0, locked_until = NULL WHERE id = ?",
                (row["id"],),
            )
            self._audit(cur, row["username"], "LOGIN")
        return Account.from_row(row)

    def change_password(self, actor: Account, current: object, new: object) -> None:
        row = self.db.query_one("SELECT password_hash FROM accounts WHERE id = ?", (actor.id,))
        if row is None:
            raise NotFound("Account not found.")
        if not isinstance(current, str) or not check_password_hash(row["password_hash"], current):
            raise AuthError("Current password is incorrect.")
        new = validate_password(new)
        with self.db.transaction() as cur:
            cur.execute(
                "UPDATE accounts SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new), actor.id),
            )
            self._audit(cur, actor.username, "CHANGE_PASSWORD")

    # ---------------------------------------------------------------- balances
    def get_balances(self, account_id: int) -> dict[Currency, Decimal]:
        rows = self.db.query(
            "SELECT currency, amount_minor FROM balances WHERE account_id = ?", (account_id,)
        )
        return {Currency(r["currency"]): from_minor(r["amount_minor"]) for r in rows}

    def credit(self, actor: Account, currency: object, amount: object, memo: object = "") -> Decimal:
        """Deposit money into the actor's own account. Returns the new balance."""
        self._require_customer(actor)
        cur_code = parse_currency(currency)
        value = parse_amount(amount)
        memo = validate_memo(memo)
        minor = to_minor(value)
        with self.db.transaction() as cur:
            balance = self._balance_minor(cur, actor.id, cur_code)
            if from_minor(balance + minor) > MAX_BALANCE:
                raise ValidationError(f"Balance would exceed the limit of {MAX_BALANCE:,}.")
            self._set_balance(cur, actor.id, cur_code, balance + minor)
            cur.execute(
                "INSERT INTO transactions (kind, account_id, account_username, currency, "
                "amount_minor, memo, created_at) VALUES ('CREDIT', ?, ?, ?, ?, ?, ?)",
                (actor.id, actor.username, cur_code, minor, memo, utcnow()),
            )
        return from_minor(balance + minor)

    def debit(self, actor: Account, currency: object, amount: object, memo: object = "") -> Decimal:
        """Withdraw money from the actor's own account. Returns the new balance."""
        self._require_customer(actor)
        cur_code = parse_currency(currency)
        value = parse_amount(amount)
        memo = validate_memo(memo)
        minor = to_minor(value)
        with self.db.transaction() as cur:
            balance = self._balance_minor(cur, actor.id, cur_code)
            if minor > balance:
                raise InsufficientFunds(
                    f"Insufficient {cur_code} funds: balance {from_minor(balance)}, requested {value}."
                )
            self._set_balance(cur, actor.id, cur_code, balance - minor)
            cur.execute(
                "INSERT INTO transactions (kind, account_id, account_username, currency, "
                "amount_minor, memo, created_at) VALUES ('DEBIT', ?, ?, ?, ?, ?, ?)",
                (actor.id, actor.username, cur_code, minor, memo, utcnow()),
            )
        return from_minor(balance - minor)

    def transfer(
        self,
        actor: Account,
        to_username: object,
        from_currency: object,
        to_currency: object,
        amount: object,
        memo: object = "",
        *,
        optimize: bool = False,
    ) -> TransferResult:
        """Move ``amount`` of ``from_currency`` from the actor to another account,
        converting to ``to_currency`` using the current exchange rate - or, with
        ``optimize=True``, along the conversion route that pays the recipient most."""
        self._require_customer(actor)
        recipient_name = validate_username(to_username)
        src = parse_currency(from_currency)
        dst = parse_currency(to_currency)
        value = parse_amount(amount)
        memo = validate_memo(memo)
        minor = to_minor(value)

        with self.db.transaction() as cur:
            row = cur.execute(
                "SELECT * FROM accounts WHERE username = ?", (recipient_name,)
            ).fetchone()
            if row is None or row["role"] != "user":
                raise NotFound(f"Recipient account '{recipient_name}' does not exist.")
            if row["id"] == actor.id:
                raise ValidationError("You cannot transfer money to your own account.")
            recipient = Account.from_row(row)

            route_code = None
            if src == dst:
                rate, credited_minor = Decimal(1), minor
            else:
                rates = self._rate_table(cur)
                self._ensure_no_arbitrage(rates)
                p = advisor.plan(rates, src, dst, minor)
                route = p.best if optimize else p.direct
                rate, credited_minor, route_code = route.effective_rate, route.hop_minor[-1], route.code
            if credited_minor <= 0:
                raise ValidationError("Amount is too small to convert at the current rate.")

            sender_balance = self._balance_minor(cur, actor.id, src)
            if minor > sender_balance:
                raise InsufficientFunds(
                    f"Insufficient {src} funds: balance {from_minor(sender_balance)}, requested {value}."
                )
            recipient_balance = self._balance_minor(cur, recipient.id, dst)
            if from_minor(recipient_balance + credited_minor) > MAX_BALANCE:
                raise ValidationError("Recipient balance would exceed the allowed limit.")

            self._set_balance(cur, actor.id, src, sender_balance - minor)
            self._set_balance(cur, recipient.id, dst, recipient_balance + credited_minor)
            cur.execute(
                "INSERT INTO transactions (kind, account_id, account_username, currency, "
                "amount_minor, counterparty_id, counterparty_username, counter_currency, "
                "counter_amount_minor, rate, route, memo, created_at) "
                "VALUES ('TRANSFER', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (actor.id, actor.username, src, minor, recipient.id, recipient.username,
                 dst, credited_minor, str(rate), route_code, memo, utcnow()),
            )
        return TransferResult(value, src, from_minor(credited_minor), dst, rate)

    def transactions_for(self, account_id: int, limit: int = 50) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM transactions WHERE account_id = ? OR counterparty_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (account_id, account_id, limit),
        )
        out = []
        for r in rows:
            item = dict(r)
            item["amount"] = from_minor(r["amount_minor"])
            if r["counter_amount_minor"] is not None:
                item["counter_amount"] = from_minor(r["counter_amount_minor"])
            item["incoming"] = r["kind"] == "TRANSFER" and r["counterparty_id"] == account_id
            out.append(item)
        return out

    # ------------------------------------------------------------------- rates
    @staticmethod
    def _rate(cur: sqlite3.Cursor, base: str, quote: str) -> Decimal:
        if base == quote:
            return Decimal("1")
        row = cur.execute(
            "SELECT rate FROM persist.exchange_rates WHERE base = ? AND quote = ?", (base, quote)
        ).fetchone()
        if row is None:  # pragma: no cover - seeded at start-up
            raise NotFound(f"No exchange rate for {base}->{quote}.")
        return Decimal(row["rate"])

    @staticmethod
    def _rate_table(cur: sqlite3.Cursor) -> dict[tuple[str, str], Decimal]:
        rows = cur.execute("SELECT base, quote, rate FROM persist.exchange_rates").fetchall()
        return {(r["base"], r["quote"]): Decimal(r["rate"]) for r in rows}

    @staticmethod
    def _ensure_no_arbitrage(rates: advisor.RateTable) -> None:
        loops = advisor.arbitrage_loops(rates)
        if loops:
            raise ValidationError(
                "Cross-currency operations are suspended: the current exchange rates contain a "
                f"risk-free loop ({loops[0].label}, x{loops[0].factor:.6f}). "
                "An administrator must correct the rates."
            )

    def rate_table(self) -> dict[tuple[str, str], Decimal]:
        with self.db.transaction() as cur:
            return self._rate_table(cur)

    def arbitrage_loops(self) -> list[advisor.ArbitrageLoop]:
        return advisor.arbitrage_loops(self.rate_table())

    def conversion_plan(self, source: object, target: object, amount: object) -> advisor.Plan:
        """Rank every conversion route from ``source`` to ``target`` for ``amount``."""
        src, dst = parse_currency(source), parse_currency(target)
        minor = to_minor(parse_amount(amount))
        return advisor.plan(self.rate_table(), src, dst, minor)

    def convert(
        self,
        actor: Account,
        source: object,
        target: object,
        amount: object,
        *,
        optimize: bool = True,
        memo: object = "",
    ) -> advisor.Route:
        """Exchange money between the actor's own currency balances, by default
        along the recommended (best-paying) route."""
        self._require_customer(actor)
        src, dst = parse_currency(source), parse_currency(target)
        value = parse_amount(amount)
        memo = validate_memo(memo)
        minor = to_minor(value)
        with self.db.transaction() as cur:
            rates = self._rate_table(cur)
            self._ensure_no_arbitrage(rates)
            p = advisor.plan(rates, src, dst, minor)  # validates src != dst
            route = p.best if optimize else p.direct
            received = route.hop_minor[-1]
            if received <= 0:
                raise ValidationError("Amount is too small to convert at the current rate.")
            src_balance = self._balance_minor(cur, actor.id, src)
            if minor > src_balance:
                raise InsufficientFunds(
                    f"Insufficient {src} funds: balance {from_minor(src_balance)}, requested {value}."
                )
            dst_balance = self._balance_minor(cur, actor.id, dst)
            if from_minor(dst_balance + received) > MAX_BALANCE:
                raise ValidationError(f"Balance would exceed the limit of {MAX_BALANCE:,}.")
            self._set_balance(cur, actor.id, src, src_balance - minor)
            self._set_balance(cur, actor.id, dst, dst_balance + received)
            cur.execute(
                "INSERT INTO transactions (kind, account_id, account_username, currency, "
                "amount_minor, counter_currency, counter_amount_minor, rate, route, memo, created_at) "
                "VALUES ('CONVERT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (actor.id, actor.username, src, minor, dst, received,
                 str(route.effective_rate), route.code, memo, utcnow()),
            )
        return route

    def get_rate(self, base: object, quote: object) -> Decimal:
        b, q = parse_currency(base), parse_currency(quote)
        with self.db.transaction() as cur:
            return self._rate(cur, b, q)

    def get_rates(self) -> list[dict]:
        return [
            dict(r)
            for r in self.db.query(
                "SELECT base, quote, rate, updated_at, updated_by "
                "FROM persist.exchange_rates ORDER BY base, quote"
            )
        ]

    def set_rate(self, actor: Account, base: object, quote: object, rate: object) -> Decimal:
        self._require_admin(actor)
        b, q = parse_currency(base), parse_currency(quote)
        if b == q:
            raise ValidationError("Base and quote currency must differ.")
        value = parse_rate(rate)
        with self.db.transaction() as cur:
            proposed = {**self._rate_table(cur), (b.value, q.value): value}
            loops = [lp for lp in advisor.arbitrage_loops(proposed)
                     if (b, q) in zip(lp.path, lp.path[1:])]
            if loops:
                limit = advisor.max_safe_rate(proposed, b, q)
                raise ValidationError(
                    f"Rejected: {b}->{q} = {value} would create a risk-free loop "
                    f"{loops[0].label} (x{loops[0].factor:.6f}), letting users create money by "
                    f"converting in a circle. With the other current rates the maximum safe "
                    f"{b}->{q} rate is {limit}."
                )
            old = cur.execute(
                "SELECT rate FROM persist.exchange_rates WHERE base = ? AND quote = ?", (b, q)
            ).fetchone()
            now = utcnow()
            cur.execute(
                "INSERT INTO persist.exchange_rates (base, quote, rate, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (base, quote) DO UPDATE SET "
                "rate = excluded.rate, updated_at = excluded.updated_at, "
                "updated_by = excluded.updated_by",
                (b, q, str(value), now, actor.username),
            )
            cur.execute(
                "INSERT INTO persist.rate_history (base, quote, old_rate, new_rate, changed_by, "
                "changed_at) VALUES (?, ?, ?, ?, ?, ?)",
                (b, q, old["rate"] if old else None, str(value), actor.username, now),
            )
            self._audit(cur, actor.username, "SET_RATE", f"{b}->{q} = {value}")
        return value

    def rate_history(self, limit: int = 50) -> list[dict]:
        return [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM persist.rate_history ORDER BY id DESC LIMIT ?", (limit,)
            )
        ]

    def audit_log(self, actor: Account, limit: int = 100) -> list[dict]:
        self._require_admin(actor)
        return [
            dict(r)
            for r in self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        ]
