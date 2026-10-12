"""Unit and integration tests for the Ledger application.

Run all tests:            python test.py            (or: python -m unittest test -v)
Run one group:            python test.py TransferTests
Run one test:             python test.py TransferTests.test_cross_currency_transfer_uses_rate

Test groups
-----------
GuardrailTests        input validation rules (amounts, currencies, rates, names, ...)
DatabaseTests         in-memory ledger tables vs. persistent rate tables
AccountAdminTests     admin-only account creation / deletion
AuthenticationTests   login, lock-out, password change
CreditDebitTests      credit / debit in USD, EUR, INR
TransferTests         transfers between accounts incl. currency conversion
RateTests             admin-only exchange-rate updates + persistence
AdvisorTests          route optimisation maths, arbitrage detection, max safe rate
ConversionTests       converting own balances / optimized transfers / arbitrage guardrail
ConcurrencyTests      thread-safety of balance updates
WebGuiTests           the Flask GUI end-to-end through the test client
WebSecurityTests      CSRF, access control, headers, XSS, SQL injection, open redirect
AdvisorWebTests       the graphical conversion advisor page and its actions
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from ledger import advisor, create_app
from ledger.db import DEFAULT_RATES, Database
from ledger.guardrails import (
    MAX_TRANSACTION,
    Currency,
    ValidationError,
    parse_amount,
    parse_currency,
    parse_rate,
    validate_full_name,
    validate_memo,
    validate_password,
    validate_role,
    validate_username,
)
from ledger.services import (
    MAX_FAILED_LOGINS,
    AuthError,
    InsufficientFunds,
    LedgerService,
    NotFound,
    PermissionDenied,
)

ADMIN_PW = "AdminPass123"
USER_PW = "UserPass123"
D = Decimal


# ============================================================== helpers / base
class ServiceTestCase(unittest.TestCase):
    """Fresh in-memory ledger + temporary rates DB for every test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.rates_path = os.path.join(self._tmp.name, "rates.db")
        self.db = Database(self.rates_path)
        self.svc = LedgerService(self.db)
        self.admin = self.svc.bootstrap_admin("admin", ADMIN_PW)
        self.alice = self.svc.create_account(self.admin, "alice", "Alice", USER_PW)
        self.bob = self.svc.create_account(self.admin, "bob", "Bob", USER_PW)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def bal(self, account, currency: str) -> Decimal:
        return self.svc.get_balances(account.id)[Currency(currency)]


class WebTestCase(unittest.TestCase):
    """Flask app + test client with an admin and two users."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "RATES_DB": os.path.join(self._tmp.name, "rates.db"),
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": ADMIN_PW,
        })
        self.svc: LedgerService = self.app.extensions["ledger"]
        admin = self.svc.get_account_by_username("admin")
        self.svc.create_account(admin, "alice", "Alice", USER_PW)
        self.svc.create_account(admin, "bob", "Bob", USER_PW)
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.app.extensions["ledger_db"].close()
        self._tmp.cleanup()

    # -- helpers
    def csrf(self, path: str = "/login") -> str:
        html = self.client.get(path, follow_redirects=True).get_data(as_text=True)
        m = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(m, f"no CSRF token on {path}")
        return m.group(1)

    def login(self, username: str, password: str):
        token = self.csrf("/login")
        return self.client.post(
            "/login", data={"username": username, "password": password, "csrf_token": token}
        )

    def post(self, path: str, data: dict, follow: bool = True):
        data = {**data, "csrf_token": self.csrf("/")}
        return self.client.post(path, data=data, follow_redirects=follow)

    def bal(self, username: str, currency: str) -> Decimal:
        acc = self.svc.get_account_by_username(username)
        return self.svc.get_balances(acc.id)[Currency(currency)]


# ================================================================== guardrails
class GuardrailTests(unittest.TestCase):
    def test_valid_amounts(self):
        self.assertEqual(parse_amount("10"), D("10"))
        self.assertEqual(parse_amount(" 0.01 "), D("0.01"))
        self.assertEqual(parse_amount("1000000.00"), MAX_TRANSACTION)

    def test_invalid_amounts(self):
        for bad in ["", "0", "0.00", "-5", "1.234", "abc", "1e5", "NaN", "Infinity",
                    "1,000", "1000000.01", "  ", None, 12, "1 0", "0x10", "+5"]:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                parse_amount(bad)

    def test_currencies(self):
        for code in ["USD", "eur", " inr "]:
            self.assertIn(parse_currency(code), set(Currency))
        for bad in ["GBP", "", "US", "USDX", None, "usd;drop"]:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                parse_currency(bad)

    def test_rates(self):
        self.assertEqual(parse_rate("83"), D("83.000000"))
        self.assertEqual(parse_rate("0.000001"), D("0.000001"))
        for bad in ["0", "-1", "0.0000001", "1000001", "abc", "", "1e3"]:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                parse_rate(bad)

    def test_usernames(self):
        self.assertEqual(validate_username("Alice_01"), "alice_01")
        for bad in ["ab", "a" * 33, "bad name", "x'; DROP TABLE accounts;--", "<script>", ""]:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_username(bad)

    def test_passwords(self):
        validate_password("abcdefg1")
        for bad in ["short1", "allletters", "12345678", "a1" * 65, None]:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_password(bad)

    def test_text_fields_strip_control_characters(self):
        self.assertEqual(validate_memo("rent\x00‮"), "rent")
        self.assertEqual(validate_full_name("  Jane Doe "), "Jane Doe")
        with self.assertRaises(ValidationError):
            validate_memo("x" * 141)
        with self.assertRaises(ValidationError):
            validate_full_name("")

    def test_roles(self):
        self.assertEqual(validate_role(""), "user")
        self.assertEqual(validate_role("ADMIN"), "admin")
        with self.assertRaises(ValidationError):
            validate_role("root")


# ==================================================================== database
class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "rates.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_tables_created_in_right_place(self):
        db = Database(self.path)
        self.assertEqual(db.table_names("main"), {"accounts", "balances", "transactions", "audit_log"})
        self.assertEqual(db.table_names("persist"), {"exchange_rates", "rate_history"})
        db.close()
        # The file on disk contains ONLY the rate tables - no ledger data.
        with sqlite3.connect(self.path) as raw:
            names = {r[0] for r in raw.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        self.assertEqual(names, {"exchange_rates", "rate_history"})

    def test_default_rates_seeded(self):
        db = Database(self.path)
        svc = LedgerService(db)
        self.assertEqual(len(svc.get_rates()), 6)
        self.assertEqual(svc.get_rate("USD", "INR"), D(DEFAULT_RATES[("USD", "INR")]))
        self.assertEqual(svc.get_rate("EUR", "EUR"), D(1))
        db.close()

    def test_ledger_is_in_memory_but_rates_persist(self):
        db1 = Database(self.path)
        svc1 = LedgerService(db1)
        admin = svc1.bootstrap_admin("admin", ADMIN_PW)
        svc1.create_account(admin, "alice", "Alice", USER_PW)
        svc1.set_rate(admin, "USD", "EUR", "0.5")
        db1.close()

        db2 = Database(self.path)  # simulates an application restart
        svc2 = LedgerService(db2)
        self.assertEqual(svc2.get_rate("USD", "EUR"), D("0.5"))       # persisted
        self.assertEqual(len(svc2.rate_history()), 1)                 # persisted
        self.assertEqual(svc2.admin_count(), 0)                       # in-memory, gone
        with self.assertRaises(NotFound):
            svc2.get_account_by_username("alice")
        db2.close()

    def test_check_constraint_blocks_negative_balance(self):
        db = Database(self.path)
        svc = LedgerService(db)
        admin = svc.bootstrap_admin("admin", ADMIN_PW)
        alice = svc.create_account(admin, "alice", "Alice", USER_PW)
        with self.assertRaises(sqlite3.IntegrityError), db.transaction() as cur:
            cur.execute("UPDATE balances SET amount_minor = -1 WHERE account_id = ?", (alice.id,))
        db.close()


# ============================================================ account admin
class AccountAdminTests(ServiceTestCase):
    def test_new_account_has_zero_balance_in_all_currencies(self):
        self.assertEqual(self.svc.get_balances(self.alice.id),
                         {Currency.USD: D("0.00"), Currency.EUR: D("0.00"), Currency.INR: D("0.00")})

    def test_admin_has_no_balances(self):
        self.assertEqual(self.svc.get_balances(self.admin.id), {})

    def test_only_admin_can_create(self):
        with self.assertRaises(PermissionDenied):
            self.svc.create_account(self.alice, "eve", "Eve", USER_PW)

    def test_duplicate_username_rejected_case_insensitive(self):
        with self.assertRaises(ValidationError):
            self.svc.create_account(self.admin, "ALICE", "Other", USER_PW)

    def test_create_with_invalid_input_rejected(self):
        with self.assertRaises(ValidationError):
            self.svc.create_account(self.admin, "carol", "Carol", "weak")
        with self.assertRaises(ValidationError):
            self.svc.create_account(self.admin, "c", "Carol", USER_PW)

    def test_admin_can_create_another_admin(self):
        acc = self.svc.create_account(self.admin, "root2", "Root Two", USER_PW, role="admin")
        self.assertTrue(acc.is_admin)
        self.assertEqual(self.svc.admin_count(), 2)

    def test_only_admin_can_delete(self):
        with self.assertRaises(PermissionDenied):
            self.svc.delete_account(self.alice, self.bob.id)

    def test_delete_empty_account(self):
        self.svc.delete_account(self.admin, self.bob.id)
        with self.assertRaises(NotFound):
            self.svc.get_account(self.bob.id)
        # balances cascade-deleted
        self.assertEqual(self.svc.get_balances(self.bob.id), {})

    def test_delete_funded_account_requires_force(self):
        self.svc.credit(self.bob, "USD", "10")
        with self.assertRaises(ValidationError):
            self.svc.delete_account(self.admin, self.bob.id)
        self.svc.delete_account(self.admin, self.bob.id, force=True)
        with self.assertRaises(NotFound):
            self.svc.get_account(self.bob.id)

    def test_cannot_delete_self_or_unknown(self):
        with self.assertRaises(ValidationError):
            self.svc.delete_account(self.admin, self.admin.id)
        with self.assertRaises(NotFound):
            self.svc.delete_account(self.admin, 9999)

    def test_history_survives_account_deletion(self):
        self.svc.credit(self.alice, "USD", "50")
        self.svc.transfer(self.alice, "bob", "USD", "USD", "20")
        self.svc.delete_account(self.admin, self.bob.id, force=True)
        self.assertEqual(len(self.svc.transactions_for(self.alice.id)), 2)

    def test_actions_are_audited(self):
        actions = [e["action"] for e in self.svc.audit_log(self.admin)]
        self.assertIn("CREATE_ACCOUNT", actions)
        self.assertIn("BOOTSTRAP_ADMIN", actions)
        with self.assertRaises(PermissionDenied):
            self.svc.audit_log(self.alice)


# ============================================================ authentication
class AuthenticationTests(ServiceTestCase):
    def test_login_success_and_case_insensitive_username(self):
        self.assertEqual(self.svc.authenticate("alice", USER_PW).id, self.alice.id)
        self.assertEqual(self.svc.authenticate("ALICE", USER_PW).id, self.alice.id)

    def test_login_failure_messages_are_generic(self):
        with self.assertRaises(AuthError) as wrong_pw:
            self.svc.authenticate("alice", "nope12345")
        with self.assertRaises(AuthError) as no_user:
            self.svc.authenticate("nobody", "nope12345")
        self.assertEqual(str(wrong_pw.exception), str(no_user.exception))

    def test_login_rejects_non_string_input(self):
        with self.assertRaises(AuthError):
            self.svc.authenticate(None, None)

    def test_lockout_after_repeated_failures(self):
        for _ in range(MAX_FAILED_LOGINS):
            with self.assertRaises(AuthError):
                self.svc.authenticate("alice", "wrong-pass1")
        with self.assertRaises(AuthError) as ctx:
            self.svc.authenticate("alice", USER_PW)  # correct password, but locked
        self.assertIn("locked", str(ctx.exception))

    def test_lockout_expires(self):
        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(timespec="seconds")
        with self.db.transaction() as cur:
            cur.execute("UPDATE accounts SET locked_until = ? WHERE id = ?", (past, self.alice.id))
        self.assertEqual(self.svc.authenticate("alice", USER_PW).id, self.alice.id)

    def test_password_is_hashed(self):
        row = self.db.query_one("SELECT password_hash FROM accounts WHERE id = ?", (self.alice.id,))
        self.assertNotIn(USER_PW, row["password_hash"])
        self.assertRegex(row["password_hash"], r"^(scrypt|pbkdf2)")

    def test_change_password(self):
        with self.assertRaises(AuthError):
            self.svc.change_password(self.alice, "wrong", "NewPass456")
        with self.assertRaises(ValidationError):
            self.svc.change_password(self.alice, USER_PW, "weak")
        self.svc.change_password(self.alice, USER_PW, "NewPass456")
        self.svc.authenticate("alice", "NewPass456")
        with self.assertRaises(AuthError):
            self.svc.authenticate("alice", USER_PW)


# =============================================================== credit/debit
class CreditDebitTests(ServiceTestCase):
    def test_credit_each_currency(self):
        for cur in ("USD", "EUR", "INR"):
            with self.subTest(cur=cur):
                self.assertEqual(self.svc.credit(self.alice, cur, "123.45"), D("123.45"))
                self.assertEqual(self.bal(self.alice, cur), D("123.45"))

    def test_debit_each_currency(self):
        for cur in ("USD", "EUR", "INR"):
            with self.subTest(cur=cur):
                self.svc.credit(self.alice, cur, "100")
                self.assertEqual(self.svc.debit(self.alice, cur, "40.10"), D("59.90"))

    def test_currencies_are_independent(self):
        self.svc.credit(self.alice, "USD", "100")
        self.assertEqual(self.bal(self.alice, "EUR"), D("0"))
        self.assertEqual(self.bal(self.alice, "INR"), D("0"))

    def test_overdraft_rejected(self):
        self.svc.credit(self.alice, "USD", "10")
        with self.assertRaises(InsufficientFunds):
            self.svc.debit(self.alice, "USD", "10.01")
        self.assertEqual(self.bal(self.alice, "USD"), D("10"))

    def test_debit_exact_balance_to_zero(self):
        self.svc.credit(self.alice, "EUR", "10")
        self.assertEqual(self.svc.debit(self.alice, "EUR", "10"), D("0"))

    def test_invalid_input_rejected(self):
        for cur, amt in [("GBP", "1"), ("USD", "-1"), ("USD", "0"), ("USD", "1.001")]:
            with self.subTest(cur=cur, amt=amt), self.assertRaises(ValidationError):
                self.svc.credit(self.alice, cur, amt)

    def test_balance_cap(self):
        with self.db.transaction() as cur:
            cur.execute("UPDATE balances SET amount_minor = ? WHERE account_id = ? AND currency='USD'",
                        (100_000_000_000, self.alice.id))  # 1,000,000,000.00 (the cap)
        with self.assertRaises(ValidationError):
            self.svc.credit(self.alice, "USD", "0.01")

    def test_admin_cannot_credit(self):
        with self.assertRaises(PermissionDenied):
            self.svc.credit(self.admin, "USD", "1")

    def test_transactions_are_recorded(self):
        self.svc.credit(self.alice, "USD", "100", "salary")
        self.svc.debit(self.alice, "USD", "30", "groceries")
        txs = self.svc.transactions_for(self.alice.id)
        self.assertEqual([t["kind"] for t in txs], ["DEBIT", "CREDIT"])
        self.assertEqual(txs[0]["amount"], D("30"))
        self.assertEqual(txs[1]["memo"], "salary")


# =================================================================== transfer
class TransferTests(ServiceTestCase):
    def setUp(self):
        super().setUp()
        self.svc.credit(self.alice, "USD", "1000")
        self.svc.credit(self.alice, "INR", "5000")

    def test_same_currency_transfer(self):
        r = self.svc.transfer(self.alice, "bob", "USD", "USD", "250.50", "dinner")
        self.assertEqual((r.debited, r.credited, r.rate), (D("250.50"), D("250.50"), D(1)))
        self.assertEqual(self.bal(self.alice, "USD"), D("749.50"))
        self.assertEqual(self.bal(self.bob, "USD"), D("250.50"))

    def test_cross_currency_transfer_uses_rate(self):
        self.svc.set_rate(self.admin, "USD", "INR", "82.5")
        r = self.svc.transfer(self.alice, "bob", "USD", "INR", "10")
        self.assertEqual(r.credited, D("825.00"))
        self.assertEqual(self.bal(self.alice, "USD"), D("990"))
        self.assertEqual(self.bal(self.bob, "INR"), D("825"))
        self.assertEqual(self.bal(self.bob, "USD"), D("0"))

    def test_conversion_rounding(self):
        self.svc.set_rate(self.admin, "INR", "EUR", "0.011086")
        r = self.svc.transfer(self.alice, "bob", "INR", "EUR", "100")
        self.assertEqual(r.credited, D("1.11"))  # 1.1086 -> 1.11 (banker's rounding)

    def test_amount_too_small_to_convert(self):
        self.svc.set_rate(self.admin, "INR", "USD", "0.001")
        with self.assertRaises(ValidationError):
            self.svc.transfer(self.alice, "bob", "INR", "USD", "0.01")

    def test_insufficient_funds_is_atomic(self):
        with self.assertRaises(InsufficientFunds):
            self.svc.transfer(self.alice, "bob", "EUR", "EUR", "1")
        self.assertEqual(self.bal(self.bob, "EUR"), D("0"))
        self.assertEqual(len(self.svc.transactions_for(self.bob.id)), 0)

    def test_cannot_transfer_to_self(self):
        with self.assertRaises(ValidationError):
            self.svc.transfer(self.alice, "alice", "USD", "EUR", "1")

    def test_unknown_or_admin_recipient(self):
        with self.assertRaises(NotFound):
            self.svc.transfer(self.alice, "ghost", "USD", "USD", "1")
        with self.assertRaises(NotFound):
            self.svc.transfer(self.alice, "admin", "USD", "USD", "1")
        self.assertEqual(self.bal(self.alice, "USD"), D("1000"))

    def test_admin_cannot_transfer(self):
        with self.assertRaises(PermissionDenied):
            self.svc.transfer(self.admin, "bob", "USD", "USD", "1")

    def test_recorded_for_both_parties(self):
        self.svc.transfer(self.alice, "bob", "USD", "EUR", "100", "gift")
        out = self.svc.transactions_for(self.alice.id)[0]
        inc = self.svc.transactions_for(self.bob.id)[0]
        self.assertEqual(out["id"], inc["id"])
        self.assertFalse(out["incoming"])
        self.assertTrue(inc["incoming"])
        self.assertEqual(inc["counter_currency"], "EUR")

    def test_money_conservation_same_currency(self):
        before = self.bal(self.alice, "USD") + self.bal(self.bob, "USD")
        for amt in ["1.11", "22.22", "333.33"]:
            self.svc.transfer(self.alice, "bob", "USD", "USD", amt)
        self.svc.transfer(self.bob, "alice", "USD", "USD", "100")
        after = self.bal(self.alice, "USD") + self.bal(self.bob, "USD")
        self.assertEqual(before, after)


# ====================================================================== rates
class RateTests(ServiceTestCase):
    def test_admin_updates_rate(self):
        self.svc.set_rate(self.admin, "EUR", "USD", "1.08")
        self.assertEqual(self.svc.get_rate("EUR", "USD"), D("1.08"))
        hist = self.svc.rate_history()[0]
        self.assertEqual((hist["old_rate"], hist["new_rate"], hist["changed_by"]),
                         (DEFAULT_RATES[("EUR", "USD")], "1.080000", "admin"))

    def test_non_admin_cannot_update_rate(self):
        with self.assertRaises(PermissionDenied):
            self.svc.set_rate(self.alice, "EUR", "USD", "100")
        self.assertEqual(self.svc.get_rate("EUR", "USD"), D(DEFAULT_RATES[("EUR", "USD")]))

    def test_invalid_rates_rejected(self):
        for base, quote, rate in [("USD", "USD", "1"), ("USD", "GBP", "1"),
                                  ("USD", "EUR", "0"), ("USD", "EUR", "-2"), ("USD", "EUR", "abc")]:
            with self.subTest(base=base, quote=quote, rate=rate), self.assertRaises(ValidationError):
                self.svc.set_rate(self.admin, base, quote, rate)

    def test_rate_change_persists_on_disk(self):
        self.svc.set_rate(self.admin, "INR", "USD", "0.0119")
        with sqlite3.connect(self.rates_path) as raw:
            rate = raw.execute(
                "SELECT rate FROM exchange_rates WHERE base='INR' AND quote='USD'").fetchone()[0]
        self.assertEqual(rate, "0.011900")


# ==================================================================== advisor
class AdvisorTests(unittest.TestCase):
    """Pure route maths over a rate table - no database involved."""

    def setUp(self):
        self.rates = {k: D(v) for k, v in DEFAULT_RATES.items()}

    def test_candidate_paths_direct_first(self):
        paths = list(advisor.candidate_paths(Currency.USD, Currency.INR))
        self.assertEqual(paths, [("USD", "INR"), ("USD", "EUR", "INR")])

    def test_every_simple_cycle_listed_once(self):
        self.assertEqual(len(list(advisor.cycles())), 5)  # 3 two-cycles + 2 three-cycles

    def test_recommends_cheaper_indirect_route(self):
        p = advisor.plan(self.rates, Currency.EUR, Currency.INR, 10000)  # 100.00 EUR
        self.assertEqual(p.best.path, ("EUR", "USD", "INR"))
        self.assertEqual(p.best.hop_minor, (10000, 10860, 901380))     # rounded at each hop
        self.assertEqual(p.best.received, D("9013.80"))
        self.assertEqual(p.direct.received, D("8980.00"))
        self.assertEqual(p.best.vs_direct, D("33.80"))
        self.assertTrue(p.improves_on_direct)

    def test_direct_recommended_when_best(self):
        p = advisor.plan(self.rates, Currency.INR, Currency.USD, 100000)
        self.assertTrue(p.best.is_direct)
        self.assertFalse(p.improves_on_direct)
        self.assertLess(p.routes[1].vs_direct, 0)

    def test_tie_prefers_fewer_hops(self):
        rates = {**self.rates, ("USD", "INR"): D("80"), ("USD", "EUR"): D("1"), ("EUR", "INR"): D("80")}
        p = advisor.plan(rates, Currency.USD, Currency.INR, 100)
        self.assertTrue(p.best.is_direct)

    def test_same_currency_rejected(self):
        with self.assertRaises(ValidationError):
            advisor.plan(self.rates, Currency.USD, Currency.USD, 100)

    def test_default_rates_have_no_arbitrage(self):
        self.assertEqual(advisor.arbitrage_loops(self.rates), [])

    def test_arbitrage_loop_detected(self):
        rates = {**self.rates, ("USD", "EUR"): D("0.95")}
        loops = advisor.arbitrage_loops(rates)
        self.assertTrue(loops)
        self.assertEqual(loops[0].path, ("USD", "EUR", "USD"))
        self.assertGreater(loops[0].factor, 1)

    def test_max_safe_rate_is_tight(self):
        limit = advisor.max_safe_rate(self.rates, Currency.USD, Currency.INR)
        self.assertEqual(advisor.arbitrage_loops({**self.rates, ("USD", "INR"): limit}), [])
        self.assertTrue(advisor.arbitrage_loops(
            {**self.rates, ("USD", "INR"): limit + D("0.000001")}))


class ConversionTests(ServiceTestCase):
    def setUp(self):
        super().setUp()
        self.svc.credit(self.alice, "EUR", "1000")

    def test_convert_uses_recommended_route(self):
        route = self.svc.convert(self.alice, "EUR", "INR", "100")
        self.assertEqual(route.code, "EUR>USD>INR")
        self.assertEqual(self.bal(self.alice, "EUR"), D("900"))
        self.assertEqual(self.bal(self.alice, "INR"), D("9013.80"))
        self.assertEqual(self.bal(self.alice, "USD"), D("0"))  # intermediate leg leaves no residue
        tx = self.svc.transactions_for(self.alice.id)[0]
        self.assertEqual((tx["kind"], tx["route"], tx["counter_amount"]), ("CONVERT", "EUR>USD>INR", D("9013.80")))

    def test_convert_direct_on_request(self):
        route = self.svc.convert(self.alice, "EUR", "INR", "100", optimize=False)
        self.assertTrue(route.is_direct)
        self.assertEqual(self.bal(self.alice, "INR"), D("8980"))

    def test_convert_guardrails(self):
        with self.assertRaises(ValidationError):
            self.svc.convert(self.alice, "EUR", "EUR", "1")
        with self.assertRaises(InsufficientFunds):
            self.svc.convert(self.alice, "EUR", "INR", "1000.01")
        with self.assertRaises(PermissionDenied):
            self.svc.convert(self.admin, "EUR", "INR", "1")
        self.assertEqual(self.bal(self.alice, "EUR"), D("1000"))

    def test_optimized_transfer(self):
        r = self.svc.transfer(self.alice, "bob", "EUR", "INR", "100", optimize=True)
        self.assertEqual(r.credited, D("9013.80"))
        self.assertEqual(self.bal(self.bob, "INR"), D("9013.80"))
        self.assertEqual(self.svc.transactions_for(self.bob.id)[0]["route"], "EUR>USD>INR")

    def test_plain_transfer_stays_direct(self):
        r = self.svc.transfer(self.alice, "bob", "EUR", "INR", "100")
        self.assertEqual(r.credited, D("8980.00"))

    def test_rate_creating_arbitrage_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            self.svc.set_rate(self.admin, "USD", "EUR", "0.95")
        self.assertIn("risk-free loop", str(ctx.exception))
        self.assertIn("maximum safe", str(ctx.exception))
        self.assertEqual(self.svc.get_rate("USD", "EUR"), D("0.92"))
        self.assertEqual(self.svc.rate_history(), [])

    def test_lowering_a_rate_is_always_allowed(self):
        self.svc.set_rate(self.admin, "USD", "EUR", "0.5")
        self.assertEqual(self.svc.arbitrage_loops(), [])

    def test_existing_arbitrage_suspends_cross_currency(self):
        with self.db.transaction() as cur:  # e.g. a tampered or legacy rates file
            cur.execute("UPDATE persist.exchange_rates SET rate = '0.95' WHERE base='USD' AND quote='EUR'")
        self.assertTrue(self.svc.arbitrage_loops())
        with self.assertRaises(ValidationError):
            self.svc.convert(self.alice, "EUR", "USD", "10")
        with self.assertRaises(ValidationError):
            self.svc.transfer(self.alice, "bob", "EUR", "USD", "10")
        self.svc.transfer(self.alice, "bob", "EUR", "EUR", "10")  # same currency still fine
        self.assertEqual(self.bal(self.bob, "EUR"), D("10"))

    def test_legacy_seed_is_upgraded_but_admin_edits_kept(self):
        self.db.close()
        with sqlite3.connect(self.rates_path) as raw:
            raw.execute("UPDATE exchange_rates SET rate='1.087000', updated_by='system' "
                        "WHERE base='EUR' AND quote='USD'")
            raw.execute("UPDATE exchange_rates SET rate='90.200000', updated_by='admin' "
                        "WHERE base='EUR' AND quote='INR'")
        self.db = Database(self.rates_path)
        svc = LedgerService(self.db)
        self.assertEqual(svc.get_rate("EUR", "USD"), D("1.086"))   # seeded value corrected
        self.assertEqual(svc.get_rate("EUR", "INR"), D("90.2"))    # admin's choice untouched


# ================================================================ concurrency
class ConcurrencyTests(ServiceTestCase):
    def test_parallel_credits_and_transfers_are_consistent(self):
        self.svc.credit(self.alice, "USD", "1000")
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(20):
                    self.svc.credit(self.bob, "USD", "1")
                    self.svc.transfer(self.alice, "bob", "USD", "USD", "1")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.bal(self.alice, "USD"), D("840"))   # 1000 - 160
        self.assertEqual(self.bal(self.bob, "USD"), D("320"))     # 160 credits + 160 transfers


# ===================================================================== web GUI
class WebGuiTests(WebTestCase):
    def test_login_page_and_redirects(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertIn(b"Log in", self.client.get("/login").data)
        r = self.login("alice", USER_PW)
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/dashboard"))

    def test_admin_login_goes_to_admin_page(self):
        r = self.login("admin", ADMIN_PW)
        self.assertTrue(r.headers["Location"].endswith("/admin"))
        self.assertIn(b"Administration", self.client.get("/admin").data)

    def test_admin_login_page(self):
        html = self.client.get("/admin/login").get_data(as_text=True)
        self.assertIn("Administrator login", html)
        self.assertIn('href="/admin/login"', self.client.get("/login").get_data(as_text=True))
        token = self.csrf("/admin/login")
        r = self.client.post("/admin/login", data={"username": "admin", "password": ADMIN_PW,
                                                   "csrf_token": token})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/admin"))

    def test_admin_login_refuses_customers(self):
        token = self.csrf("/admin/login")
        r = self.client.post("/admin/login", data={"username": "alice", "password": USER_PW,
                                                   "csrf_token": token})
        self.assertEqual(r.status_code, 403)
        self.assertIn(b"administrators only", r.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)  # not logged in

    def test_anonymous_admin_page_redirects_to_admin_login(self):
        self.assertIn("/admin/login", self.client.get("/admin").headers["Location"])

    def test_customer_on_admin_page_can_switch_account(self):
        self.login("alice", USER_PW)
        r = self.client.get("/admin")
        self.assertEqual(r.status_code, 403)
        self.assertIn(b"Log out and sign in as administrator", r.data)
        r = self.post("/logout", {"next": "admin"}, follow=False)
        self.assertTrue(r.headers["Location"].endswith("/admin/login"))

    def test_bad_login(self):
        r = self.login("alice", "wrong-pass1")
        self.assertEqual(r.status_code, 401)
        self.assertIn(b"Invalid username or password", r.data)

    def test_dashboard_shows_three_balances_and_rates(self):
        self.login("alice", USER_PW)
        html = self.client.get("/dashboard").get_data(as_text=True)
        for cur in ("USD", "EUR", "INR"):
            self.assertIn(f'id="balance-{cur}"', html)
        self.assertIn("Exchange rates", html)

    def test_credit_and_debit_through_gui(self):
        self.login("alice", USER_PW)
        r = self.post("/entry", {"kind": "credit", "currency": "EUR", "amount": "75.25"})
        self.assertIn(b"Credited 75.25 EUR", r.data)
        r = self.post("/entry", {"kind": "debit", "currency": "EUR", "amount": "25.25"})
        self.assertIn(b"Debited 25.25 EUR", r.data)
        self.assertEqual(self.bal("alice", "EUR"), D("50"))

    def test_gui_shows_validation_errors(self):
        self.login("alice", USER_PW)
        r = self.post("/entry", {"kind": "debit", "currency": "USD", "amount": "5"})
        self.assertIn(b"Insufficient USD funds", r.data)
        r = self.post("/entry", {"kind": "credit", "currency": "GBP", "amount": "5"})
        self.assertIn(b"Unsupported currency", r.data)
        r = self.post("/entry", {"kind": "steal", "currency": "USD", "amount": "5"})
        self.assertIn(b"Unknown operation", r.data)

    def test_transfer_through_gui(self):
        self.login("alice", USER_PW)
        self.post("/entry", {"kind": "credit", "currency": "USD", "amount": "100"})
        r = self.post("/transfer", {"to_username": "bob", "from_currency": "USD",
                                    "to_currency": "USD", "amount": "40", "memo": "lunch"})
        self.assertIn(b"Transferred 40 USD to bob", r.data)
        self.assertEqual(self.bal("alice", "USD"), D("60"))
        self.assertEqual(self.bal("bob", "USD"), D("40"))
        # bob sees the incoming transfer
        self.post("/logout", {})
        self.login("bob", USER_PW)
        self.assertIn(b"TRANSFER IN", self.client.get("/dashboard").data)

    def test_admin_creates_and_deletes_account_through_gui(self):
        self.login("admin", ADMIN_PW)
        r = self.post("/admin/accounts", {"username": "carol", "full_name": "Carol",
                                          "password": "CarolPass1", "role": "user"})
        self.assertIn(b"Account &#39;carol&#39; created", r.data)
        carol = self.svc.get_account_by_username("carol")
        r = self.post(f"/admin/accounts/{carol.id}/delete", {})
        self.assertIn(b"Account deleted", r.data)
        with self.assertRaises(NotFound):
            self.svc.get_account(carol.id)

    def test_admin_updates_rate_through_gui(self):
        self.login("admin", ADMIN_PW)
        r = self.post("/admin/rates", {"base": "USD", "quote": "EUR", "rate": "0.90"})
        self.assertIn(b"set to 0.900000", r.data)
        self.assertEqual(self.svc.get_rate("USD", "EUR"), D("0.90"))
        r = self.post("/admin/rates", {"base": "USD", "quote": "EUR", "rate": "-1"})
        self.assertIn(b"Rate must be a positive number", r.data)

    def test_change_password_through_gui(self):
        self.login("alice", USER_PW)
        r = self.post("/password", {"current_password": USER_PW, "new_password": "Fresh1234",
                                    "confirm_password": "Fresh1234"})
        self.assertIn(b"Password changed", r.data)
        self.post("/logout", {})
        self.assertEqual(self.login("alice", "Fresh1234").status_code, 302)

    def test_logout(self):
        self.login("alice", USER_PW)
        self.post("/logout", {})
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])


# ================================================================ web security
class WebSecurityTests(WebTestCase):
    def test_pages_require_login(self):
        for path in ["/dashboard", "/admin", "/password"]:
            with self.subTest(path=path):
                r = self.client.get(path)
                self.assertEqual(r.status_code, 302)
                self.assertIn("/login", r.headers["Location"])

    def test_user_cannot_access_admin_functions(self):
        self.login("alice", USER_PW)
        self.assertEqual(self.client.get("/admin").status_code, 403)
        bob = self.svc.get_account_by_username("bob")
        for path, data in [("/admin/accounts", {"username": "evil", "full_name": "E",
                                                "password": "Evil12345"}),
                           (f"/admin/accounts/{bob.id}/delete", {}),
                           ("/admin/rates", {"base": "USD", "quote": "INR", "rate": "1"})]:
            with self.subTest(path=path):
                self.assertEqual(self.post(path, data, follow=False).status_code, 403)
        self.assertEqual(self.svc.get_rate("USD", "INR"), D(DEFAULT_RATES[("USD", "INR")]))
        self.assertIsNotNone(self.svc.get_account(bob.id))

    def test_post_without_csrf_token_is_rejected(self):
        self.login("alice", USER_PW)
        r = self.client.post("/entry", data={"kind": "credit", "currency": "USD", "amount": "5"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/entry", data={"kind": "credit", "currency": "USD",
                                             "amount": "5", "csrf_token": "forged"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.bal("alice", "USD"), D("0"))

    def test_login_requires_csrf(self):
        r = self.client.post("/login", data={"username": "alice", "password": USER_PW})
        self.assertEqual(r.status_code, 400)

    def test_security_headers(self):
        r = self.client.get("/login")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.login("alice", USER_PW)
        self.assertEqual(self.client.get("/dashboard").headers["Cache-Control"], "no-store")

    def test_session_cookie_flags(self):
        r = self.login("alice", USER_PW)
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_session_is_regenerated_on_login(self):
        token_before = self.csrf("/login")
        self.login("alice", USER_PW)
        self.assertNotEqual(token_before, self.csrf("/dashboard"))

    def test_sql_injection_in_login_fails(self):
        for payload in ["' OR '1'='1", "admin'--", "\" OR 1=1 --"]:
            with self.subTest(payload=payload):
                self.assertEqual(self.login(payload, payload).status_code, 401)
        self.assertEqual(self.svc.admin_count(), 1)

    def test_stored_xss_is_escaped(self):
        self.login("alice", USER_PW)
        self.post("/entry", {"kind": "credit", "currency": "USD", "amount": "1",
                             "memo": "<script>alert(1)</script>"})
        html = self.client.get("/dashboard").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_cannot_move_someone_elses_money(self):
        """There is no way to name a source account: transfers always debit the session user."""
        self.svc.credit(self.svc.get_account_by_username("bob"), "USD", "100")
        self.login("alice", USER_PW)
        self.post("/transfer", {"to_username": "alice", "from_currency": "USD",
                                "to_currency": "USD", "amount": "50", "account_id": "3",
                                "from_username": "bob"})
        self.assertEqual(self.bal("bob", "USD"), D("100"))
        self.assertEqual(self.bal("alice", "USD"), D("0"))

    def test_deleted_user_session_is_invalidated(self):
        self.login("bob", USER_PW)
        admin = self.svc.get_account_by_username("admin")
        bob = self.svc.get_account_by_username("bob")
        self.svc.delete_account(admin, bob.id)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_open_redirect_blocked(self):
        token = self.csrf("/login")
        r = self.client.post("/login?next=//evil.example.com",
                             data={"username": "alice", "password": USER_PW, "csrf_token": token})
        self.assertNotIn("evil.example.com", r.headers["Location"])

    def test_oversized_request_rejected(self):
        self.login("alice", USER_PW)
        r = self.client.post("/entry", data={"memo": "x" * 50_000, "csrf_token": self.csrf("/")})
        self.assertEqual(r.status_code, 413)

    def test_brute_force_lockout_via_gui(self):
        for _ in range(MAX_FAILED_LOGINS):
            self.login("bob", "wrong-pass1")
        r = self.login("bob", USER_PW)
        self.assertEqual(r.status_code, 401)
        self.assertIn(b"locked", r.data)


# ============================================================ advisor web GUI
class AdvisorWebTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.svc.credit(self.svc.get_account_by_username("alice"), "EUR", "500")

    def test_requires_login(self):
        self.assertIn("/login", self.client.get("/advisor").headers["Location"])

    def test_graphical_recommendation(self):
        self.login("alice", USER_PW)
        html = self.client.get("/advisor?from=EUR&to=INR&amount=100").get_data(as_text=True)
        self.assertIn("Convert via <strong>EUR → USD → INR</strong>", html)
        self.assertIn("9,013.80", html)
        self.assertEqual(html.count('<g class="edge '), 6)          # network: 6 directed rates
        self.assertEqual(html.count('class="edge best"'), 2)        # 2 highlighted hops
        self.assertIn('class="bar-row better is-best"', html)        # bar chart
        self.assertIn('class="cell h3 selected"', html)              # heatmap cell for EUR->INR
        self.assertIn("All routes", html)                            # table view

    def test_direct_recommendation(self):
        self.login("alice", USER_PW)
        html = self.client.get("/advisor?from=INR&to=USD&amount=1000").get_data(as_text=True)
        self.assertIn("Convert <strong>directly</strong>", html)

    def test_invalid_input_shows_error(self):
        self.login("alice", USER_PW)
        for q in ["from=USD&to=USD&amount=1", "from=GBP&to=USD&amount=1",
                  "from=USD&to=EUR&amount=-4", "from=USD&to=EUR&amount=%3Cscript%3E"]:
            with self.subTest(q=q):
                r = self.client.get(f"/advisor?{q}")
                self.assertEqual(r.status_code, 200)
                self.assertIn(b'class="flash error"', r.data)
                self.assertNotIn(b"<script>", r.data)

    def test_no_inline_scripts(self):
        self.login("alice", USER_PW)
        html = self.client.get("/advisor").get_data(as_text=True)
        self.assertEqual(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html), [])
        self.assertNotIn(" style=", html)

    def test_convert_from_advisor(self):
        self.login("alice", USER_PW)
        r = self.post("/convert", {"from": "EUR", "to": "INR", "amount": "100", "route": "best"})
        self.assertIn(b"via EUR \xe2\x86\x92 USD \xe2\x86\x92 INR", r.data)
        self.assertEqual(self.bal("alice", "INR"), D("9013.80"))
        r = self.post("/convert", {"from": "EUR", "to": "INR", "amount": "100", "route": "direct"})
        self.assertEqual(self.bal("alice", "INR"), D("17993.80"))
        self.assertIn(b"CONVERT", self.client.get("/dashboard").data)

    def test_convert_requires_csrf(self):
        self.login("alice", USER_PW)
        r = self.client.post("/convert", data={"from": "EUR", "to": "INR", "amount": "1"})
        self.assertEqual(r.status_code, 400)

    def test_optimized_transfer_from_dashboard(self):
        self.login("alice", USER_PW)
        r = self.post("/transfer", {"to_username": "bob", "from_currency": "EUR", "to_currency": "INR",
                                    "amount": "100", "optimize": "on"})
        self.assertIn(b"optimized rate", r.data)
        self.assertEqual(self.bal("bob", "INR"), D("9013.80"))

    def test_admin_sees_advisor_but_cannot_convert(self):
        self.login("admin", ADMIN_PW)
        html = self.client.get("/advisor?from=EUR&to=INR&amount=100").get_data(as_text=True)
        self.assertIn("Recommendation", html)
        self.assertNotIn("Convert my EUR", html)
        r = self.post("/convert", {"from": "EUR", "to": "INR", "amount": "1"})
        self.assertIn(b"do not hold balances", r.data)

    def test_admin_rate_form_rejects_arbitrage(self):
        self.login("admin", ADMIN_PW)
        r = self.post("/admin/rates", {"base": "EUR", "quote": "USD", "rate": "1.2"})
        self.assertIn(b"risk-free loop", r.data)
        self.assertEqual(self.svc.get_rate("EUR", "USD"), D(DEFAULT_RATES[("EUR", "USD")]))

    def test_admin_warned_about_existing_arbitrage(self):
        db = self.app.extensions["ledger_db"]
        with db.transaction() as cur:
            cur.execute("UPDATE persist.exchange_rates SET rate = '0.95' WHERE base='USD' AND quote='EUR'")
        self.login("admin", ADMIN_PW)
        self.assertIn(b"Arbitrage detected", self.client.get("/admin").data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
