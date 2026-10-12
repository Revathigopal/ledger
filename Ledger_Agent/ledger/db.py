"""Storage layer.

* The ledger itself (accounts, balances, transactions, audit log) lives in an
  **in-memory** SQLite database - it is wiped whenever the process stops.
* Exchange rates (and their change history) live in a **file-backed** SQLite
  database that is ``ATTACH``-ed to the same connection under the schema name
  ``persist``. One connection means a single transaction can atomically touch
  both databases.

All access goes through ``Database.transaction()`` / ``Database.query()``, which
serialise use of the shared connection with a re-entrant lock so the threaded
Flask server is safe.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .guardrails import CURRENCIES

DEFAULT_RATES: dict[tuple[str, str], str] = {
    ("USD", "EUR"): "0.920000",
    ("USD", "INR"): "83.000000",
    ("EUR", "USD"): "1.086000",
    ("EUR", "INR"): "89.800000",  # thinly traded pair: wider spread, routing via USD pays more
    ("INR", "USD"): "0.012048",
    ("INR", "EUR"): "0.011086",
}

_MEMORY_SCHEMA = """
CREATE TABLE accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name       TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE balances (
    account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    currency        TEXT NOT NULL CHECK (currency IN ('USD', 'EUR', 'INR')),
    amount_minor    INTEGER NOT NULL DEFAULT 0 CHECK (amount_minor >= 0),
    PRIMARY KEY (account_id, currency)
);

-- Ledger history. No FK to accounts so history survives account deletion.
CREATE TABLE transactions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                  TEXT NOT NULL CHECK (kind IN ('CREDIT', 'DEBIT', 'TRANSFER', 'CONVERT')),
    account_id            INTEGER NOT NULL,
    account_username      TEXT NOT NULL,
    currency              TEXT NOT NULL,
    amount_minor          INTEGER NOT NULL CHECK (amount_minor > 0),
    counterparty_id       INTEGER,
    counterparty_username TEXT,
    counter_currency      TEXT,
    counter_amount_minor  INTEGER,
    rate                  TEXT,
    route                 TEXT,
    memo                  TEXT NOT NULL DEFAULT '',
    created_at            TEXT NOT NULL
);
CREATE INDEX ix_tx_account ON transactions(account_id);
CREATE INDEX ix_tx_counterparty ON transactions(counterparty_id);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    details         TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
"""

_PERSISTENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS persist.exchange_rates (
    base        TEXT NOT NULL,
    quote       TEXT NOT NULL,
    rate        TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    PRIMARY KEY (base, quote),
    CHECK (base <> quote)
);

CREATE TABLE IF NOT EXISTS persist.rate_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    base        TEXT NOT NULL,
    quote       TEXT NOT NULL,
    old_rate    TEXT,
    new_rate    TEXT NOT NULL,
    changed_by  TEXT NOT NULL,
    changed_at  TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    def __init__(self, rates_path: str | Path) -> None:
        self.rates_path = str(rates_path)
        if self.rates_path != ":memory:":
            Path(self.rates_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            ":memory:", check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("ATTACH DATABASE ? AS persist", (self.rates_path,))
        self._conn.executescript(_MEMORY_SCHEMA)
        self._conn.executescript(_PERSISTENT_SCHEMA)
        self._seed_rates()

    def _seed_rates(self) -> None:
        with self.transaction() as cur:
            for base in CURRENCIES:
                for quote in CURRENCIES:
                    if base == quote:
                        continue
                    cur.execute(
                        "INSERT OR IGNORE INTO persist.exchange_rates "
                        "(base, quote, rate, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                        (base, quote, DEFAULT_RATES[(base, quote)], utcnow(), "system"),
                    )
            # Earlier releases seeded EUR->USD = 1.087, which together with the other
            # defaults formed a risk-free loop (USD->INR->EUR->USD = x1.00019), and a
            # tighter EUR->INR quote. Upgrade those seeds only if nobody has edited them.
            for base, quote, old in (("EUR", "USD", "1.087000"), ("EUR", "INR", "90.200000")):
                cur.execute(
                    "UPDATE persist.exchange_rates SET rate = ? "
                    "WHERE base = ? AND quote = ? AND rate = ? AND updated_by = 'system'",
                    (DEFAULT_RATES[(base, quote)], base, quote, old),
                )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """Run a block atomically (BEGIN IMMEDIATE ... COMMIT / ROLLBACK)."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
            except BaseException:
                cur.execute("ROLLBACK")
                raise
            else:
                cur.execute("COMMIT")
            finally:
                cur.close()

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def table_names(self, schema: str = "main") -> set[str]:
        match schema:
            case "main":
                sql = "SELECT name FROM main.sqlite_master WHERE type = 'table'"
            case "persist":
                sql = "SELECT name FROM persist.sqlite_master WHERE type = 'table'"
            case _:
                raise ValueError("unknown schema")
        rows = self.query(sql)
        return {r["name"] for r in rows if not r["name"].startswith("sqlite_")}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
