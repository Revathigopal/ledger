# Ledger Application

A small multi-currency ledger web application written in Python. Individuals hold
balances in **USD, EUR and INR**, can **credit** (deposit) and **debit** (withdraw)
their own account, and can **transfer** money to another account with automatic
currency conversion. A graphical **conversion advisor** recommends the best-paying
route between currencies (direct, or through a third currency) and can execute it.
**Administrators** create and delete accounts and maintain the
**exchange-rate table**, which is stored persistently on disk. Everything else is
kept in an in-memory database.

The project also includes a unit/integration test suite (`test.py`) and a test
**orchestrator** (`orchestrator.py`). The orchestrator applies static security
**guardrails** to the code, runs the test suite, starts the real server, exercises
every feature over HTTP, and probes the server for common web vulnerabilities.

---

## 1. Technology stack and rationale

| Layer | Choice | Why |
|---|---|---|
| Language | **Python 3.12+** (developed on 3.14) | Uses modern features: `enum.StrEnum` for currencies, `@dataclass(slots=True, frozen=True)` for immutable domain objects, structural pattern matching (`match`), `X \| None` type unions, `datetime.UTC`. |
| Web framework / GUI | **Flask 3.1** + **Jinja2** server-rendered HTML | Lightweight and explicit, with no build step. Server-side rendering keeps all logic and authorization on the server. Jinja2 auto-escapes output, which protects against XSS by default. The pages contain no JavaScript, so a strict Content-Security-Policy is possible. |
| Ledger database | **SQLite in-memory** (`:memory:`) via the standard-library `sqlite3` | Meets the in-memory requirement and still gives real SQL: ACID transactions, `CHECK` constraints (balances can never go negative), foreign keys with cascading deletes, and indexes. Needs no external server. |
| Rate database | **SQLite file** (`data/rates.db`), `ATTACH`-ed to the same connection | Persistent, as required. Because both databases share one connection, a single transaction can update the in-memory audit log and the on-disk rate tables atomically. |
| Money arithmetic | `decimal.Decimal` + integer minor units (cents/paise) | Avoids binary floating-point rounding errors. Conversions use banker's rounding (`ROUND_HALF_EVEN`). |
| Password hashing | `werkzeug.security` (scrypt) | A strong, salted, memory-hard hash. Ships with Flask, so no extra dependency is needed. |
| Tests | Standard-library **`unittest`** + Flask test client | No extra dependency. Also works unchanged under `pytest`. |
| Orchestrator | Standard library only (`ast`, `subprocess`, `urllib`) | Runs the stages in order, starts a real server process, and drives it like a browser (cookies + CSRF tokens). |
| Charts | Server-rendered **inline SVG** (geometry computed in `ledger/viz.py`) + one small static script for tooltips | No charting library or CDN, and nothing inline, so the strict CSP still holds. The charts render without JavaScript. Colours come from CSS variables with separate light and dark values (a blue/red diverging pair and a sequential blue ramp from a validated data-viz palette). |
| Optional scanners | **bandit** (static security analysis), **pip-audit** (dependency CVEs) | Industry-standard tools. The orchestrator uses them when they are installed. |

The only runtime dependency is **Flask** (`requirements.txt`).

---

## 2. Project structure

```
Ledger_Agent/
├── app.py                  # Entry point: python app.py [--demo] [--port N] [--rates-db PATH]
├── ledger/                 # Application package
│   ├── __init__.py         # create_app() factory: config, DB, admin bootstrap, error pages
│   ├── guardrails.py       # Input validation: amounts, currencies, rates, usernames, passwords, memos
│   ├── db.py               # Database: in-memory ledger + ATTACHed persistent rate DB, schemas, seeding
│   ├── services.py         # LedgerService: business rules + role checks (accounts, auth, credit/debit, transfer, rates)
│   ├── security.py         # CSRF tokens, session login, login_required/admin_required, security headers
│   ├── advisor.py          # Conversion-route optimiser + arbitrage detection (pure functions)
│   ├── viz.py              # SVG geometry for the advisor charts
│   ├── web.py              # Flask blueprint: GUI routes
│   ├── templates/          # Jinja2 pages (login, dashboard, advisor, admin, password, error)
│   └── static/             # style.css (light + dark, mobile-friendly), viz.js (chart tooltips)
├── test.py                 # Unit + integration test suite (113 tests)
├── orchestrator.py         # Multi-stage test orchestrator with guardrails + security probes
├── requirements.txt        # Runtime dependency (Flask)
├── requirements-dev.txt    # + bandit, pip-audit for the optional scanner stage
├── data/rates.db           # Created at first run: persistent exchange rates (git-ignored)
└── reports/                # Orchestrator JSON report (git-ignored)
```

### Architecture

```
Browser ──HTML forms──▶ web.py (routes) ──▶ services.py (business rules + authorization)
                          │                        │
                 security.py (CSRF,         guardrails.py (validation)
                 sessions, headers,                │
                 role decorators)                  ▼
                                        db.py ── one SQLite connection
                                           ├── main    (in-memory): accounts, balances, transactions, audit_log
                                           └── persist (rates.db):  exchange_rates, rate_history
```

Authorization is enforced **twice**: by route decorators in `web.py`, and again
inside `LedgerService`. A route that forgot its decorator still could not let a
non-admin create accounts or change rates.

### Data model

| Table | Storage | Purpose |
|---|---|---|
| `accounts` | memory | Username (unique, case-insensitive), full name, password hash, role (`user`/`admin`), failed-login counter, lock-out time |
| `balances` | memory | One row per (account, currency), stored as integer minor units with `CHECK (amount_minor >= 0)` |
| `transactions` | memory | Every CREDIT, DEBIT, TRANSFER and CONVERT, including the effective rate, the converted amount, the **route** taken (e.g. `EUR>USD>INR`) and a memo. Kept after an account is deleted. |
| `audit_log` | memory | Security-relevant events: logins, failed logins, account create/delete, rate changes, password changes |
| `exchange_rates` | **disk** | Directional rate for each currency pair (6 pairs), with who updated it and when |
| `rate_history` | **disk** | Every rate change (old → new, by whom, when) |

---

## 3. Running the application

```bash
cd Ledger_Agent
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Option A: choose the admin password yourself
export LEDGER_ADMIN_PASSWORD='Admin12345'
python app.py --demo                 # --demo also creates users alice and bob

# Option B: let the app generate a random admin password (printed at start-up)
python app.py
```

Open **http://127.0.0.1:5000**.

- Customers sign in at **http://127.0.0.1:5000/login** (*Customer login*).
- Administrators sign in at **http://127.0.0.1:5000/admin/login** (*Admin login*). This page refuses customer accounts.

Both pages are linked from the top bar and from tabs on the login form. If you open an admin page while signed in as a customer, the 403 page offers **Log out and sign in as administrator**.

| Login | Password | Notes |
|---|---|---|
| `admin` | the value of `LEDGER_ADMIN_PASSWORD`, or the generated one printed in the console | Administrator |
| `alice` | `password123` | Only with `--demo`. Starts with USD 1000, EUR 500, INR 25000. |
| `bob` | `password123` | Only with `--demo`. Starts with USD 200, EUR 100, INR 10000. |

### Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LEDGER_ADMIN_USERNAME` | `admin` | Username of the bootstrap administrator |
| `LEDGER_ADMIN_PASSWORD` | *(random, printed)* | Bootstrap admin password (≥ 8 characters, at least one letter and one digit) |
| `LEDGER_SECRET_KEY` | *(random per start)* | Flask session-signing key. Set it to keep sessions valid across restarts. |
| `LEDGER_RATES_DB` | `data/rates.db` | Path of the persistent exchange-rate database (also `--rates-db`) |
| `LEDGER_SECURE_COOKIES` | unset | Set to `1` when serving over HTTPS, to mark cookies `Secure` |

> **Note:** accounts, balances and transactions are held **in memory**, so they are
> lost when the server stops. This is by design. Exchange rates and their history
> survive restarts. For production use, run the app behind a WSGI server such as
> `gunicorn 'ledger:create_app()'` or `waitress` with HTTPS instead of the built-in
> development server.

---

## 4. Using the features (manual walkthrough)

1. **Log in as admin** at `/admin/login` (or click *Admin login*). You land on **Administration**.
2. **Create accounts.** Use *Create account* to add a username, full name, initial
   password and role (`user` or `admin`). A new user starts with 0.00 in USD, EUR
   and INR.
3. **Update exchange rates.** Under *Update exchange rate*, pick *From* and *To* and
   enter the rate (1 From = *rate* To, up to 6 decimals). The *Exchange rates* table
   and the *Rate history* table update. Restart the server and the new rate is
   still there.
4. **Delete accounts.** Click *Delete* in the accounts table. If the account still
   holds funds, the deletion is refused unless you tick **force**. You cannot delete
   yourself or the last administrator.
5. **Log out**, then **log in as a user** (for example `alice`). The dashboard
   shows the three balances.
6. **Credit or debit.** Choose *Credit (deposit)* or *Debit (withdraw)*, a
   currency, an amount (up to 2 decimals) and an optional memo. Overdrafts are
   rejected.
7. **Transfer.** Enter the recipient's username, the currency to **send from**, the
   currency the recipient **receives in**, and the amount. The app converts the
   amount using the current rate. For example, 10 USD → INR at 83 credits 830.00 INR.
   You cannot transfer to yourself, to an admin, to a non-existent user, or more
   than your balance. **Use optimized route** (ticked by default) pays the
   recipient along the best-paying route when the currencies differ.
8. **History.** *Recent transactions* lists credits, debits, outgoing transfers and
   incoming transfers, with the rate that was used.
9. **Conversion advisor.** Click *Conversion advisor* in the top bar, then choose
   *From*, *To* and an amount. The page shows:
   - a **recommendation** card: the best route and how much more it pays than
     converting directly. Customers can execute it on their own balances with
     *Convert my … using the recommended route*, or choose *Convert directly instead*;
   - a **route network**: every currency as a node and every rate as an arrow, with
     the recommended route highlighted and its steps numbered, and the direct route dashed;
   - a **gain vs direct** bar chart: blue bars pay more than direct, red bars pay less;
   - an **All routes** table: hop rates, the amount after each hop, and the effective rate;
   - a **Where routing helps** heatmap: for every currency pair, how much the best
     route beats the direct rate. Click a cell to analyse that pair.

   Hover over (or Tab to) any arrow, bar or cell for a tooltip. With the default
   rates, **EUR → INR via USD** pays about 0.38% more than the direct EUR→INR rate.
10. **Change password.** Use the *Password* link in the top bar.
11. The **Audit log** on the admin page shows logins, failed logins, account
    changes and rate changes.

### Guardrails and limits

| Rule | Limit |
|---|---|
| Currencies | USD, EUR, INR only |
| Amount | > 0, at most 2 decimals, ≤ 1,000,000.00 per transaction. Rejects `NaN`, `1e9`, negatives and `1,000`. |
| Balance | ≥ 0 (enforced by validation **and** a DB `CHECK`), ≤ 1,000,000,000.00 per currency |
| Rate | > 0, ≤ 1,000,000, at most 6 decimals. Base ≠ quote. **No arbitrage:** a rate that would let money grow around a loop (e.g. USD→EUR→USD > 1) is rejected, and the error shows the maximum safe value. |
| Conversion | If the stored rates ever contain such a loop (e.g. a hand-edited rates file), conversions and cross-currency transfers are suspended and admins see a warning until it is fixed. Same-currency transfers keep working. |
| Username | 3–32 characters from `A–Z a–z 0–9 . _ -`, case-insensitive |
| Password | 8–128 characters, at least one letter and one digit. Stored as a scrypt hash. |
| Memo / name | ≤ 140 / 80 characters. Control characters and bidi overrides are stripped. |
| Login | Generic error message. Lock-out for 5 minutes after 5 failed attempts. |
| Web | CSRF token on every POST, session regenerated at login, `HttpOnly` + `SameSite=Lax` cookies, 30-minute session lifetime, strict CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store` on authenticated pages, 16 KB request limit, open-redirect protection |

---

## 5. Testing

### 5.1 Unit and integration tests: `test.py`

```bash
source .venv/bin/activate
python test.py                       # run everything (113 tests, about 45 s, mostly password hashing)
python -m unittest test -v           # same thing
python test.py TransferTests         # one group
python test.py TransferTests.test_cross_currency_transfer_uses_rate   # one test
pytest test.py -q                    # also works if pytest is installed
```

Each test gets a fresh in-memory ledger and a temporary rates file, so tests never
touch `data/rates.db` and can run in any order.

| Test group | What it verifies |
|---|---|
| `GuardrailTests` | Every validator accepts good input and rejects bad input: negative/zero/NaN/exponent amounts, unknown currencies, malformed rates, SQL-ish usernames, weak passwords, control characters |
| `DatabaseTests` | Ledger tables live in memory. Only the rate tables exist on disk. Default rates are seeded. After a simulated restart, rates and history **persist** and accounts are **gone**. The DB `CHECK` blocks negative balances. |
| `AccountAdminTests` | Only admins create/delete. New accounts start at zero in all 3 currencies. Duplicate usernames are rejected. Deleting a funded account requires `force`. Admins cannot delete themselves or the last admin. History survives deletion. Actions are audited. |
| `AuthenticationTests` | Login works and usernames are case-insensitive. Errors are identical for a wrong password and an unknown user. Lock-out happens after 5 failures and expires. Passwords are hashed. Password change works. |
| `CreditDebitTests` | Credit and debit in each currency. Currencies are independent. Overdrafts are rejected. Balance cap. Admins have no wallet. Transactions are recorded. |
| `TransferTests` | Same-currency and cross-currency transfers using the rate. Rounding. Amounts too small to convert. Failed transfers leave balances unchanged. No self, admin or unknown recipients. Both parties see the transfer. Money is conserved. |
| `RateTests` | Admin updates rates and history is recorded. Non-admins are refused. Invalid rates are rejected. The new value is written to the on-disk file. |
| `AdvisorTests` | Route enumeration, per-hop rounding, best route vs direct, preferring fewer hops on a tie, detecting arbitrage loops, and checking that the "maximum safe rate" is exact (that value is accepted; one millionth more is rejected) |
| `ConversionTests` | Converting own balances along the recommended or direct route, the transaction record and route, guardrails (same currency, overdraft, admin), optimized transfers, rejected arbitrage rates, suspension when the stored rates contain a loop, and the upgrade of legacy seed rates |
| `ConcurrencyTests` | 8 threads crediting and transferring in parallel produce exact final balances (no lost updates). |
| `WebGuiTests` | Every GUI flow through the Flask test client: login redirects, dashboard balances, credit/debit, error messages, transfer, admin create/delete account, admin rate update, password change, logout |
| `WebSecurityTests` | Login is required. Users get 403 on all admin endpoints. POSTs without a CSRF token, or with a forged one, are rejected. Security headers and cookie flags are set. The session is regenerated at login. SQL injection, stored XSS, moving someone else's money, sessions of deleted users, open redirects, oversized requests and brute-force lock-out are all handled. |
| `AdvisorWebTests` | The advisor page needs a login and renders the recommendation, network, bars, heatmap and table. Invalid or hostile query input is handled safely. There are no inline scripts or styles. Convert works from the page and needs a CSRF token. Optimized transfers work from the dashboard. Admins can view the page but not convert. The admin rate form rejects arbitrage, and the admin page warns about existing arbitrage. |

### 5.2 Orchestrated testing with guardrails: `orchestrator.py`

```bash
python orchestrator.py                        # run all stages
python orchestrator.py --stages e2e security  # run selected stages
python orchestrator.py --list                 # list the stages
pip install -r requirements-dev.txt           # optional: enables the bandit and pip-audit stage
```

| Stage | What it does |
|---|---|
| `preflight` | Checks the Python version, that Flask is installed, and that the expected files are present |
| `guardrails` | **Static rules on the source code** (AST and template analysis). Fails the build if any of these is broken: SQL must be constant strings with `?` placeholders (no f-string, `%` or `+` SQL); no `eval`, `exec`, `os.system`, `pickle.loads` or `shell=True`; Flask `debug=True` never used; no hard-coded `SECRET_KEY`; templates never use `\|safe` or disable auto-escaping; every POST form has a CSRF token; every non-public route has `login_required` or `admin_required`; every `/admin` route has `admin_required`; service methods re-check the admin role; templates contain no inline `<script>`, `style=` or `on…=` handlers (needed for the strict CSP); `set_rate` checks for arbitrage, and `convert`/`transfer` suspend cross-currency moves while a loop exists. |
| `unit` | Runs `test.py` in a subprocess and reports a pass/fail line for each test group |
| `e2e` | Starts the **real server** on a free port with a temporary rates DB, then acts like a browser (cookies + CSRF): admin creates users and changes a rate; a user credits all 3 currencies, debits, hits the overdraft guard and transfers USD→INR; the recipient sees the converted amount; the conversion advisor recommends USD → EUR → INR after the admin's rate change and the user converts along it; a rate that would create arbitrage is rejected; admin force-deletes a funded account and that user's session ends. It then **restarts the server** and checks that the rate change and its history persisted while the in-memory accounts are gone. |
| `security` | Black-box probes against the live server: security headers, server banner, anonymous access, Werkzeug debug console, missing CSRF tokens (login, credit/debit, convert), SQL injection payloads, script injection via advisor query parameters, stored XSS, privilege escalation (user → admin endpoints), out-of-range amounts and unsupported currencies, spending money you do not have, brute-force lock-out, `HttpOnly` cookie |
| `scanners` | Runs `bandit` (static security analysis) and `pip-audit` (known CVEs in dependencies) if they are installed. Otherwise the stage is marked SKIP. If pip-audit cannot reach its vulnerability database, it reports WARN rather than FAIL. |

Each check reports **PASS**, **FAIL**, **WARN** or **SKIP**. A failing stage does
not stop the other stages. The run ends with a summary table and writes
`reports/orchestrator_report.json`. The exit code is `0` only if nothing failed,
so you can use the orchestrator directly as a CI step.

### 5.3 Testing it yourself by hand

1. Start the server with `LEDGER_ADMIN_PASSWORD=Admin12345 python app.py --demo`.
2. Log in as `alice` / `password123`. Credit `100` USD, then debit `5000` USD and
   confirm the *Insufficient USD funds* error.
3. Transfer `10` USD to `bob`, receiving in INR. The message shows the converted
   amount and the rate.
4. Log out and log in as `bob`. The INR balance has increased, and the history
   shows **TRANSFER IN**.
5. While logged in as `bob`, open `http://127.0.0.1:5000/admin`. You get **403 Forbidden**.
6. Log in as `admin`. Change USD→INR to `82` and repeat step 3 to see the new rate
   applied. Then try `90`: it is **rejected**, because USD→INR→USD would return
   more than you started with. The error shows the maximum safe value.
7. Open *Conversion advisor* and compare USD → INR. After your change to 82,
   routing via EUR pays more, and the network diagram highlights USD → EUR → INR.
8. Stop the server (Ctrl+C) and start it again. The USD→INR rate is still `82`, but
   `alice` and `bob` are gone (re-run with `--demo` to recreate them).
9. Enter the wrong password for a user 5 times. The 6th attempt, even with the
   right password, reports that the account is locked.
10. Try a memo such as `<script>alert(1)</script>`. It is displayed as plain text
   and never executed.

---

## 6. Design notes

- **Why integer minor units?** Storing `amount_minor` as an INTEGER lets the
  database do exact arithmetic and enforce `CHECK (amount_minor >= 0)`, so a
  negative balance is impossible even if application code had a bug.
- **Atomic transfers.** The balance check, the debit, the credit and the history
  row all run inside one `BEGIN IMMEDIATE … COMMIT` transaction, guarded by a
  re-entrant lock. A failure at any point rolls back everything.
- **Directional rates.** USD→EUR and EUR→USD are stored separately, as real FX
  quotes are (bid/ask). The admin can set each of the 6 pairs independently.
  Transfers within the same currency always use a rate of 1.
- **How the advisor finds the best route.** It enumerates every simple path from
  the source to the target currency (direct, then through each other currency) and
  simulates each one **with rounding to the cent at every hop**. Routes are ranked
  by the amount received; on a tie, fewer hops wins. The executed conversion uses
  exactly the simulated numbers inside one database transaction, so what you see
  is what you get.
- **Why the arbitrage guardrail matters.** "Pick the best route" is only safe if
  no loop of rates multiplies to more than 1. Otherwise a user could convert in a
  circle and create money. So rate updates are checked against every loop through
  the edited pair, and the error explains the largest safe value. Without
  arbitrage, an indirect route can still win, but only when the direct quote has a
  wider spread than the two legs. That is realistic for thinly traded pairs, which
  is why the default EUR→INR rate (89.8) sits a little below EUR→USD→INR
  (1.086 × 83 ≈ 90.14).
- **Default-rate upgrade.** Earlier versions seeded EUR→USD = 1.087, which formed a
  tiny loop (USD→INR→EUR→USD ≈ ×1.00019), and a tighter EUR→INR = 90.2. On
  start-up those two seeds are upgraded, but only if they still carry the system's
  original values. Rates edited by an admin are never touched.
- **Admin bootstrap.** Because accounts are in memory, the first administrator is
  re-created at every start from `LEDGER_ADMIN_USERNAME` / `LEDGER_ADMIN_PASSWORD`.
  If no password is given, a random one is generated, so there is never a
  well-known default password.
