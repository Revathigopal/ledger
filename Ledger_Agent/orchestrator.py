"""Test orchestrator for the Ledger application.

Runs a pipeline of verification stages, each guarded so that a failure in one
stage is reported but does not hide the results of the others:

  1. preflight     - interpreter version, dependencies, project layout
  2. guardrails    - static security/quality rules over the source (AST + templates)
  3. unit          - the full unittest suite in test.py (run in a subprocess)
  4. e2e           - starts the real server and drives every feature over HTTP,
                     then restarts it to prove rates persist and the ledger does not
  5. security      - black-box probes against the live server (CSRF, access control,
                     headers, SQL injection, XSS, brute force, debugger exposure)
  6. scanners      - optional third-party scanners (bandit, pip-audit) if installed

Usage:
    python orchestrator.py                    # all stages
    python orchestrator.py --stages unit e2e  # selected stages
    python orchestrator.py --list             # list stages

A JSON report is written to reports/orchestrator_report.json.
Exit code is 0 only if no stage failed.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable
SOURCE_FILES = [ROOT / "app.py", *sorted((ROOT / "ledger").glob("*.py"))]
TEMPLATES = sorted((ROOT / "ledger" / "templates").glob("*.html"))
ADMIN_PW = "OrchAdmin123"


# ------------------------------------------------------------------ reporting
@dataclass
class Check:
    name: str
    status: str  # PASS | FAIL | WARN | SKIP
    detail: str = ""


@dataclass
class StageResult:
    stage: str
    checks: list[Check] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def status(self) -> str:
        states = {c.status for c in self.checks}
        for s in ("FAIL", "WARN", "PASS"):
            if s in states:
                return s
        return "SKIP"


class Recorder:
    def __init__(self, result: StageResult) -> None:
        self.result = result

    def check(self, name: str, ok: bool, detail: str = "", *, warn_only: bool = False) -> bool:
        status = "PASS" if ok else ("WARN" if warn_only else "FAIL")
        self.result.checks.append(Check(name, status, detail))
        colour = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m"}[status]
        print(f"    {colour}{status:<4}\033[0m {name}" + (f"  - {detail}" if detail and not ok else ""))
        return ok

    def skip(self, name: str, detail: str) -> None:
        self.result.checks.append(Check(name, "SKIP", detail))
        print(f"    \033[90mSKIP\033[0m {name}  - {detail}")


# ------------------------------------------------------------- HTTP client
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib API
        return None


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str


class Browser:
    """Tiny cookie-aware HTTP client that understands the app's CSRF tokens."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect()
        )

    def request(self, method: str, path: str, data: dict | None = None, follow: bool = True) -> Response:
        url = urllib.parse.urljoin(self.base, path)
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method)
        try:
            with self.opener.open(req, timeout=10) as r:
                resp = Response(r.status, dict(r.headers), r.read().decode())
        except urllib.error.HTTPError as e:
            resp = Response(e.code, dict(e.headers), e.read().decode(errors="replace"))
        if follow and resp.status in (301, 302, 303) and "Location" in resp.headers:
            return self.request("GET", resp.headers["Location"], follow=True)
        return resp

    def get(self, path: str, follow: bool = True) -> Response:
        return self.request("GET", path, follow=follow)

    def csrf(self, path: str = "/") -> str:
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.get(path).body)
        return m.group(1) if m else ""

    def post(self, path: str, data: dict, follow: bool = True, csrf: bool = True) -> Response:
        if csrf:
            data = {**data, "csrf_token": self.csrf("/")}
        return self.request("POST", path, data, follow)

    def login(self, username: str, password: str) -> Response:
        token = self.csrf("/login")
        return self.request("POST", "/login",
                            {"username": username, "password": password, "csrf_token": token},
                            follow=False)

    @staticmethod
    def flashes(html: str) -> list[str]:
        return re.findall(r'class="flash [^"]*"[^>]*>([^<]*)<', html)

    @staticmethod
    def balance(html: str, currency: str) -> str | None:
        m = re.search(rf'id="balance-{currency}">\s*<div class="cur">{currency}</div>\s*'
                      r'<div class="amt">([^<]+)</div>', html)
        return m.group(1).replace(",", "") if m else None


class LiveServer:
    def __init__(self, rates_db: Path) -> None:
        self.rates_db = rates_db
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None
        self.log = tempfile.TemporaryFile()

    def __enter__(self) -> LiveServer:
        env = {**os.environ, "LEDGER_ADMIN_PASSWORD": ADMIN_PW, "LEDGER_ADMIN_USERNAME": "admin",
               "PYTHONUNBUFFERED": "1"}
        self.proc = subprocess.Popen(
            [PY, str(ROOT / "app.py"), "--port", str(self.port), "--rates-db", str(self.rates_db)],
            cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited early:\n{self.output()}")
            try:
                urllib.request.urlopen(self.base + "/login", timeout=1).close()
                return self
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("server did not start within 20s")

    def output(self) -> str:
        self.log.seek(0)
        return self.log.read().decode(errors="replace")

    def __exit__(self, *exc) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ===================================================================== stages
def stage_preflight(rec: Recorder, ctx: dict) -> None:
    rec.check("Python >= 3.12", sys.version_info >= (3, 12), sys.version.split()[0])
    rec.check("Flask installed", importlib.util.find_spec("flask") is not None,
              "pip install -r requirements.txt")
    for rel in ["app.py", "test.py", "requirements.txt", "README.md", "ledger/__init__.py",
                "ledger/db.py", "ledger/services.py", "ledger/guardrails.py",
                "ledger/security.py", "ledger/web.py", "ledger/advisor.py", "ledger/viz.py",
                "ledger/static/viz.js", "ledger/templates/advisor.html"]:
        rec.check(f"file exists: {rel}", (ROOT / rel).is_file())


_SQL_CALLS = {"execute", "executemany", "executescript", "query", "query_one"}


def stage_guardrails(rec: Recorder, ctx: dict) -> None:
    sql_violations, danger, secrets_, debug = [], [], [], []
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                # 1. SQL must be a constant string with ? placeholders
                if name in _SQL_CALLS and node.args:
                    sql = node.args[0]
                    if isinstance(sql, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(sql, ast.Call) and getattr(sql.func, "attr", "") == "format"
                    ):
                        sql_violations.append(f"{path.name}:{node.lineno}")
                # 2. dangerous primitives
                if name in {"eval", "exec", "system", "loads"} and (
                    name != "loads" or getattr(getattr(fn, "value", None), "id", "") == "pickle"
                ):
                    danger.append(f"{path.name}:{node.lineno} {name}()")
                if any(k.arg == "shell" and getattr(k.value, "value", False) is True
                       for k in node.keywords):
                    danger.append(f"{path.name}:{node.lineno} shell=True")
                # 3. debug server
                if name == "run" and any(k.arg == "debug" and getattr(k.value, "value", False) is True
                                         for k in node.keywords):
                    debug.append(f"{path.name}:{node.lineno}")
                # 4. hard-coded secret key
                for k in node.keywords:
                    if k.arg == "SECRET_KEY" and isinstance(k.value, ast.Constant):
                        secrets_.append(f"{path.name}:{node.lineno}")
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if (isinstance(t, ast.Subscript) and getattr(t.slice, "value", None) == "SECRET_KEY"
                            and isinstance(node.value, ast.Constant)):
                        secrets_.append(f"{path.name}:{node.lineno}")
    rec.check("SQL uses parameterised constant strings only", not sql_violations, ", ".join(sql_violations))
    rec.check("no eval/exec/os.system/pickle/shell=True", not danger, ", ".join(danger))
    rec.check("Flask debugger never enabled", not debug, ", ".join(debug))
    rec.check("no hard-coded SECRET_KEY", not secrets_, ", ".join(secrets_))

    # Templates: autoescape must stay on and every POST form carries a CSRF token.
    unsafe, missing_csrf = [], []
    for tpl in TEMPLATES:
        text = tpl.read_text()
        if re.search(r"\|\s*safe\b|autoescape\s+false|Markup\(", text):
            unsafe.append(tpl.name)
        for form in re.findall(r"<form[^>]*method=\"post\".*?</form>", text, re.S | re.I):
            if "csrf_token()" not in form:
                missing_csrf.append(tpl.name)
    rec.check("templates never disable auto-escaping", not unsafe, ", ".join(unsafe))
    inline = [t.name for t in TEMPLATES
              if re.search(r"<script(?![^>]*\bsrc=)[^>]*>|\sstyle=\"|\son[a-z]+=\"", t.read_text())]
    rec.check("templates CSP-safe (no inline script/style/event handlers)", not inline, ", ".join(inline))
    rec.check("every POST form includes a CSRF token", not missing_csrf, ", ".join(missing_csrf))

    # Routes: every view except the public ones needs an auth decorator;
    # every /admin route needs admin_required.
    public = {"index", "login", "admin_login", "logout"}
    tree = ast.parse((ROOT / "ledger" / "web.py").read_text())
    unprotected, weak_admin = [], []
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        decos = [ast.unparse(d) for d in fn.decorator_list]
        route = next((d for d in decos if d.startswith("bp.")), None)
        if route is None:
            continue
        has_login = any(d in {"login_required", "admin_required"} for d in decos)
        if fn.name not in public and not has_login:
            unprotected.append(fn.name)
        if "'/admin" in route and fn.name not in public and "admin_required" not in decos:
            weak_admin.append(fn.name)
    rec.check("all non-public routes require login", not unprotected, ", ".join(unprotected))
    rec.check("all /admin routes require admin role", not weak_admin, ", ".join(weak_admin))

    # The service layer must re-check roles (defence in depth).
    svc_src = (ROOT / "ledger" / "services.py").read_text()
    set_rate = re.search(r"def set_rate\(.*?(?=\n    def |\Z)", svc_src, re.S)
    rec.check("service.set_rate refuses rates that create arbitrage loops",
              bool(set_rate and "arbitrage_loops" in set_rate.group(0)))
    for method in ("convert", "transfer"):
        body = re.search(rf"def {method}\(.*?(?=\n    def |\Z)", svc_src, re.S)
        rec.check(f"service.{method} suspends cross-currency moves under arbitrage",
                  bool(body and "_ensure_no_arbitrage" in body.group(0)))
    for method in ("create_account", "delete_account", "set_rate", "list_accounts", "audit_log"):
        body = re.search(rf"def {method}\(.*?(?=\n    def |\Z)", svc_src, re.S)
        rec.check(f"service.{method} enforces admin role",
                  bool(body and "_require_admin(actor)" in body.group(0)))


def stage_unit(rec: Recorder, ctx: dict) -> None:
    proc = subprocess.run([PY, "-m", "unittest", "test", "-v"], cwd=ROOT,
                          capture_output=True, text=True, timeout=900)
    out = proc.stderr + proc.stdout
    ran = re.search(r"Ran (\d+) tests? in ([\d.]+)s", out)
    groups: dict[str, list[bool]] = {}
    for m in re.finditer(r"^(\w+) \(test\.(\w+)\.\w+\)(?:.*?)\.\.\. (ok|FAIL|ERROR)", out, re.M):
        groups.setdefault(m.group(2), []).append(m.group(3) == "ok")
    for group, results in groups.items():
        rec.check(f"{group} ({sum(results)}/{len(results)})", all(results))
    detail = f"{ran.group(1)} tests in {ran.group(2)}s" if ran else "no summary"
    if proc.returncode != 0:
        failures = re.findall(r"^(?:FAIL|ERROR): (.+)$", out, re.M)
        detail += "; failing: " + "; ".join(failures[:10])
    rec.check("unittest suite", proc.returncode == 0, detail)
    ctx["unit_output"] = out[-4000:]


def stage_e2e(rec: Recorder, ctx: dict) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ledger-e2e-"))
    rates_db = tmp / "rates.db"
    try:
        with LiveServer(rates_db) as srv:
            ctx["server_base"] = srv.base
            admin = Browser(srv.base)
            r = admin.login("admin", ADMIN_PW)
            rec.check("admin can log in", r.status == 302 and r.headers.get("Location", "").endswith("/admin"))

            for user, name in [("alice", "Alice E2E"), ("bob", "Bob E2E")]:
                r = admin.post("/admin/accounts", {"username": user, "full_name": name,
                                                   "password": "UserPass123", "role": "user"})
                rec.check(f"admin creates account '{user}'", any("created" in f for f in admin.flashes(r.body)),
                          str(admin.flashes(r.body)))
            r = admin.post("/admin/rates", {"base": "USD", "quote": "INR", "rate": "80"})
            rec.check("admin updates USD->INR rate to 80", "80.000000" in r.body)

            alice = Browser(srv.base)
            rec.check("alice logs in", alice.login("alice", "UserPass123").status == 302)
            for cur, amt in [("USD", "500"), ("EUR", "200"), ("INR", "10000")]:
                alice.post("/entry", {"kind": "credit", "currency": cur, "amount": amt})
            r = alice.post("/entry", {"kind": "debit", "currency": "EUR", "amount": "50.50"})
            html = alice.get("/dashboard").body
            rec.check("credit in USD/EUR/INR + debit EUR",
                      [alice.balance(html, c) for c in ("USD", "EUR", "INR")] == ["500.00", "149.50", "10000.00"],
                      str([alice.balance(html, c) for c in ("USD", "EUR", "INR")]))
            r = alice.post("/entry", {"kind": "debit", "currency": "USD", "amount": "999"})
            rec.check("overdraft rejected", any("Insufficient" in f for f in alice.flashes(r.body)))

            r = alice.post("/transfer", {"to_username": "bob", "from_currency": "USD",
                                         "to_currency": "INR", "amount": "10", "memo": "e2e"})
            rec.check("cross-currency transfer USD->INR", any("800.00 INR" in f for f in alice.flashes(r.body)),
                      str(alice.flashes(r.body)))

            bob = Browser(srv.base)
            bob.login("bob", "UserPass123")
            html = bob.get("/dashboard").body
            rec.check("recipient sees converted funds + history",
                      bob.balance(html, "INR") == "800.00" and "TRANSFER IN" in html)

            # ---- conversion advisor (graphical recommendation)
            # The admin lowered USD->INR to 80 above, so routing USD via EUR (0.92 x 89.8) now pays more.
            html = alice.get("/advisor?from=USD&to=INR&amount=100").body
            rec.check("advisor recommends USD → EUR → INR after the rate change, with charts",
                      "Convert via <strong>USD → EUR → INR</strong>" in html
                      and html.count('class="edge best"') == 2 and 'class="bar-row better is-best"' in html
                      and 'class="cell ' in html)
            r = alice.get("/static/viz.js")
            rec.check("chart tooltip script served", r.status == 200 and "data-tip" in r.body)
            r = alice.post("/convert", {"from": "USD", "to": "INR", "amount": "100", "route": "best"})
            rec.check("convert own USD→INR along recommended route (8,261.60 INR vs 8,000.00 direct)",
                      any("into 8261.60 INR via USD → EUR → INR" in f for f in alice.flashes(r.body)),
                      str(alice.flashes(r.body)))
            r = admin.post("/admin/rates", {"base": "EUR", "quote": "USD", "rate": "1.2"})
            rec.check("rate that would create arbitrage is rejected",
                      any("risk-free loop" in f for f in admin.flashes(r.body)))

            bob_id = re.search(r"<td>(\d+)</td><td>bob</td>", admin.get("/admin").body)
            r = admin.post(f"/admin/accounts/{bob_id.group(1)}/delete", {})
            rec.check("funded account needs force to delete", any("force" in f for f in admin.flashes(r.body)))
            r = admin.post(f"/admin/accounts/{bob_id.group(1)}/delete", {"force": "on"})
            rec.check("admin force-deletes account", any("deleted" in f for f in admin.flashes(r.body)))
            rec.check("deleted user's session ends", bob.get("/dashboard", follow=False).status == 302)

        # ---- restart: rates persist, ledger is in-memory
        with LiveServer(rates_db) as srv:
            admin = Browser(srv.base)
            admin.login("admin", ADMIN_PW)
            html = admin.get("/admin").body
            rec.check("after restart: rate table persisted (USD->INR = 80)",
                      bool(re.search(r"<td>USD</td><td>INR</td><td class=\"num\">80\.000000", html)))
            rec.check("after restart: rate history persisted", "80.000000" in html and "Rate history" in html)
            rec.check("after restart: in-memory accounts are gone",
                      Browser(srv.base).login("alice", "UserPass123").status == 401)
    except Exception as exc:  # report, don't crash the orchestrator
        rec.check("live e2e run", False, f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def stage_security(rec: Recorder, ctx: dict) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ledger-sec-"))
    try:
        with LiveServer(tmp / "rates.db") as srv:
            anon = Browser(srv.base)
            r = anon.get("/login")
            h = r.headers
            rec.check("CSP header present", "default-src 'self'" in h.get("Content-Security-Policy", ""))
            rec.check("clickjacking protection (X-Frame-Options)", h.get("X-Frame-Options") == "DENY")
            rec.check("MIME sniffing disabled", h.get("X-Content-Type-Options") == "nosniff")
            rec.check("Server banner hidden", "Werkzeug" not in h.get("Server", ""),
                      f"Server: {h.get('Server')} (use a production WSGI server/reverse proxy)",
                      warn_only=True)
            for path in ("/dashboard", "/admin", "/password"):
                rec.check(f"anonymous GET {path} redirected to login",
                          anon.get(path, follow=False).status == 302)
            rec.check("Werkzeug debug console not exposed", anon.get("/console").status == 404)

            r = anon.request("POST", "/login", {"username": "admin", "password": ADMIN_PW}, follow=False)
            rec.check("login without CSRF token rejected (400)", r.status == 400)

            for payload in ("' OR '1'='1' --", "admin'--", "admin\" OR \"\"=\""):
                r = Browser(srv.base).login(payload, payload)
                rec.check(f"SQL injection login rejected: {payload!r}", r.status == 401)

            admin = Browser(srv.base)
            admin.login("admin", ADMIN_PW)
            admin.post("/admin/accounts", {"username": "mallory", "full_name": "<img src=x onerror=alert(1)>",
                                           "password": "Mallory123"})
            admin.post("/admin/accounts", {"username": "victim", "full_name": "Victim",
                                           "password": "Victim1234"})
            rec.check("stored XSS in full name is escaped",
                      "<img src=x" not in admin.get("/admin").body)

            mallory = Browser(srv.base)
            mallory.login("mallory", "Mallory123")
            rec.check("user cannot open admin page (403)", mallory.get("/admin").status == 403)
            r = mallory.post("/admin/accounts", {"username": "evil", "full_name": "E",
                                                 "password": "Evil12345", "role": "admin"}, follow=False)
            rec.check("user cannot create accounts (403)", r.status == 403)
            r = mallory.post("/admin/rates", {"base": "USD", "quote": "INR", "rate": "999999"}, follow=False)
            rec.check("user cannot change rates (403)", r.status == 403)
            r = mallory.post("/admin/accounts/1/delete", {}, follow=False)
            rec.check("user cannot delete accounts (403)", r.status == 403)
            r = mallory.request("POST", "/entry", {"kind": "credit", "currency": "USD", "amount": "1000000"},
                                follow=False)
            rec.check("state change without CSRF token rejected (400)", r.status == 400)

            r = mallory.request("POST", "/convert", {"from": "USD", "to": "INR", "amount": "1"}, follow=False)
            rec.check("convert without CSRF token rejected (400)", r.status == 400)
            r = mallory.get("/advisor?from=USD&to=EUR&amount=%3Cscript%3Ealert(1)%3C/script%3E")
            rec.check("advisor input reflected safely", "<script>alert(1)" not in r.body)
            for amount in ("-100", "1e9", "NaN", "0.001", "99999999"):
                r = mallory.post("/entry", {"kind": "credit", "currency": "USD", "amount": amount})
                rec.check(f"guardrail rejects amount {amount!r}",
                          any("Amount" in f for f in mallory.flashes(r.body)) and
                          mallory.balance(r.body, "USD") == "0.00")
            r = mallory.post("/entry", {"kind": "credit", "currency": "BTC", "amount": "1"})
            rec.check("guardrail rejects unsupported currency", any("Unsupported" in f for f in mallory.flashes(r.body)))

            r = mallory.post("/transfer", {"to_username": "victim", "from_currency": "USD",
                                           "to_currency": "USD", "amount": "10"})
            rec.check("cannot transfer money you do not have", any("Insufficient" in f for f in mallory.flashes(r.body)))

            victim = Browser(srv.base)
            for _ in range(5):
                victim.login("victim", "wrong-guess1")
            r = victim.login("victim", "Victim1234")
            rec.check("brute force triggers account lock-out", r.status == 401 and "locked" in r.body)

            cookie = next((c for c in admin.jar), None)
            rec.check("session cookie is HttpOnly",
                      cookie is not None and cookie.has_nonstandard_attr("HttpOnly"))
    except Exception as exc:
        rec.check("live security run", False, f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def stage_scanners(rec: Recorder, ctx: dict) -> None:
    # bandit: static security analysis of our own code.
    # pip-audit: known CVEs in the installed dependencies (needs network access).
    for tool, args in [("bandit", ["-q", "-r", "ledger", "app.py"]), ("pip-audit", ["--progress-spinner", "off"])]:
        exe = shutil.which(tool) or (str(Path(PY).parent / tool) if (Path(PY).parent / tool).exists() else None)
        if not exe:
            rec.skip(tool, f"not installed (pip install {tool})")
            continue
        try:
            proc = subprocess.run([exe, *args], cwd=ROOT, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            rec.check(tool, False, "timed out", warn_only=True)
            continue
        out = (proc.stdout + proc.stderr).strip()
        if tool == "pip-audit" and proc.returncode != 0 and "known vulnerabilit" not in out:
            rec.check(tool, False, "could not complete (network?): " + out[-300:], warn_only=True)
            continue
        rec.check(tool, proc.returncode == 0, out[-500:])


STAGES: dict[str, Callable[[Recorder, dict], None]] = {
    "preflight": stage_preflight,
    "guardrails": stage_guardrails,
    "unit": stage_unit,
    "e2e": stage_e2e,
    "security": stage_security,
    "scanners": stage_scanners,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stages", nargs="+", choices=list(STAGES), default=list(STAGES))
    parser.add_argument("--list", action="store_true", help="list stages and exit")
    parser.add_argument("--report", default=str(ROOT / "reports" / "orchestrator_report.json"))
    args = parser.parse_args()
    if args.list:
        for name, fn in STAGES.items():
            print(f"{name:<11} {fn.__name__}")
        return 0

    ctx: dict = {}
    results: list[StageResult] = []
    for name in args.stages:
        print(f"\n\033[1m== Stage: {name}\033[0m")
        result = StageResult(name)
        start = time.monotonic()
        try:
            STAGES[name](Recorder(result), ctx)
        except Exception as exc:  # a crashing stage is a failing stage
            Recorder(result).check(f"{name} stage crashed", False, f"{type(exc).__name__}: {exc}")
        result.seconds = round(time.monotonic() - start, 2)
        results.append(result)

    print("\n\033[1m== Summary\033[0m")
    for r in results:
        counts = {s: sum(c.status == s for c in r.checks) for s in ("PASS", "FAIL", "WARN", "SKIP")}
        print(f"  {r.stage:<11} {r.status:<5} pass={counts['PASS']:<3} fail={counts['FAIL']:<3} "
              f"warn={counts['WARN']:<3} skip={counts['SKIP']:<3} ({r.seconds}s)")
    failed = any(r.status == "FAIL" for r in results)

    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python": sys.version.split()[0],
        "overall": "FAIL" if failed else "PASS",
        "stages": [{**asdict(r), "status": r.status} for r in results],
    }, indent=2))
    print(f"\nOverall: {'\033[31mFAIL' if failed else '\033[32mPASS'}\033[0m   report: {report}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
