"""Run the Ledger web application.

    python app.py                 # http://127.0.0.1:5000
    python app.py --demo          # also seed demo users alice / bob
    python app.py --port 8080 --rates-db /tmp/rates.db
"""

from __future__ import annotations

import argparse

from werkzeug.serving import WSGIRequestHandler

from ledger import create_app
from ledger.services import LedgerService

# Documented demo credential, only used with --demo.
DEMO_PASSWORD = "password123"  # nosec B105


def seed_demo(service: LedgerService, admin_username: str) -> None:
    admin = service.get_account_by_username(admin_username)
    for username, name, funds in [
        ("alice", "Alice Smith", {"USD": "1000", "EUR": "500", "INR": "25000"}),
        ("bob", "Bob Kumar", {"USD": "200", "EUR": "100", "INR": "10000"}),
    ]:
        user = service.create_account(admin, username, name, DEMO_PASSWORD)
        for currency, amount in funds.items():
            service.credit(user, currency, amount, "Opening balance")
    print(f" * Demo users: alice / bob  (password: {DEMO_PASSWORD})", flush=True)
    print(f" * Admin login page: /admin/login  (username: {admin_username})", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ledger web application")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--rates-db", help="path of the persistent exchange-rate database")
    parser.add_argument("--demo", action="store_true", help="seed demo users alice and bob")
    args = parser.parse_args()

    config: dict = {"DEMO": args.demo}
    if args.rates_db:
        config["RATES_DB"] = args.rates_db
    app = create_app(config)
    if args.demo:
        seed_demo(app.extensions["ledger"], app.config["ADMIN_USERNAME"])
    # Do not advertise server software/version in the Server header.
    WSGIRequestHandler.server_version = "Ledger"
    WSGIRequestHandler.sys_version = ""
    # Never enable the Werkzeug debugger: it allows arbitrary code execution.
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
