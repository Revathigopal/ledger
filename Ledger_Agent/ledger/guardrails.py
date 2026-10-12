"""Input guardrails.

Every value that crosses the trust boundary (HTML form, CLI, test harness)
is validated here *before* it reaches the service layer or the database.
Each validator either returns a clean, typed value or raises ``ValidationError``.
"""

from __future__ import annotations

import re
import unicodedata
from decimal import Decimal, InvalidOperation
from enum import StrEnum


class Currency(StrEnum):
    USD = "USD"
    EUR = "EUR"
    INR = "INR"


CURRENCIES: tuple[Currency, ...] = tuple(Currency)

# --- limits -----------------------------------------------------------------
MINOR_UNITS = 100                              # 2 decimal places for all currencies
MAX_TRANSACTION = Decimal("1000000.00")        # per credit / debit / transfer
MAX_BALANCE = Decimal("1000000000.00")         # per currency, per account
MAX_RATE = Decimal("1000000")
RATE_PLACES = Decimal("0.000001")              # rates are stored with 6 dp
MAX_MEMO_LEN = 140
MAX_NAME_LEN = 80

_AMOUNT_RE = re.compile(r"^\d{1,13}(\.\d{1,2})?$")
_RATE_RE = re.compile(r"^\d{1,7}(\.\d{1,6})?$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class LedgerError(Exception):
    """Base class for all domain errors (safe to show to the user)."""


class ValidationError(LedgerError):
    pass


def _clean_text(raw: object) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ValidationError("Expected text input.")
    return raw.strip()


def parse_amount(raw: object) -> Decimal:
    """Positive money amount with at most 2 decimals and below MAX_TRANSACTION."""
    text = _clean_text(raw)
    if not _AMOUNT_RE.fullmatch(text):
        raise ValidationError("Amount must be a positive number with at most 2 decimal places.")
    try:
        value = Decimal(text)
    except InvalidOperation as exc:  # pragma: no cover - regex already guards this
        raise ValidationError("Invalid amount.") from exc
    if value <= 0:
        raise ValidationError("Amount must be greater than zero.")
    if value > MAX_TRANSACTION:
        raise ValidationError(f"Amount exceeds the per-transaction limit of {MAX_TRANSACTION:,}.")
    return value


def parse_currency(raw: object) -> Currency:
    text = _clean_text(raw).upper()
    try:
        return Currency(text)
    except ValueError as exc:
        allowed = ", ".join(CURRENCIES)
        raise ValidationError(f"Unsupported currency. Allowed: {allowed}.") from exc


def parse_rate(raw: object) -> Decimal:
    """Exchange rate: > 0, <= MAX_RATE, at most 6 decimal places."""
    text = _clean_text(raw)
    if not _RATE_RE.fullmatch(text):
        raise ValidationError("Rate must be a positive number with at most 6 decimal places.")
    value = Decimal(text)
    if value <= 0:
        raise ValidationError("Rate must be greater than zero.")
    if value > MAX_RATE:
        raise ValidationError(f"Rate must not exceed {MAX_RATE}.")
    return value.quantize(RATE_PLACES)


def validate_username(raw: object) -> str:
    text = _clean_text(raw)
    if not _USERNAME_RE.fullmatch(text):
        raise ValidationError(
            "Username must be 3-32 characters: letters, digits, '.', '_' or '-'."
        )
    return text.lower()


def validate_password(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValidationError("Password is required.")
    if not 8 <= len(raw) <= 128:
        raise ValidationError("Password must be 8-128 characters long.")
    if not (any(c.isalpha() for c in raw) and any(c.isdigit() for c in raw)):
        raise ValidationError("Password must contain at least one letter and one digit.")
    return raw


def validate_full_name(raw: object) -> str:
    text = _strip_control(_clean_text(raw))
    if not 1 <= len(text) <= MAX_NAME_LEN:
        raise ValidationError(f"Full name must be 1-{MAX_NAME_LEN} characters.")
    return text


def validate_memo(raw: object) -> str:
    text = _strip_control(_clean_text(raw))
    if len(text) > MAX_MEMO_LEN:
        raise ValidationError(f"Memo must be at most {MAX_MEMO_LEN} characters.")
    return text


def validate_role(raw: object) -> str:
    text = _clean_text(raw).lower() or "user"
    if text not in {"user", "admin"}:
        raise ValidationError("Role must be 'user' or 'admin'.")
    return text


def _strip_control(text: str) -> str:
    """Remove control / format characters (e.g. NUL, RTL overrides)."""
    return "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")


def to_minor(amount: Decimal) -> int:
    return int(amount * MINOR_UNITS)


def from_minor(minor: int) -> Decimal:
    return (Decimal(minor) / MINOR_UNITS).quantize(Decimal("0.01"))
