"""Conversion advisor: route optimisation and arbitrage detection.

Pure functions over a rate table ``{(base, quote): Decimal}`` - no database
access - so the maths is easy to test and is shared by the service layer
(which executes routes) and the GUI (which charts them).

A *route* converts money hop by hop, e.g. USD -> EUR -> INR. Every hop is
rounded to minor units exactly as a real execution would be, so the advisor
never recommends a route on the strength of fractions of a cent that would
not actually be paid out.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, Decimal
from itertools import permutations

from .guardrails import CURRENCIES, Currency, ValidationError, from_minor

type RateTable = Mapping[tuple[str, str], Decimal]

ONE = Decimal(1)


@dataclass(frozen=True, slots=True)
class Route:
    path: tuple[Currency, ...]
    rates: tuple[Decimal, ...]          # one per hop
    hop_minor: tuple[int, ...]          # amount after each step, starting with the input
    sent: Decimal
    received: Decimal
    vs_direct: Decimal = Decimal(0)     # received - direct.received (in target currency)
    vs_direct_pct: Decimal = Decimal(0)

    @property
    def hops(self) -> int:
        return len(self.path) - 1

    @property
    def is_direct(self) -> bool:
        return self.hops == 1

    @property
    def effective_rate(self) -> Decimal:
        return (self.received / self.sent).quantize(Decimal("0.000001"))

    @property
    def label(self) -> str:
        return " → ".join(self.path)

    @property
    def code(self) -> str:
        """Compact form stored in the transactions table, e.g. ``USD>EUR>INR``."""
        return ">".join(self.path)


@dataclass(frozen=True, slots=True)
class Plan:
    source: Currency
    target: Currency
    amount: Decimal
    routes: tuple[Route, ...]           # best first

    @property
    def best(self) -> Route:
        return self.routes[0]

    @property
    def direct(self) -> Route:
        return next(r for r in self.routes if r.is_direct)

    @property
    def improves_on_direct(self) -> bool:
        return not self.best.is_direct and self.best.received > self.direct.received


@dataclass(frozen=True, slots=True)
class ArbitrageLoop:
    path: tuple[Currency, ...]          # starts and ends with the same currency
    factor: Decimal                     # product of rates, > 1

    @property
    def label(self) -> str:
        return " → ".join(self.path)


def rate_of(rates: RateTable, base: str, quote: str) -> Decimal:
    return ONE if base == quote else rates[(base, quote)]


def candidate_paths(source: Currency, target: Currency) -> Iterator[tuple[Currency, ...]]:
    """All simple paths source -> ... -> target (direct first)."""
    others = [c for c in CURRENCIES if c not in (source, target)]
    for k in range(len(others) + 1):
        for middle in permutations(others, k):
            yield (source, *middle, target)


def simulate(rates: RateTable, path: tuple[Currency, ...], minor: int) -> Route:
    amounts = [minor]
    hop_rates = []
    for base, quote in zip(path, path[1:]):
        r = rate_of(rates, base, quote)
        hop_rates.append(r)
        amounts.append(int((Decimal(amounts[-1]) * r).quantize(ONE, rounding=ROUND_HALF_EVEN)))
    return Route(path, tuple(hop_rates), tuple(amounts), from_minor(minor), from_minor(amounts[-1]))


def plan(rates: RateTable, source: Currency, target: Currency, minor: int) -> Plan:
    if source == target:
        raise ValidationError("Choose two different currencies to compare conversion routes.")
    routes = [simulate(rates, p, minor) for p in candidate_paths(source, target)]
    direct = next(r for r in routes if r.is_direct)
    enriched = []
    for r in routes:
        diff = r.received - direct.received
        pct = (diff / direct.received * 100).quantize(Decimal("0.0001")) if direct.received else Decimal(0)
        enriched.append(Route(r.path, r.rates, r.hop_minor, r.sent, r.received, diff, pct))
    # Most money received wins; ties go to the route with fewer hops (simpler, fewer roundings).
    enriched.sort(key=lambda r: (-r.received, r.hops))
    return Plan(source, target, from_minor(minor), tuple(enriched))


def path_factor(rates: RateTable, path: tuple[Currency, ...]) -> Decimal:
    factor = ONE
    for base, quote in zip(path, path[1:]):
        factor *= rate_of(rates, base, quote)
    return factor


def best_factor(rates: RateTable, source: Currency, target: Currency) -> tuple[tuple[Currency, ...], Decimal]:
    """Best route ignoring rounding: (path, product of rates)."""
    return max(
        ((p, path_factor(rates, p)) for p in candidate_paths(source, target)),
        key=lambda pf: (pf[1], -len(pf[0])),
    )


def cycles() -> Iterator[tuple[Currency, ...]]:
    """Every simple cycle of length >= 2, each listed once (rotations removed)."""
    order = {c: i for i, c in enumerate(CURRENCIES)}
    for k in range(2, len(CURRENCIES) + 1):
        for combo in permutations(CURRENCIES, k):
            if min(combo, key=order.get) == combo[0]:  # canonical rotation
                yield (*combo, combo[0])


def arbitrage_loops(rates: RateTable) -> list[ArbitrageLoop]:
    """Loops whose rate product exceeds 1, i.e. risk-free profit (money creation)."""
    loops = [ArbitrageLoop(c, path_factor(rates, c)) for c in cycles()]
    return sorted((lp for lp in loops if lp.factor > ONE), key=lambda lp: -lp.factor)


def max_safe_rate(rates: RateTable, base: Currency, quote: Currency) -> Decimal:
    """Largest value for base->quote that keeps every loop through that edge at <= 1."""
    limit: Decimal | None = None
    for c in cycles():
        legs = list(zip(c, c[1:]))
        if (base, quote) not in legs:
            continue
        # Rotate so the edge comes first, then multiply the remaining legs.
        i = legs.index((base, quote))
        rest = legs[i + 1:] + legs[:i]
        other = ONE
        for b, q in rest:
            other *= rate_of(rates, b, q)
        bound = ONE / other
        limit = bound if limit is None else min(limit, bound)
    if limit is None:  # pragma: no cover - every edge lies on at least one cycle
        raise ValueError(f"{base}->{quote} is not part of any cycle")
    return limit.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
