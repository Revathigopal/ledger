"""Geometry for the conversion-advisor graphics.

The charts are rendered server-side as SVG by Jinja (no client-side charting
library and no inline script/style, so the strict Content-Security-Policy
stays intact). This module only computes coordinates and labels; colours come
from CSS classes in ``static/style.css`` so light and dark mode both work.
"""

from __future__ import annotations

import math
from decimal import Decimal

from . import advisor
from .guardrails import CURRENCIES

# ----------------------------------------------------------------- formatting

def fmt_rate(rate: Decimal) -> str:
    """0.920000 -> '0.92', 83.000000 -> '83'."""
    text = f"{rate.normalize():f}"
    return text


def fmt_signed(value: Decimal, places: str = "0.01") -> str:
    q = value.quantize(Decimal(places))
    return f"+{q:,}" if q > 0 else f"{q:,}"


# --------------------------------------------------------------- route network
NET_W, NET_H = 560, 330
NODE_R = 38


def network(plan: advisor.Plan, rates: advisor.RateTable) -> dict:
    """Directed graph of all currencies; the recommended route is highlighted."""
    # triangle spans cy-70 .. cy+140; centre that span vertically
    cx, radius = NET_W / 2, 140
    cy = (NET_H - 210) / 2 + 70
    n = len(CURRENCIES)
    pos = {}
    for i, c in enumerate(CURRENCIES):
        angle = math.radians(-150 + i * 360 / n)
        pos[c] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))

    best_legs = list(zip(plan.best.path, plan.best.path[1:]))
    direct_leg = (plan.source, plan.target)
    edges = []
    for base in CURRENCIES:
        for quote in CURRENCIES:
            if base == quote:
                continue
            (ax, ay), (bx, by) = pos[base], pos[quote]
            dx, dy = bx - ax, by - ay
            length = math.hypot(dx, dy)
            ux, uy = dx / length, dy / length
            nx, ny = -uy, ux  # perpendicular: each direction sits on its own side
            off = 10
            x1, y1 = ax + ux * (NODE_R + 6) + nx * off, ay + uy * (NODE_R + 6) + ny * off
            x2, y2 = bx - ux * (NODE_R + 14) + nx * off, by - uy * (NODE_R + 14) + ny * off
            mx, my = (ax + bx) / 2 + nx * 30, (ay + by) / 2 + ny * 30
            leg = (base, quote)
            if leg in best_legs:
                state, step = "best", best_legs.index(leg) + 1
            elif leg == direct_leg:
                state, step = "direct", None
            else:
                state, step = "muted", None
            rate = advisor.rate_of(rates, base, quote)
            edges.append({
                "base": base, "quote": quote, "state": state, "step": step,
                "x1": round(x1, 1), "y1": round(y1, 1), "x2": round(x2, 1), "y2": round(y2, 1),
                "lx": round(mx, 1), "ly": round(my, 1),
                "label": fmt_rate(rate),
                "tip": f"{base} → {quote}: 1 {base} = {fmt_rate(rate)} {quote}"
                       + (f" · step {step} of the recommended route" if step else "")
                       + (" · direct route" if state == "direct" else ""),
            })
    # draw muted first so highlighted edges sit on top
    edges.sort(key=lambda e: {"muted": 0, "direct": 1, "best": 2}[e["state"]])
    on_route = set(plan.best.path)
    nodes = [{
        "code": c, "x": round(x, 1), "y": round(y, 1),
        "role": "source" if c == plan.source else "target" if c == plan.target
        else "via" if c in on_route else "idle",
    } for c, (x, y) in pos.items()]
    return {"w": NET_W, "h": NET_H, "r": NODE_R, "nodes": nodes, "edges": edges}


# ---------------------------------------------------- gain-vs-direct bar chart
BAR_W, ROW_H, BAR_H = 520, 48, 20
LABEL_W, VALUE_W = 150, 140


def _bar_path(x0: float, x1: float, y: float, h: float) -> str:
    """Bar from the baseline x0 to x1 with a 4px rounded data-end, square at the baseline."""
    r = min(4.0, abs(x1 - x0), h / 2)
    if x1 >= x0:
        return (f"M{x0:.1f},{y:.1f} H{x1 - r:.1f} Q{x1:.1f},{y:.1f} {x1:.1f},{y + r:.1f} "
                f"V{y + h - r:.1f} Q{x1:.1f},{y + h:.1f} {x1 - r:.1f},{y + h:.1f} H{x0:.1f} Z")
    return (f"M{x0:.1f},{y:.1f} H{x1 + r:.1f} Q{x1:.1f},{y:.1f} {x1:.1f},{y + r:.1f} "
            f"V{y + h - r:.1f} Q{x1:.1f},{y + h:.1f} {x1 + r:.1f},{y + h:.1f} H{x0:.1f} Z")


def gain_bars(plan: advisor.Plan) -> dict:
    """Diverging bars: how much more (or less) each route pays than converting directly."""
    plot_x0, plot_x1 = LABEL_W, BAR_W - VALUE_W
    zero = (plot_x0 + plot_x1) / 2
    half = (plot_x1 - plot_x0) / 2 - 4
    biggest = max((abs(r.vs_direct) for r in plan.routes), default=Decimal(0)) or Decimal(1)
    rows = []
    for i, r in enumerate(plan.routes):
        y = 22 + i * ROW_H
        width = float(abs(r.vs_direct) / biggest) * half
        x1 = zero + width if r.vs_direct >= 0 else zero - width
        kind = "better" if r.vs_direct > 0 else "worse" if r.vs_direct < 0 else "same"
        value = ("baseline" if r.is_direct else
                 f"{fmt_signed(r.vs_direct)} {plan.target} ({fmt_signed(r.vs_direct_pct, '0.001')}%)")
        rows.append({
            "label": r.label, "best": i == 0, "kind": kind,
            "y": y, "bar_y": y + (ROW_H - BAR_H) / 2 - 6, "text_y": y + ROW_H / 2 - 2,
            "path": _bar_path(zero, x1, y + (ROW_H - BAR_H) / 2 - 6, BAR_H) if width >= 1 else None,
            "value": value,
            "tip": f"{r.label}: receive {r.received:,} {plan.target} "
                   f"(effective rate {fmt_rate(r.effective_rate)})"
                   + ("" if r.is_direct else f", {value} vs direct"),
        })
    height = 22 + len(rows) * ROW_H + 8
    return {"w": BAR_W, "h": height, "zero": zero, "rows": rows, "label_w": LABEL_W,
            "value_x": plot_x1 + 8, "target": plan.target}


# ------------------------------------------------------------ savings heatmap
_BINS = [  # (upper bound in %, css class, legend label)
    (Decimal("0"), "h0", "none (direct is best)"),
    (Decimal("0.05"), "h1", "up to 0.05%"),
    (Decimal("0.2"), "h2", "0.05 – 0.2%"),
    (Decimal("0.5"), "h3", "0.2 – 0.5%"),
    (None, "h4", "over 0.5%"),
]


def heatmap(rates: advisor.RateTable, selected: tuple[str, str] | None = None) -> dict:
    """For every currency pair: how much better the best route is than direct (rates only)."""
    rows = []
    for base in CURRENCIES:
        cells = []
        for quote in CURRENCIES:
            if base == quote:
                cells.append({"diag": True})
                continue
            path, factor = advisor.best_factor(rates, base, quote)
            direct = advisor.rate_of(rates, base, quote)
            pct = ((factor / direct - 1) * 100).quantize(Decimal("0.001"))
            cls = next(c for bound, c, _ in _BINS if bound is None or pct <= bound)
            via = " → ".join(path[1:-1])
            cells.append({
                "diag": False, "base": base, "quote": quote, "cls": cls,
                "pct": f"+{pct}%" if pct > 0 else "0%",
                "via": f"via {via}" if len(path) > 2 else "direct",
                "selected": selected == (base, quote),
                "tip": f"{base} → {quote}: best route {' → '.join(path)}"
                       + (f", {pct}% more than direct" if pct > 0 else ", direct is best"),
            })
        rows.append({"base": base, "cells": cells})
    return {"rows": rows, "currencies": CURRENCIES,
            "legend": [{"cls": c, "label": label} for _, c, label in _BINS]}
