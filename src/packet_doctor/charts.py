"""Small inline-SVG charts (no JavaScript libraries, so the report stays one file).

Colours come from CSS custom properties defined in the report template, so the
charts follow light/dark mode. Every mark carries a ``data-tip`` attribute that
the report's tooltip script shows on hover/focus.
"""
from __future__ import annotations

from html import escape


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    import math
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def _fmt_rate(bps: float) -> str:
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} Gbit/s"
    if bps >= 1e6:
        return f"{bps / 1e6:.2f} Mbit/s"
    if bps >= 1e3:
        return f"{bps / 1e3:.1f} kbit/s"
    return f"{bps:.0f} bit/s"


def throughput_chart(timeline: dict, events: list, width: int = 900, height: int = 260) -> str:
    """Line+area of throughput over time, with problem events as ticks underneath.

    ``events``: list of (time_s, severity, label).
    """
    pts = timeline.get("points", [])
    if not pts:
        return '<p class="muted">No traffic to chart.</p>'
    bucket = timeline.get("bucket_s", 1)
    left, right, top = 84, 12, 12
    ev_h = 34 if events else 0
    plot_h = height - top - 28 - ev_h
    t_max = max(pts[-1][0] + bucket, 1)
    y_max = _nice_max(max(v for _, v in pts))
    pw = width - left - right

    def x(t):
        return left + pw * t / t_max

    def y(v):
        return top + plot_h * (1 - v / y_max)

    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="Throughput over time, peak {_fmt_rate(max(v for _, v in pts))}">']
    for i in range(5):                                   # recessive grid
        v = y_max * i / 4
        yy = y(v)
        out.append(f'<line x1="{left}" x2="{width - right}" y1="{yy:.1f}" y2="{yy:.1f}" class="grid"/>')
        out.append(f'<text x="{left - 6}" y="{yy + 4:.1f}" class="axis" text-anchor="end">{_fmt_rate(v)}</text>')
    for i in range(6):
        t = t_max * i / 5
        out.append(f'<text x="{x(t):.1f}" y="{top + plot_h + 16:.1f}" class="axis" text-anchor="{"end" if i == 5 else "start" if i == 0 else "middle"}">{_fmt_t(t, t_max)}</text>')
    line = " ".join(f"{x(t + bucket / 2):.1f},{y(v):.1f}" for t, v in pts)
    area = f"{x(pts[0][0] + bucket / 2):.1f},{y(0):.1f} {line} {x(pts[-1][0] + bucket / 2):.1f},{y(0):.1f}"
    out.append(f'<polygon points="{area}" class="area"/>')
    out.append(f'<polyline points="{line}" class="line"/>')
    # hit targets: one invisible column per bucket, bigger than the line itself
    bw = max(pw / max(len(pts), 1), 2)
    for t, v in pts:
        tip = escape(f"{_fmt_t(t, 1 if bucket < 0.1 else 10 if bucket < 1 else 100)}"
                     f" to {_fmt_t(t + bucket, 1 if bucket < 0.1 else 10 if bucket < 1 else 100)}: {_fmt_rate(v)}")
        out.append(f'<rect x="{x(t):.1f}" y="{top}" width="{bw:.1f}" height="{plot_h}" class="hit" '
                   f'data-tip="{tip}" tabindex="-1"/>')
    if events:
        ey = top + plot_h + 26
        out.append(f'<text x="{left - 6}" y="{ey + 9}" class="axis" text-anchor="end">events</text>')
        out.append(f'<line x1="{left}" x2="{width - right}" y1="{ey + 5}" y2="{ey + 5}" class="grid"/>')
        for t, sev, label in events[:400]:
            xx = x(min(max(t, 0), t_max))
            out.append(f'<rect x="{xx - 1.5:.1f}" y="{ey - 3}" width="3" height="16" rx="1.5" '
                       f'class="ev ev-{sev}" data-tip="{escape(f"t={t:.3f}s: {label}")}"/>')
    out.append("</svg>")
    return "".join(out)


def hbar_chart(rows: list, value_fmt=lambda v: f"{v:.1f}", width: int = 900, bar_h: int = 18,
               label_w: int = 260, unit: str = "", mark_threshold: float | None = None) -> str:
    """Horizontal bars, one series. ``rows``: list of (label, value, tooltip)."""
    if not rows:
        return '<p class="muted">Nothing to chart.</p>'
    gap = 8
    height = len(rows) * (bar_h + gap) + 24
    vmax = _nice_max(max(max(v for _, v, _ in rows), mark_threshold or 0))
    pw = width - label_w - 80
    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img">']
    if mark_threshold:
        tx = label_w + pw * mark_threshold / vmax
        out.append(f'<line x1="{tx:.1f}" x2="{tx:.1f}" y1="0" y2="{height - 20}" class="threshold"/>')
        out.append(f'<text x="{tx + 4:.1f}" y="{height - 6}" class="axis">threshold {value_fmt(mark_threshold)}{unit}</text>')
    for i, (label, v, tip) in enumerate(rows):
        yy = i * (bar_h + gap)
        w = max(pw * v / vmax, 2)
        lab = label if len(label) <= 38 else label[:36] + "…"
        out.append(f'<text x="{label_w - 8}" y="{yy + bar_h - 4}" class="label" text-anchor="end">{escape(lab)}</text>')
        # bar anchored at the baseline: square at the axis, 4px rounding at the data end
        out.append(f'<path d="M{label_w},{yy} h{max(w - 4, 0):.1f} q4,0 4,4 v{bar_h - 8} q0,4 -4,4 '
                   f'h-{max(w - 4, 0):.1f} z" class="bar" data-tip="{escape(tip)}"/>')
        out.append(f'<text x="{label_w + w + 6:.1f}" y="{yy + bar_h - 4}" class="value">{value_fmt(v)}{unit}</text>')
    out.append("</svg>")
    return "".join(out)


def _fmt_t(t: float, t_max: float) -> str:
    if t_max < 2:
        return f"{t:.2f}s"
    if t_max < 20:
        return f"{t:.1f}s"
    if t_max < 600:
        return f"{t:.0f}s"
    return f"{t / 60:.1f}min"
