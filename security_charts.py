"""Plotly charts for the /security dashboard. Inline divs, no Flask."""

from datetime import datetime

import plotly.graph_objects as go

from chart_theme import SEV, base_layout, axis, to_div
from security_logger import get_summary, hourly_counts

SEV_COLORS = {"CRITICAL": SEV["Critical"], "WARN": SEV["High"], "INFO": SEV["Low"]}


def timeline_chart():
    """Events per hour, last 24h, one line per severity."""
    data = hourly_counts(24)
    if not any(any(v) for v in data["series"].values()):
        return ""
    x = [datetime.fromisoformat(h) for h in data["hours"]]
    fig = go.Figure()
    for sev in ("INFO", "WARN", "CRITICAL"):
        fig.add_trace(go.Scatter(
            x=x, y=data["series"][sev], mode="lines+markers", name=sev,
            line=dict(color=SEV_COLORS[sev], width=2), marker=dict(size=4),
            hovertemplate=f"{sev}: %{{y}}<extra></extra>",
        ))
    fig.update_layout(**base_layout(
        height=300, hovermode="x unified",
        xaxis=axis(showgrid=False, tickformat="%H:%M"),
        yaxis=axis(rangemode="tozero", dtick=1),
        legend=dict(orientation="h", y=1.14, x=0),
    ))
    return to_div(fig, 300)


def type_breakdown_chart():
    """Count per event type, all time, sorted descending."""
    by_type = get_summary()["all_time"]["by_type"]
    if not by_type:
        return ""
    items = sorted(by_type.items(), key=lambda kv: kv[1])  # plotly draws bottom-up
    height = max(180, 40 * len(items) + 48)
    fig = go.Figure(go.Bar(
        x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
        marker=dict(color="#1B3A8C", opacity=0.85),
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(**base_layout(
        height=height, margin=dict(l=150, r=8, t=8, b=32), bargap=0.55,
        xaxis=axis(rangemode="tozero", dtick=1),
        yaxis=axis(showgrid=False),
    ))
    return to_div(fig, height)
