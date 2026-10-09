"""Risk velocity — snapshots across time + score trends. No AI, no Flask."""

import json
import os
import re

from risk_engine import analyze_risks


def data_dir():
    d = os.getenv("RISK_DATA_DIR") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data"
    )
    os.makedirs(d, exist_ok=True)
    return d


def slug(name):
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", (name or "").strip()).strip("_")
    return s or "project"


def _path(project):
    return os.path.join(data_dir(), slug(project) + ".snapshots.json")


def list_snapshots(project):
    p = _path(project)
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f).get("snapshots", [])


def save_snapshot(project, label, snapshot_date, risks, currency="$"):
    """Append a time point. Raises ValueError on bad label/risks/duplicates."""
    label = (label or "").strip()
    if not label:
        raise ValueError("snapshot needs a label, e.g. 'Week 1'")
    if not isinstance(risks, list) or not risks:
        raise ValueError("snapshot needs at least one risk")
    snaps = list_snapshots(project)
    if any(s["label"] == label for s in snaps):
        raise ValueError(f"snapshot {label!r} already exists — pick another label")
    # validates risks (raises on bad P/I, missing fields, dup ids)
    analyze_risks(project, "", snapshot_date or "", risks, currency=currency)
    snaps.append(
        {
            "label": label,
            "date": snapshot_date or "",
            "currency": currency or "$",
            "risks": risks,
        }
    )
    with open(_path(project), "w", encoding="utf-8") as f:
        json.dump({"project_name": project, "snapshots": snaps}, f, indent=2)
    return snaps


def compute_trends(project):
    """Per-risk score series across snapshots + status. Pure from stored data."""
    snaps = list_snapshots(project)
    scored = []
    for s in snaps:
        a = analyze_risks(
            project, "", s.get("date", ""), s["risks"],
            currency=s.get("currency", "$"),
        )
        scored.append((s["label"], {r["id"]: r for r in a["risks"]}))
    ids = []
    for _, m in scored:
        for rid in m:
            if rid not in ids:
                ids.append(rid)
    n = len(snaps)
    trends = []
    for rid in sorted(ids):
        pts = []
        for label, m in scored:
            r = m.get(rid)
            pts.append(
                {
                    "label": label,
                    "score": r["score"],
                    "probability": r["probability"],
                    "impact": r["impact"],
                    "severity": r["severity"],
                    "title": r["title"],
                }
                if r
                else None
            )
        present = [(i, p) for i, p in enumerate(pts) if p]
        if n <= 1:
            status = "Stable"
        elif len(present) == 1:
            status = "New" if present[0][0] == n - 1 else "Closed"
        elif present[-1][0] < n - 1:
            status = "Closed"
        elif present[0][0] > 0:
            status = "New"
        else:
            d = present[-1][1]["score"] - present[0][1]["score"]
            status = "Worsened" if d > 0 else ("Improved" if d < 0 else "Stable")
        trends.append(
            {
                "id": rid,
                "title": present[0][1]["title"],
                "points": pts,
                "first_score": present[0][1]["score"],
                "last_score": present[-1][1]["score"],
                "delta": present[-1][1]["score"] - present[0][1]["score"],
                "status": status,
                "color": present[-1][1].get("color", "#6B7280"),
            }
        )
    trends.sort(key=lambda t: (-t["delta"], t["id"]))
    return {
        "project": project,
        "labels": [s["label"] for s in snaps],
        "snapshots": snaps,
        "trends": trends,
    }


def trend_chart(project):
    """Plotly multi-line score-over-time chart, inline HTML div."""
    from plotly.offline import plot
    import plotly.graph_objects as go

    data = compute_trends(project)
    fig = go.Figure()
    for t in data["trends"]:
        fig.add_trace(
            go.Scatter(
                x=data["labels"],
                y=[p["score"] if p else None for p in t["points"]],
                mode="lines+markers",
                name=f"{t['id']} ({t['status']})",
                line=dict(color=t["color"], width=2.5),
                marker=dict(size=8),
                hovertemplate=[
                    (
                        f"<b>{t['id']}</b> — {p['title']}<br>"
                        f"{lbl}: score {p['score']} ({p['severity']}, "
                        f"P={p['probability']} I={p['impact']})<extra></extra>"
                    )
                    if p
                    else f"<b>{t['id']}</b> — not logged<extra></extra>"
                    for p, lbl in zip(t["points"], data["labels"])
                ],
                connectgaps=False,
            )
        )
    fig.update_layout(
        title=f"{project} — Risk Velocity",
        xaxis=dict(title="Time point"),
        yaxis=dict(title="Risk score", range=[0, 26]),
        margin=dict(l=60, r=20, t=60, b=60),
        plot_bgcolor="white",
        paper_bgcolor="white",
        legend=dict(orientation="h", y=-0.25, x=0),
    )
    return plot(fig, output_type="div", include_plotlyjs=False)
