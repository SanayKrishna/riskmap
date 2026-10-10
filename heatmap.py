"""Plotly 5x5 risk heat map — no AI, no Flask."""

from plotly.offline import plot
import plotly.graph_objects as go

IMPACT_LABELS = ["Negligible", "Minor", "Moderate", "Major", "Catastrophic"]
PROB_LABELS = ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"]

# smooth green -> yellow -> orange -> red
CELL_COLORSCALE = [
    [0.0, "#F0FDF4"],
    [0.20, "#16A34A"],
    [0.28, "#FEF3C7"],
    [0.48, "#D97706"],
    [0.55, "#FFEDD5"],
    [0.72, "#EA580C"],
    [0.80, "#FEE2E2"],
    [1.0, "#DC2626"],
]


def _jitter_offsets(count):
    """Small offsets so markers sharing a cell don't fully overlap."""
    if count == 1:
        return [(0.0, 0.0)]
    step = 0.16
    # spread along x, alternate y slightly
    return [
        ((k - (count - 1) / 2) * step, 0.12 if k % 2 else -0.12)
        for k in range(count)
    ]


def generate_heatmap(analysis):
    """Build an interactive 5x5 heat map, return inline Plotly HTML div."""
    project_name = analysis.get("project_name", "Project")
    risks = analysis.get("risks", [])

    # background cell scores: z[row=prob][col=impact] = p * i
    z = [[p * i for i in range(1, 6)] for p in range(1, 6)]

    fig = go.Figure()

    fig.add_trace(
        go.Heatmap(
            z=z,
            x=[1, 2, 3, 4, 5],
            y=[1, 2, 3, 4, 5],
            colorscale=CELL_COLORSCALE,
            zmin=1,
            zmax=25,
            showscale=False,
            hoverinfo="skip",
        )
    )

    # group risk ids by cell for offsetting
    from collections import defaultdict
    cells = defaultdict(list)
    for r in risks:
        cells[(r["probability"], r["impact"])].append(r)

    for (prob, imp), cell_risks in sorted(cells.items()):
        cell_risks = sorted(cell_risks, key=lambda r: str(r["id"]))
        offsets = _jitter_offsets(len(cell_risks))
        for r, (dx, dy) in zip(cell_risks, offsets):
            fig.add_trace(
                go.Scatter(
                    x=[r["impact"] + dx],
                    y=[r["probability"] + dy],
                    mode="markers+text",
                    marker=dict(
                        color=r["color"],
                        size=26,
                        line=dict(color="white", width=2),
                    ),
                    text=[r["id"]],
                    textposition="middle center",
                    textfont=dict(color="white", size=11),
                    name=f"{r['id']} ({r['severity']})",
                    hovertemplate=(
                        f"<b>{r['id']} · {r['title']}</b><br>"
                        f"Score {r['score']} — {r['severity']}<br>"
                        f"Probability {r['probability']} · Impact {r['impact']}<br>"
                        f"<i>{r['description']}</i><extra></extra>"
                    ),
                    showlegend=False,
                )
            )

    # legend bands (dummy traces)
    for label, color in [
        ("Critical (20–25)", "#DC2626"),
        ("High (13–19)", "#EA580C"),
        ("Medium (7–12)", "#D97706"),
        ("Low (1–6)", "#16A34A"),
    ]:
        fig.add_trace(
            go.Scatter(
                x=[None], y=[None],
                mode="markers",
                marker=dict(color=color, size=12, symbol="square"),
                name=label,
            )
        )

    fig.update_layout(
        title=f"{project_name} — Risk Heat Map",
        xaxis=dict(
            title="Impact · 1 Negligible → 5 Catastrophic",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["1", "2", "3", "4", "5"],
            range=[0.5, 5.5],
            title_standoff=12,
        ),
        yaxis=dict(
            title="Probability",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=[f"{p} — {lbl}" for p, lbl in enumerate(PROB_LABELS, 1)],
            range=[0.5, 5.5],
        ),
        margin=dict(l=60, r=20, t=60, b=150),
        plot_bgcolor="white",
        paper_bgcolor="white",
        hovermode="closest",
        hoverlabel=dict(bgcolor="white", bordercolor="#D4D1C8",
                        font=dict(family="Inter, sans-serif", size=13, color="#141414")),
        legend=dict(orientation="h", y=-0.38, x=0),
    )

    return plot(fig, output_type="div", include_plotlyjs=False)
