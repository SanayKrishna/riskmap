"""Shared Plotly look for the charts that stay on Plotly (trend, security).

Transparent background, no titles, hairline grid, no axis ticks. Charts get an
explicit pixel height and a responsive config so they fill their container.
Severity colours match the stylesheet; there is no green in the palette.
"""

INK = "#0E1A33"
INK_2 = "#3A4660"
MUTED = "#6B7690"
GRID = "#E1E6EF"
FONT = dict(family="Public Sans, sans-serif", size=12, color=INK_2)
CONFIG = {"displayModeBar": False, "responsive": True}

# severity colours (low is a muted blue, not green)
SEV = {"Critical": "#C0262D", "High": "#CF5F0A", "Medium": "#B07C06", "Low": "#4C74A6"}
# risk_engine's own hex per severity -> chart colour, so the engine stays untouched
ENGINE_TO_CHART = {"#DC2626": SEV["Critical"], "#EA580C": SEV["High"],
                   "#D97706": SEV["Medium"], "#16A34A": SEV["Low"]}


def chart_color(engine_hex):
    return ENGINE_TO_CHART.get(str(engine_hex).upper(), INK_2)


def base_layout(height=320, **extra):
    layout = dict(
        autosize=True,
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=FONT,
        margin=dict(l=36, r=8, t=8, b=36),
        hoverlabel=dict(bgcolor="#FFFFFF", bordercolor="#CDD4E1",
                        font=dict(family="Public Sans, sans-serif", size=13, color=INK)),
    )
    layout.update(extra)
    return layout


def axis(**extra):
    ax = dict(gridcolor=GRID, linecolor=GRID, zeroline=False, title=None, ticks="",
              tickfont=dict(color=MUTED, size=11.5))
    ax.update(extra)
    return ax


def to_div(fig, height=320):
    """Inline HTML div with a fixed pixel height and responsive width."""
    return fig.to_html(full_html=False, include_plotlyjs=False, config=CONFIG,
                       default_width="100%", default_height=f"{height}px")
