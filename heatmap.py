"""5x5 risk heat map as a plain HTML grid — no AI, no Flask, no charting library."""

from collections import defaultdict
from html import escape

from risk_engine import score_to_severity

IMPACT_LABELS = ["Negligible", "Minor", "Moderate", "Major", "Catastrophic"]
PROB_LABELS = ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"]
BANDS = [("Critical", "20–25"), ("High", "13–19"), ("Medium", "7–12"), ("Low", "1–6")]


def generate_heatmap(analysis):
    """Return the heat map as an inline HTML fragment (responsive CSS grid)."""
    risks = analysis.get("risks", [])
    cells = defaultdict(list)
    for r in risks:
        cells[(r["probability"], r["impact"])].append(r)

    out = ['<div class="hm" role="img" aria-label="Risk heat map: probability against impact">',
           '<div class="hm-grid">']
    for p in range(5, 0, -1):  # likeliest at the top
        out.append(f'<div class="hm-ylab"><b>{p}</b><span>{PROB_LABELS[p - 1]}</span></div>')
        for i in range(1, 6):
            band, _ = score_to_severity(p * i)
            chips = "".join(
                f'<span class="hm-chip sev-{escape(str(r["severity"]))}" tabindex="0" '
                f'title="{escape(str(r["id"]))} — {escape(str(r["title"]))}&#10;'
                f'Score {r["score"]} ({escape(str(r["severity"]))}), P{p} × I{i}">{escape(str(r["id"]))}</span>'
                for r in sorted(cells.get((p, i), []), key=lambda r: str(r["id"]))
            )
            out.append(f'<div class="hm-cell band-{band}"><i>{p * i}</i>{chips}</div>')
    out.append('<div class="hm-corner"></div>')
    for i in range(1, 6):
        out.append(f'<div class="hm-xlab"><b>{i}</b><span>{IMPACT_LABELS[i - 1]}</span></div>')
    out.append("</div>")
    out.append('<div class="hm-axis"><span>↑ Probability</span><span>Impact →</span></div>')
    out.append('<ul class="hm-legend">')
    for band, rng in BANDS:
        out.append(f'<li><i class="band-{band}"></i>{band} <span>{rng}</span></li>')
    out.append("</ul></div>")
    return "".join(out)
