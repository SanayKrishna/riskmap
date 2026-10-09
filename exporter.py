"""CSV export — pandas DataFrame + bytes for flask.send_file."""

import io

import pandas as pd

COLUMNS = [
    "Risk ID", "Title", "Category", "Probability", "Impact",
    "Score", "Severity", "Cost Impact", "EMV", "Linked Risks",
    "Strategy", "Actions", "Owner", "Contingency",
]


def build_dataframe(analysis, ai_plans=None):
    """Combine risk register + AI responses into a DataFrame."""
    ai_plans = ai_plans or {}
    rows = []
    for r in analysis.get("risks", []):
        plan = ai_plans.get(r["id"], {})
        actions = plan.get("actions", [])
        links = r.get("triggers", []) or []
        rows.append(
            {
                "Risk ID": r["id"],
                "Title": r["title"],
                "Category": r["category"],
                "Probability": r["probability"],
                "Impact": r["impact"],
                "Score": r["score"],
                "Severity": r["severity"],
                "Cost Impact": r.get("cost_impact") if r.get("cost_impact") is not None else "",
                "EMV": r.get("emv") if r.get("emv") is not None else "",
                "Linked Risks": "; ".join(links),
                "Strategy": plan.get("strategy", ""),
                "Actions": "; ".join(actions) if isinstance(actions, list) else str(actions),
                "Owner": plan.get("owner", ""),
                "Contingency": plan.get("contingency", ""),
            }
        )
    df = pd.DataFrame(rows, columns=COLUMNS)
    # keep register sorted by score desc
    if not df.empty:
        df = df.sort_values("Score", ascending=False).reset_index(drop=True)
    return df


def to_csv_bytes(analysis, ai_plans=None):
    """Return CSV file bytes (utf-8-sig for Excel)."""
    df = build_dataframe(analysis, ai_plans)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8-sig")
