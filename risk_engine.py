"""Risk scoring engine — pure Python, no Flask, no AI."""


SEVERITY_RULES = [
    (20, 25, "Critical", "#DC2626"),
    (13, 19, "High", "#EA580C"),
    (7, 12, "Medium", "#D97706"),
    (1, 6, "Low", "#16A34A"),
]

REQUIRED_RISK_FIELDS = ("id", "title", "category", "probability", "impact", "description")

# P=1..5 maps to 0.2..1.0 for EMV math (P/5)
def prob_to_decimal(probability):
    return round(probability / 5.0, 2)


def score_to_severity(score):
    """Map a 1-25 score to (severity_label, hex_color)."""
    for low, high, label, color in SEVERITY_RULES:
        if low <= score <= high:
            return label, color
    raise ValueError(f"score out of range 1-25: {score!r}")


def _validate_int_in_range(name, value, risk_id):
    # bool is a subclass of int — reject it explicitly. Reject floats/strings.
    if isinstance(value, bool) or type(value) is not int:
        raise ValueError(
            f"risk {risk_id!r}: {name} must be an integer 1-5, got {value!r}"
        )
    if not 1 <= value <= 5:
        raise ValueError(
            f"risk {risk_id!r}: {name} must be between 1 and 5, got {value!r}"
        )
    return value


def validate_risk(risk):
    """Validate a single risk dict. Raises ValueError with a clear message."""
    if not isinstance(risk, dict):
        raise ValueError(f"each risk must be an object, got {risk!r}")
    for field in REQUIRED_RISK_FIELDS:
        if field not in risk or risk[field] in (None, ""):
            # allow empty description? spec says required — enforce it
            raise ValueError(
                f"risk {risk.get('id', '?')!r}: missing required field {field!r}"
            )
    risk_id = risk.get("id", "?")
    _validate_int_in_range("probability", risk["probability"], risk_id)
    _validate_int_in_range("impact", risk["impact"], risk_id)
    # optional EMV field: non-negative number or absent
    cost = risk.get("cost_impact", None)
    if cost in (None, ""):
        risk["cost_impact"] = None
    else:
        if isinstance(cost, bool) or not isinstance(cost, (int, float)):
            raise ValueError(
                f"risk {risk_id!r}: cost_impact must be a number >= 0, got {cost!r}"
            )
        if cost < 0:
            raise ValueError(
                f"risk {risk_id!r}: cost_impact must be >= 0, got {cost!r}"
            )
        risk["cost_impact"] = float(cost)
    # optional links: list of risk ids (cross-checked in graph.py)
    triggers = risk.get("triggers", [])
    if triggers in (None, ""):
        triggers = []
    if not isinstance(triggers, list) or any(not isinstance(t, str) for t in triggers):
        raise ValueError(f"risk {risk_id!r}: triggers must be a list of risk ids")
    risk["triggers"] = triggers
    return True


def analyze_risks(project_name, project_manager, date, risks, currency="$"):
    """Score, categorize and rank every risk.

    Returns a plain dict with per-risk and aggregate outputs.
    """
    if not isinstance(risks, list):
        raise ValueError("risks must be a list")
    if len(risks) == 0:
        raise ValueError("at least one risk is required")

    seen_ids = set()
    scored = []
    for risk in risks:
        validate_risk(risk)
        rid = risk["id"]
        if rid in seen_ids:
            raise ValueError(f"duplicate risk id {rid!r}")
        seen_ids.add(rid)
        p = risk["probability"]
        i = risk["impact"]
        score = p * i
        severity, color = score_to_severity(score)
        cost = risk.get("cost_impact")
        emv = round(prob_to_decimal(p) * cost, 2) if cost is not None else None
        scored.append(
            {
                "id": rid,
                "title": risk["title"],
                "category": risk["category"],
                "probability": p,
                "impact": i,
                "description": risk["description"],
                "score": score,
                "severity": severity,
                "color": color,
                "cost_impact": cost,
                "emv": emv,
                "triggers": risk.get("triggers", []),
            }
        )

    # sort by score desc, then id for stability; rank = position (1 = highest)
    scored.sort(key=lambda r: (-r["score"], str(r["id"])))
    for idx, r in enumerate(scored, start=1):
        r["priority_rank"] = idx

    critical = sum(1 for r in scored if r["severity"] == "Critical")
    high = sum(1 for r in scored if r["severity"] == "High")
    medium = sum(1 for r in scored if r["severity"] == "Medium")
    low = sum(1 for r in scored if r["severity"] == "Low")
    total = len(scored)
    total_exposure = round(sum(r["emv"] for r in scored if r["emv"] is not None), 2)
    exposure_count = sum(1 for r in scored if r["emv"] is not None)

    if critical > 0:
        overall = "Critical"
    elif high > 2:
        overall = "High"
    elif total > 0 and medium > total / 2:
        overall = "Medium"
    else:
        overall = "Low"

    # 5x5 matrix: (probability, impact) -> [risk ids]
    matrix_grid = {(p, i): [] for p in range(1, 6) for i in range(1, 6)}
    for r in scored:
        matrix_grid[(r["probability"], r["impact"])].append(r["id"])

    return {
        "project_name": project_name,
        "project_manager": project_manager,
        "date": date,
        "currency": currency or "$",
        "risks": scored,
        "total_count": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "overall_level": overall,
        "matrix_grid": matrix_grid,
        "total_exposure": total_exposure,
        "exposure_count": exposure_count,
    }
