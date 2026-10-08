"""Risk scoring engine — pure Python, no Flask, no AI."""


SEVERITY_RULES = [
    (20, 25, "Critical", "#DC2626"),
    (13, 19, "High", "#EA580C"),
    (7, 12, "Medium", "#D97706"),
    (1, 6, "Low", "#16A34A"),
]

REQUIRED_RISK_FIELDS = ("id", "title", "category", "probability", "impact", "description")


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
    return True


def analyze_risks(project_name, project_manager, date, risks):
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
        "risks": scored,
        "total_count": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "overall_level": overall,
        "matrix_grid": matrix_grid,
    }
