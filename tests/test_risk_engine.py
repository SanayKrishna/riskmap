from risk_engine import analyze_risks, score_to_severity


def sample_risks():
    return [
        {"id": "R1", "title": "a", "category": "Technical", "probability": 4, "impact": 5, "description": "d"},
        {"id": "R2", "title": "b", "category": "Cost", "probability": 3, "impact": 4, "description": "d"},
        {"id": "R3", "title": "c", "category": "Schedule", "probability": 2, "impact": 2, "description": "d"},
    ]


def test_score_calculation():
    out = analyze_risks("P", "M", "2026-09-15", sample_risks())
    by_id = {r["id"]: r for r in out["risks"]}
    assert by_id["R1"]["score"] == 20
    assert by_id["R2"]["score"] == 12
    assert by_id["R3"]["score"] == 4


def test_severity_boundaries():
    assert score_to_severity(6) == ("Low", "#16A34A")
    assert score_to_severity(7) == ("Medium", "#D97706")
    assert score_to_severity(12) == ("Medium", "#D97706")
    assert score_to_severity(13) == ("High", "#EA580C")
    assert score_to_severity(19) == ("High", "#EA580C")
    assert score_to_severity(20) == ("Critical", "#DC2626")
    assert score_to_severity(25) == ("Critical", "#DC2626")
    assert score_to_severity(1) == ("Low", "#16A34A")


def _make(prob, imp, rid="RX"):
    return {"id": rid, "title": "t", "category": "Technical",
            "probability": prob, "impact": imp, "description": "d"}


def test_overall_critical_wins():
    risks = [_make(5, 5, "R1"), _make(1, 1, "R2")]
    out = analyze_risks("P", "M", "2026-09-15", risks)
    assert out["overall_level"] == "Critical"


def test_overall_high_when_more_than_two_high():
    risks = [_make(3, 5, "R1"), _make(3, 5, "R2"), _make(3, 5, "R3"),
             _make(1, 1, "R4")]
    out = analyze_risks("P", "M", "2026-09-15", risks)
    assert out["high_count"] == 3
    assert out["overall_level"] == "High"


def test_overall_medium_when_majority():
    risks = [_make(3, 3, "R1"), _make(3, 3, "R2"), _make(3, 3, "R3"),
             _make(1, 1, "R4")]
    out = analyze_risks("P", "M", "2026-09-15", risks)
    assert out["overall_level"] == "Medium"


def test_overall_low_by_default():
    risks = [_make(1, 1, "R1"), _make(2, 2, "R2")]
    out = analyze_risks("P", "M", "2026-09-15", risks)
    assert out["overall_level"] == "Low"


def test_priority_rank_and_counts():
    out = analyze_risks("P", "M", "2026-09-15", sample_risks())
    assert out["total_count"] == 3
    assert out["critical_count"] == 1
    ranks = {r["id"]: r["priority_rank"] for r in out["risks"]}
    assert ranks["R1"] == 1  # highest score first
    assert out["risks"][0]["score"] >= out["risks"][1]["score"]


def test_matrix_grid():
    out = analyze_risks("P", "M", "2026-09-15", sample_risks())
    assert out["matrix_grid"][(4, 5)] == ["R1"]
    assert out["matrix_grid"][(1, 1)] == []


def test_rejects_floats_and_out_of_range():
    import pytest
    with pytest.raises(ValueError):
        analyze_risks("P", "M", "d", [_make(2.5, 3, "R1")])
    with pytest.raises(ValueError):
        analyze_risks("P", "M", "d", [_make(0, 3, "R1")])
    with pytest.raises(ValueError):
        analyze_risks("P", "M", "d", [_make(3, 6, "R1")])


def _cost_risk(rid, prob, cost):
    return {"id": rid, "title": "t", "category": "Cost",
            "probability": prob, "impact": 5, "description": "d",
            "cost_impact": cost}


def test_emv_math_and_prob_mapping():
    from risk_engine import prob_to_decimal
    assert prob_to_decimal(1) == 0.2
    assert prob_to_decimal(3) == 0.6
    assert prob_to_decimal(5) == 1.0
    out = analyze_risks("P", "M", "d", [_cost_risk("R1", 3, 50000)])
    assert out["risks"][0]["emv"] == 30000.0
    assert out["total_exposure"] == 30000.0
    assert out["exposure_count"] == 1


def test_emv_optional_and_total():
    risks = [_cost_risk("R1", 4, 80000),
             {"id": "R2", "title": "t", "category": "Cost",
              "probability": 2, "impact": 2, "description": "d"}]
    out = analyze_risks("P", "M", "d", risks, currency="USD")
    assert out["currency"] == "USD"
    by_id = {r["id"]: r for r in out["risks"]}
    assert by_id["R2"]["emv"] is None
    assert out["total_exposure"] == round(0.8 * 80000, 2)
    assert out["exposure_count"] == 1


def test_emv_rejects_bad_cost():
    import pytest
    with pytest.raises(ValueError):
        analyze_risks("P", "M", "d", [_cost_risk("R1", 3, -5)])
    with pytest.raises(ValueError):
        analyze_risks("P", "M", "d", [_cost_risk("R1", 3, "lots")])
