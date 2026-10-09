import pytest

import velocity
from velocity import compute_trends, list_snapshots, save_snapshot, trend_chart


@pytest.fixture()
def iso(tmp_path, monkeypatch):
    monkeypatch.setenv("RISK_DATA_DIR", str(tmp_path))
    return tmp_path


def _risks(p1=4, i1=5, extra=None):
    risks = [
        {"id": "R1", "title": "Dev leaves", "category": "Resource",
         "probability": p1, "impact": i1, "description": "d"},
        {"id": "R2", "title": "Minor", "category": "Cost",
         "probability": 1, "impact": 2, "description": "d"},
    ]
    if extra:
        risks.extend(extra)
    return risks


def test_save_list_and_duplicate_label(iso):
    save_snapshot("Proj", "Week 1", "2026-09-15", _risks())
    assert [s["label"] for s in list_snapshots("Proj")] == ["Week 1"]
    with pytest.raises(ValueError):
        save_snapshot("Proj", "Week 1", "2026-09-22", _risks())
    with pytest.raises(ValueError):
        save_snapshot("Proj", " ", "2026-09-22", _risks())


def test_trend_statuses(iso):
    save_snapshot("Proj", "Week 1", "2026-09-15", _risks(p1=2, i1=2))  # R1 = 4
    save_snapshot("Proj", "Week 2", "2026-09-22", _risks(p1=4, i1=5, extra=[
        {"id": "R3", "title": "New", "category": "Cost",
         "probability": 5, "impact": 5, "description": "d"}]))  # R1 = 20
    data = compute_trends("Proj")
    by_id = {t["id"]: t for t in data["trends"]}
    assert by_id["R1"]["status"] == "Worsened"
    assert by_id["R1"]["delta"] == 16
    assert by_id["R2"]["status"] == "Stable"
    assert by_id["R3"]["status"] == "New"


def test_closed_risk(iso):
    save_snapshot("Proj", "Week 1", "2026-09-15", _risks())
    save_snapshot("Proj", "Week 2", "2026-09-22", [_risks()[0]])
    by_id = {t["id"]: t for t in compute_trends("Proj")["trends"]}
    assert by_id["R2"]["status"] == "Closed"


def test_chart_div(iso):
    save_snapshot("Proj", "Week 1", "2026-09-15", _risks())
    div = trend_chart("Proj")
    assert "R1" in div and "Risk Velocity" in div
